using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using Microsoft.IdentityModel.Tokens;
using JwtAuthDemo.Controllers;
using System.Text.Json;

namespace JwtAuthDemo.Infrastructure
{
    public interface IJwtAuthManager
    {
        IImmutableDictionary<string, RefreshToken> UsersRefreshTokensReadOnlyDictionary { get; }
        JwtAuthResult GenerateTokens(string username, Claim[] claims, DateTime now);
        JwtAuthResult Refresh(string refreshToken, string accessToken, DateTime now, bool ignoreExpired = false);
        void RemoveExpiredRefreshTokens(DateTime now);
        void RemoveRefreshTokenByUserName(string userName);
        (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token, bool ignoreExpired = false);
    }

    public class JwtAuthManager : IJwtAuthManager
    {
        public IImmutableDictionary<string, RefreshToken> UsersRefreshTokensReadOnlyDictionary => _usersRefreshTokens.ToImmutableDictionary();
        private readonly ConcurrentDictionary<string, RefreshToken> _usersRefreshTokens;  // can store in a database or a distributed cache
        private readonly JwtTokenConfig _jwtTokenConfig;
        private readonly byte[] _secret;

        private readonly RsaSecurityKey privateEncryptionKey;
        private readonly RsaSecurityKey publicEncryptionKey;
        private readonly ECDsaSecurityKey privateSigningKey;
        private readonly ECDsaSecurityKey publicSigningKey;

        public JwtAuthManager(JwtTokenConfig jwtTokenConfig)
        {
            _jwtTokenConfig = jwtTokenConfig;
            _usersRefreshTokens = new ConcurrentDictionary<string, RefreshToken>();
            _secret = Encoding.ASCII.GetBytes(jwtTokenConfig.Secret);

            RSA encryptionKey = RSA.Create(2048); // public key for encryption, private key for decryption
            var content = File.ReadAllText(jwtTokenConfig.PrivateKeyFile);
            encryptionKey.ImportFromPem(content);

            ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);  // private key for signing, public key for validating
            content = File.ReadAllText(jwtTokenConfig.PrivateSignKeyFile);
            signingKey.ImportFromPem(content);

            privateEncryptionKey = new RsaSecurityKey(encryptionKey) { KeyId = JwtTokenConfig.EncryptionKid };
            publicEncryptionKey = new RsaSecurityKey(encryptionKey.ExportParameters(false)) { KeyId = JwtTokenConfig.EncryptionKid };
            privateSigningKey = new ECDsaSecurityKey(signingKey) { KeyId = JwtTokenConfig.SigningKid };
            publicSigningKey = new ECDsaSecurityKey(ECDsa.Create(signingKey.ExportParameters(false))) { KeyId = JwtTokenConfig.SigningKid };
        }

        public JwtAuthManager(JwtTokenConfig jwtTokenConfig, RsaSecurityKey privateEncKey, RsaSecurityKey publicEncKey, 
            ECDsaSecurityKey privateSignKey, ECDsaSecurityKey publicSingKey)
        {
            _jwtTokenConfig = jwtTokenConfig;
            _usersRefreshTokens = new ConcurrentDictionary<string, RefreshToken>();
            _secret = Encoding.ASCII.GetBytes(jwtTokenConfig.Secret);

            this.privateEncryptionKey = privateEncKey;
            this.publicEncryptionKey = publicEncKey;
            this.privateSigningKey = privateSignKey;
            this.publicSigningKey = publicSingKey;
        }

        // optional: clean up expired refresh tokens
        public void RemoveExpiredRefreshTokens(DateTime now)
        {
            var expiredTokens = _usersRefreshTokens.Where(x => x.Value.ExpireAt < now).ToList();
            foreach (var expiredToken in expiredTokens)
            {
                _usersRefreshTokens.TryRemove(expiredToken.Key, out _);
            }
        }

        // can be more specific to ip, user agent, device name, etc.
        public void RemoveRefreshTokenByUserName(string userName)
        {
            var refreshTokens = _usersRefreshTokens.Where(x => x.Value.UserName == userName).ToList();
            foreach (var refreshToken in refreshTokens)
            {
                _usersRefreshTokens.TryRemove(refreshToken.Key, out _);
            }
        }

        public JwtAuthResult GenerateTokens(string username, Claim[] claims, DateTime now)
        {
            var shouldAddAudienceClaim = string.IsNullOrWhiteSpace(claims?.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Aud)?.Value);
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            IList<Claim> allClaims = new List<Claim>(claims);

            Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateKey();
            string aesKey = Convert.ToBase64String(aes.Key);
            Claim target = allClaims.FirstOrDefault((x) => x.Type == JwtTokenConfig.CLAIMTYPE_SYMMETRICALGO);
            if (target != null)
            {
                allClaims.Remove(target);
            }
            target = allClaims.FirstOrDefault((x) => x.Type == JwtTokenConfig.CLAIMTYPE_SYMMETRICKEY);
            if (target != null)
            {
                allClaims.Remove(target);
            }
            allClaims.Add(new Claim(JwtTokenConfig.CLAIMTYPE_SYMMETRICALGO, "AES-256-CBC"));
            allClaims.Add(new Claim(JwtTokenConfig.CLAIMTYPE_SYMMETRICKEY, aesKey));

            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(allClaims),
                Issuer = _jwtTokenConfig.Issuer,
                Audience = shouldAddAudienceClaim ? _jwtTokenConfig.Audience : string.Empty,
                NotBefore = now,
                Expires = now.AddMinutes(_jwtTokenConfig.AccessTokenExpiration),
                SigningCredentials = new SigningCredentials(this.privateSigningKey, SecurityAlgorithms.EcdsaSha256),
                //SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_secret), SecurityAlgorithms.HmacSha256Signature),
                EncryptingCredentials = new EncryptingCredentials(this.publicEncryptionKey, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)
            };
            SecurityToken liveToken = handler.CreateToken(tokenDescriptor);
            var accessToken = handler.WriteToken(liveToken);

            var refreshToken = new RefreshToken
            {
                UserName = username,
                TokenString = GenerateRefreshTokenString(),
                ExpireAt = now.AddMinutes(_jwtTokenConfig.RefreshTokenExpiration)
            };
            _usersRefreshTokens.AddOrUpdate(refreshToken.TokenString, refreshToken, (_, _) => refreshToken);

            return new JwtAuthResult
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }

        public JwtAuthResult Refresh(string refreshToken, string accessToken, DateTime now, bool ignoreExpired = false)
        {
            //System.Diagnostics.Debugger.Launch();
            var (principal, jwtToken) = DecodeJwtToken(accessToken, ignoreExpired);
            //if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature))
            if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.RsaOAEP))
            {
                throw new SecurityTokenException("Invalid token");
            }

            var userName = principal.Identity?.Name;
            if (!_usersRefreshTokens.TryGetValue(refreshToken, out var existingRefreshToken))
            {
                throw new SecurityTokenException("Invalid token");
            }
            if (existingRefreshToken.UserName != userName || existingRefreshToken.ExpireAt < now)
            {
                throw new SecurityTokenException("Invalid token");
            }

            return GenerateTokens(userName, principal.Claims.ToArray(), now); // need to recover the original claims
        }

        public (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token, bool ignoreExpired = false)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new SecurityTokenException("Invalid token");
            }
            var principal = new JwtSecurityTokenHandler()
                .ValidateToken(token,
                    new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = _jwtTokenConfig.Issuer,
                        ValidateIssuerSigningKey = true,
                        //IssuerSigningKey = new SymmetricSecurityKey(_secret),

                        // public key for signing validation
                        IssuerSigningKey = this.publicSigningKey,

                        // private key for decryption
                        TokenDecryptionKey = this.privateEncryptionKey,
                        ValidAudience = _jwtTokenConfig.Audience,
                        ValidateAudience = true,
                        ValidateLifetime = !ignoreExpired,
                        ClockSkew = TimeSpan.FromMinutes(1)
                    },
                    out var validatedToken);
            return (principal, validatedToken as JwtSecurityToken);
        }

        private static string GenerateRefreshTokenString()
        {
            var randomNumber = new byte[32];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }

    public class JwtAuthResult
    {
        [JsonPropertyName("accessToken")]
        public string AccessToken { get; set; }

        [JsonPropertyName("refreshToken")]
        public RefreshToken RefreshToken { get; set; }
    }

    public class RefreshToken
    {
        [JsonPropertyName("username")]
        public string UserName { get; set; }    // can be used for usage tracking
        // can optionally include other metadata, such as user agent, ip address, device name, and so on

        [JsonPropertyName("tokenString")]
        public string TokenString { get; set; }

        [JsonPropertyName("expireAt")]
        public DateTime ExpireAt { get; set; }
    }

}

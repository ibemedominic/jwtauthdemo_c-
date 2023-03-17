using System.Text.Json.Serialization;

namespace JwtAuthDemo.Infrastructure
{
    public class JwtTokenConfig
    {

        public const string EncryptionKid = "8524e3e6674e494f85c5c775dcd602c5";
        public const string SigningKid = "29b4adf8bcc941dc8ce40a6d0227b6d3";
        public const string CLAIMTYPE_SYMMETRICALGO = "symalgo";
        public const string CLAIMTYPE_SYMMETRICKEY = "symkey";

        [JsonPropertyName("secret")]
        public string Secret { get; set; }

        [JsonPropertyName("issuer")]
        public string Issuer { get; set; }

        [JsonPropertyName("audience")]
        public string Audience { get; set; }

        [JsonPropertyName("PrivateKeyFile")]
        public string PrivateKeyFile { get; set; }

        [JsonPropertyName("PublicKeyFile")]
        public string PublicKeyFile { get; set; }

        [JsonPropertyName("PrivateSignKeyFile")]
        public string PrivateSignKeyFile { get; set; }

        [JsonPropertyName("PublicSignKeyFile")]
        public string PublicSignKeyFile { get; set; }

        [JsonPropertyName("accessTokenExpiration")]
        public int AccessTokenExpiration { get; set; }

        [JsonPropertyName("refreshTokenExpiration")]
        public int RefreshTokenExpiration { get; set; }
    }
}

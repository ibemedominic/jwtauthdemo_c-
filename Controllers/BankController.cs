using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Security.Claims;
using System.Text.Json.Serialization;
using JwtAuthDemo.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.IO;
using System.Text.Json;

namespace JwtAuthDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class BankController : ControllerBase
    {
        private readonly ILogger<BankController> _logger;

        public BankController(ILogger<BankController> logger)
        {
            _logger = logger;
        }

        [HttpPost("submit")]
        [Authorize]
        public ActionResult submitSecureBankDetails([FromBody] EncryptedData request)
        {
            string symKey = User.FindFirst(JwtTokenConfig.CLAIMTYPE_SYMMETRICKEY)?.Value ?? string.Empty;
            byte[] encryptedData = Convert.FromBase64String(request.CipherText);
            byte[] iv = Convert.FromBase64String(request.IV);
            byte[] key = Convert.FromBase64String(symKey);

            Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            AccountRequest accountDetails = null;
            String jsonValue = null;

            ICryptoTransform decryptor = aes.CreateDecryptor();
            //Decryption will be done in a memory stream through a CryptoStream object
            using (MemoryStream ms = new MemoryStream(encryptedData))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        jsonValue = sr.ReadToEnd();
                        accountDetails = JsonSerializer.Deserialize<AccountRequest>(jsonValue);
                    }
                }
            }
            _logger.LogInformation($"Data Recieved from Request = {jsonValue}");
            return Ok(accountDetails);
        }

        [HttpGet("request/{accountNumber}")]
        [Authorize()]
        public ActionResult requestSecureBankDetails(String accountNumber)
        {
            string symKey = User.FindFirst(JwtTokenConfig.CLAIMTYPE_SYMMETRICKEY)?.Value ?? string.Empty;
            byte[] key = Convert.FromBase64String(symKey);

            Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateIV();
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            String iv = Convert.ToBase64String(aes.IV);

            AccountRequest accountDetails = new AccountRequest();
            accountDetails.AccountNumber = accountNumber;
            accountDetails.AccountName = "Dominic Ibeme";
            accountDetails.Cvv = "311";
            accountDetails.CardNumber = "221334432244";
            accountDetails.Balance = 3000000;
            accountDetails.CardType = "VISA";
            String jsonValue = JsonSerializer.Serialize(accountDetails);
            byte[] encryptedData = null;

            ICryptoTransform encryptor = aes.CreateEncryptor();
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(jsonValue);
                    }
                    encryptedData = ms.ToArray();
                }
            }
            EncryptedData result = new EncryptedData();
            result.IV = iv;
            result.CipherText = Convert.ToBase64String(encryptedData);
            _logger.LogInformation($"Data Returned  to Request = {result.CipherText}");
            return Ok(result);
        }

    }

    public class EncryptedData
    {
        [Required]
        [JsonPropertyName("cipherText")]
        public string CipherText { get; set; }

        [Required]
        [JsonPropertyName("iv")]
        public string IV { get; set; }
    }


    public class AccountRequest
    {
        [Required]
        [JsonPropertyName("accountNumber")]
        public string AccountNumber { get; set; }

        [Required]
        [JsonPropertyName("accountName")]
        public string AccountName { get; set; }

        [Required]
        [JsonPropertyName("cardNumber")]
        public string CardNumber { get; set; }

        [Required]
        [JsonPropertyName("balance")]
        public decimal Balance { get; set; }

        [Required]
        [JsonPropertyName("cardType")]
        public string CardType { get; set; }

        [Required]
        [JsonPropertyName("cvv")]
        public string Cvv { get; set; }

    }

}

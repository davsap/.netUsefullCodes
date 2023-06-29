using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;

namespace CustomProvider.Example
{
    public class EncryptedJsonConfigurationProvider : JsonConfigurationProvider
    {
        public EncryptedJsonConfigurationProvider(JsonConfigurationSource source) : base(source)
        {
        }

        public override void Load(Stream stream)
        {
            base.Load(stream); // Load the JSON data into the Data dictionary
            DecryptData(); // Decrypt the encrypted values in the Data dictionary
        }

        private void DecryptData()
        {
            foreach (var key in Data.Keys)
            {
                if (Data[key].StartsWith("ENC:")) // Check if the value is encrypted
                {
                    var encryptedBytes = Convert.FromBase64String(Data[key].Substring(4)); // Remove the "ENC:" prefix and convert to bytes
                    var decryptedBytes = ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.LocalMachine); // Decrypt using DPAPI
                    var decryptedValue = System.Text.Encoding.UTF8.GetString(decryptedBytes); // Convert to string
                    Data[key] = decryptedValue; // Replace the encrypted value with the decrypted value
                }
            }
        }
    }

    public class EncryptedJsonConfigurationSource : JsonConfigurationSource
    {
        public override IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            EnsureDefaults(builder);
            return new EncryptedJsonConfigurationProvider(this);
        }
    }

    public static class EncryptedJsonConfigurationExtensions
    {
        public static IConfigurationBuilder AddEncryptedJsonFile(this IConfigurationBuilder builder, string path)
        {
            return builder.Add(new EncryptedJsonConfigurationSource()
            {
                Path = path,
                Optional = true,
                ReloadOnChange = true
            });
        }
    }
}

/*
in config 
var builder = new ConfigurationBuilder()
    .AddEncryptedJsonFile("appsettings.json");
*/
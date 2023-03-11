using System.Security.Cryptography;
using System.Text;

namespace NexusExtensions.Security.Encryption
{
    public sealed class Encrypter : EncryptionBase
    {
        public static string Encrypt(string plainText)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  
            var saltStringBytes = Generate256BitsOfRandomEntropy();
            var ivStringBytes = Generate256BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            using var password = new Rfc2898DeriveBytes(PassPhrase, saltStringBytes, DerivationIterations, HashAlgorithmName.SHA256);

            var (cipher, keyParamWithIv) = CreateEncryptionLayer(password, ivStringBytes);
           
            cipher.Init(true, keyParamWithIv);
            var comparisonBytes = new byte[cipher.GetOutputSize(plainTextBytes.Length)];
            var length = cipher.ProcessBytes(plainTextBytes, comparisonBytes, 0);

            cipher.DoFinal(comparisonBytes, length);
            return Convert.ToBase64String(saltStringBytes.Concat(ivStringBytes).Concat(comparisonBytes).ToArray());
        }
    }
}
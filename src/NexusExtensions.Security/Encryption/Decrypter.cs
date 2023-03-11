using System.Security.Cryptography;
using System.Text;

namespace NexusExtensions.Security.Encryption
{
    public sealed class Decrypter : EncryptionBase
    {
        public static string Decrypt(string cipherText)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            using var password = new Rfc2898DeriveBytes(PassPhrase, saltStringBytes, DerivationIterations, HashAlgorithmName.SHA256);
            var (cipher, parametersWithIv) = CreateEncryptionLayer(password, ivStringBytes);

            cipher.Init(false, parametersWithIv);
            var comparisonBytes = new byte[cipher.GetOutputSize(cipherTextBytes.Length)];
            var length = cipher.ProcessBytes(cipherTextBytes, comparisonBytes, 0);

            cipher.DoFinal(comparisonBytes, length);

            var nullIndex = comparisonBytes.Length - 1;
            while (comparisonBytes[nullIndex] == 0)
            {
                nullIndex--;
            }
            comparisonBytes = comparisonBytes.Take(nullIndex + 1).ToArray();

            var result = Encoding.UTF8.GetString(comparisonBytes, 0, comparisonBytes.Length);
            return result;
        }
    }
}
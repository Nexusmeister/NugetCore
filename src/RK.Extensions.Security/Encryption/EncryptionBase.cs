using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace RK.Extensions.Security.Encryption
{
    public class EncryptionBase
    {
        private const string DefaultPassPhrase = "HarambeIsKing";

        // This const should be editable for clients, to customize their encryption
        protected static string PassPhrase = DefaultPassPhrase;
        /// <summary>
        /// This constant is used to determine the keysize of the encryption algorithm in bits.
        /// We divide this by 8 within the code below to get the equivalent number of bytes.
        /// </summary>
        protected const int Keysize = 256;

        /// <summary>
        /// This constant determines the number of iterations for the password bytes generation function.
        /// </summary>
        protected const int DerivationIterations = 10000;

        /// <summary>
        /// Changes the internal PassPhrase for customization of the client's encryption
        /// </summary>
        /// <param name="passPhrase">String value that overwrites the internal PassPhrase</param>
        public static void ChangePassPhrase(string passPhrase)
        {
            PassPhrase = passPhrase;
        }

        /// <summary>
        /// Generates randomly 32 Byte Arrays
        /// </summary>
        /// <returns></returns>
        protected static byte[] Generate256BitsOfRandomEntropy()
        {
            var randomBytes = new byte[32]; // 32 Bytes will give us 256 bits.

            using var rngCsp = RandomNumberGenerator.Create();
            // Fill the array with cryptographically secure random bytes.
            rngCsp.GetBytes(randomBytes);
            return randomBytes;
        }

        /// <summary>
        /// Creates necessary steps for de- and encrypting input strings
        /// </summary>
        /// <param name="password">Byte derivation based on <seealso cref="HMACSHA1"/></param>
        /// <param name="ivStringBytes">Byte Array</param>
        /// <returns></returns>
        protected static (PaddedBufferedBlockCipher, ParametersWithIV) CreateEncryptionLayer(Rfc2898DeriveBytes password, byte[] ivStringBytes)
        {
            var keyBytes = password.GetBytes(Keysize / 8);
            var engine = new RijndaelEngine(256);
            var blockCipher = new CbcBlockCipher(engine);
            var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());
            var keyParam = new KeyParameter(keyBytes);
            var keyParamWithIv = new ParametersWithIV(keyParam, ivStringBytes, 0, 32);

            return (cipher, keyParamWithIv);
        }
    }
}
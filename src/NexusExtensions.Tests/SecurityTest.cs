using NexusExtensions.Security.Encryption;

namespace NexusExtensions.Tests
{
    public class SecurityTest
    {
        [Fact]
        public void TestEncryption_WithoutChangingPassPhrase()
        {
            var encrypted = Encrypter.Encrypt("This is a very special test");
            Assert.NotEmpty(encrypted);
        }

        [Fact]
        public void TestEncryptAndDecrypt_WithChangingPassPhrase()
        {
            EncryptionBase.ChangePassPhrase("LULW");
            const string testString = "SpecialTestPassword";

            var encrypted = Encrypter.Encrypt(testString); 
            Assert.NotNull(encrypted);
            Assert.NotEmpty(encrypted);

            var decrypted = Decrypter.Decrypt(encrypted);
            Assert.NotNull(decrypted);
            Assert.NotEmpty(decrypted);

            Assert.Equal(testString, decrypted);
        }

        [Fact]
        public void TestEncryptAndDecrypt_WithoutChangingPassPhrase()
        {
            const string testString = "SpecialTestPassword";

            var encrypted = Encrypter.Encrypt(testString);
            Assert.NotNull(encrypted);
            Assert.NotEmpty(encrypted);

            var decrypted = Decrypter.Decrypt(encrypted);
            Assert.NotNull(decrypted);
            Assert.NotEmpty(decrypted);

            Assert.Equal(testString, decrypted);
        }

        [Fact]
        public void TestDecryptio_WithFormatException()
        {
            EncryptionBase.ChangePassPhrase("COGGERS");
            Assert.Throws<FormatException>(() => Decrypter.Decrypt("AIWNIANGIOANIWONDAIONWD"));
        }
    }
}
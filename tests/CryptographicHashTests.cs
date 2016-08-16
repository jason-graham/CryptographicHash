using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Linq;
using System.IO;

namespace CryptographicHashTests
{
    [TestClass]
    public class CryptographicHashTests
    {
        private static readonly byte[] HelloWorldBytes = System.Text.Encoding.ASCII.GetBytes("Hello World!");
        private const string MD5_HASH_H = "ed076287532e86365e841e92bfc50d8c";
        private const string MD5_HASH_D = "ed07-6287-532e-8636-5e84-1e92-bfc5-0d8c";
        private const string SHA1_HASH_H = "2ef7bde608ce5404e97d5f042f95f89f1c232871";
        private const string SHA256_HASH_H = "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069";
        private const string SHA384_HASH_H = "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a";
        private const string SHA512_HASH_H = "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8";
        private const string RIPEMD160_HASH_H = "8476ee4631b9b30ac2754b0ee0c47e161d3f724c";
        private string TempFile;

        [TestInitialize]
        public void Initialize()
        {
            TempFile = Path.GetTempFileName();

            using (Stream stream = File.Open(TempFile, FileMode.Open, FileAccess.Write, FileShare.None))
                stream.Write(HelloWorldBytes, 0, HelloWorldBytes.Length);
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (File.Exists(TempFile))
                File.Delete(TempFile);
        }

        private static byte[] ComputeHash<T>(byte[] data) where T : HashAlgorithm
        {
            using (var alg = Activator.CreateInstance<T>())
                return alg.ComputeHash(HelloWorldBytes, 0, HelloWorldBytes.Length);
        }

        private static Stream GetHelloWorldStream()
        {
            MemoryStream ms = new MemoryStream();
            ms.Write(HelloWorldBytes, 0, HelloWorldBytes.Length);
            ms.Position = 0;
            return ms;
        }

        [TestMethod]
        public void MD5TestHelloWorld()
        {
            MD5Hash expected = new MD5Hash(ComputeHash<MD5CryptoServiceProvider>(HelloWorldBytes));
            MD5Hash result = MD5Hash.HashBytes(HelloWorldBytes);

            Assert.AreEqual(expected, result);
        }

        [TestMethod]
        public void MD5TestInvalidEquals()
        {
            MD5Hash expected = new MD5Hash(ComputeHash<MD5CryptoServiceProvider>(HelloWorldBytes));

            Assert.IsFalse(expected.Equals((string)null));
            Assert.IsFalse(expected.Equals(null));
            Assert.AreNotEqual(expected, "INVALID");
        }

        [TestMethod]
        public void MD5TestTryParse()
        {
            MD5Hash result;

            var parseResult = MD5Hash.TryParse(MD5_HASH_H, out result);
            MD5Hash expected = new MD5Hash(MD5_HASH_H);

            Assert.IsTrue(parseResult);
            Assert.AreEqual(expected, result);
        }

        [TestMethod]
        public void MD5TestTryParseBytes()
        {
            MD5Hash result;

            var parseResult = MD5Hash.TryParse(ComputeHash<MD5CryptoServiceProvider>(HelloWorldBytes), out result);
            MD5Hash expected = new MD5Hash(MD5_HASH_H);

            Assert.IsTrue(parseResult);
            Assert.AreEqual(expected, result);
        }


        [TestMethod]
        public void MD5TestTryParseInvalid()
        {
            MD5Hash result;

            var parseResult = MD5Hash.TryParse("INVALID", out result);

            Assert.IsFalse(parseResult);
        }

        [TestMethod]
        public void MD5TestTryParseInvalidBytes()
        {
            MD5Hash result;

            var parseResult = MD5Hash.TryParse(new byte[0], out result);

            Assert.IsFalse(parseResult);
        }

        [TestMethod]
        public void MD5TestHelloWorldStream()
        {
            using (Stream stream = GetHelloWorldStream())
            {
                MD5Hash expected = new MD5Hash(ComputeHash<MD5CryptoServiceProvider>(HelloWorldBytes));
                MD5Hash result = MD5Hash.HashStream(stream);

                Assert.AreEqual(expected, result);
            }
        }

        [TestMethod]
        public void MD5TestHelloWorldFile()
        {
            MD5Hash expected = new MD5Hash(ComputeHash<MD5CryptoServiceProvider>(HelloWorldBytes));
            MD5Hash result = MD5Hash.HashFile(TempFile);

            Assert.AreEqual(expected, result);
        }

        [TestMethod]
        public void MD5TestHashCode()
        {
            MD5Hash expected = new MD5Hash(ComputeHash<MD5CryptoServiceProvider>(HelloWorldBytes));
            MD5Hash result = MD5Hash.HashBytes(HelloWorldBytes);

            Assert.AreEqual(expected.GetHashCode(), result.GetHashCode());
        }

        [TestMethod]
        public void MD5TestBinaryHashCode()
        {
            MD5Hash expected = new MD5Hash(MD5_HASH_H);
            MD5Hash result = MD5Hash.HashBytes(HelloWorldBytes);

            Assert.IsTrue(expected.ToArray().SequenceEqual(result.ToArray()));
        }

        [TestMethod]
        public void MD5TestFormatting()
        {
            MD5Hash expected = new MD5Hash(MD5_HASH_H);

            Assert.AreEqual(MD5_HASH_H, expected.ToString(), true);
            Assert.AreEqual(MD5_HASH_H, expected.ToString("H"), true);
            Assert.AreEqual(MD5_HASH_D, expected.ToString("D"), true);
        }


        [TestMethod]
        public void MD5EqualityTests()
        {
            MD5Hash hash = new MD5Hash(MD5_HASH_H);
            MD5Hash hash2 = new MD5Hash(MD5_HASH_D);

            Assert.IsTrue(hash == hash2);
            Assert.IsFalse(hash != hash2);
            Assert.IsFalse(null == hash2);
            Assert.IsFalse(hash == null);
        }

        [TestMethod]
        public void MD5CompareTest()
        {
            MD5Hash hash = new MD5Hash(MD5_HASH_H);
            MD5Hash hash2 = new MD5Hash(MD5_HASH_D);

            Assert.AreEqual(0, hash.CompareTo((object)hash2));
            Assert.AreEqual(0, hash.CompareTo(hash2));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MD5CompareTestInvalidType()
        {
            MD5Hash hash = new MD5Hash(MD5_HASH_H);

            Assert.AreEqual(0, hash.CompareTo(0));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MD5CompareTestInvalidBinaryHashCode()
        {
            MD5Hash hash = new MD5Hash(new byte[0]);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void MD5CompareTestNullBinaryHashCode()
        {
            MD5Hash hash = new MD5Hash((byte[])null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void MD5CompareTestNullHash()
        {
            MD5Hash hash = new MD5Hash((string)null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MD5CompareTestInconsistentHash()
        {
            MD5Hash hash = new MD5Hash("ed07-62870532e08636-5e8401e920bfc500d8c");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MD5CompareTestInvalidHash()
        {
            MD5Hash hash = new MD5Hash("Ad076r87532e86365e841e92bfc50d8c");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MD5CompareTestInvalidFormat1()
        {
            MD5Hash hash = new MD5Hash(MD5_HASH_H);

            hash.ToString("INVALID");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void MD5CompareTestInvalidFormat2()
        {
            MD5Hash hash = new MD5Hash(MD5_HASH_H);

            hash.ToString("I");
        }

        [TestMethod]
        public void SHA1TestHelloWorld()
        {
            SHA1Hash expected = new SHA1Hash(ComputeHash<SHA1CryptoServiceProvider>(HelloWorldBytes));
            SHA1Hash result = SHA1Hash.HashBytes(HelloWorldBytes);

            Assert.AreEqual(expected, result);
        }

        [TestMethod]
        public void SHA1TestBinaryHashCode()
        {
            SHA1Hash expected = new SHA1Hash(SHA1_HASH_H);
            SHA1Hash result = SHA1Hash.HashBytes(HelloWorldBytes);

            Assert.IsTrue(expected.ToArray().SequenceEqual(result.ToArray()));
        }

        [TestMethod]
        public void SHA256TestHelloWorld()
        {
            SHA256Hash expected = new SHA256Hash(ComputeHash<SHA256CryptoServiceProvider>(HelloWorldBytes));
            SHA256Hash result = SHA256Hash.HashBytes(HelloWorldBytes);

            Assert.AreEqual(expected, result);
        }

        [TestMethod]
        public void SHA256TestBinaryHashCode()
        {
            SHA256Hash expected = new SHA256Hash(SHA256_HASH_H);
            SHA256Hash result = SHA256Hash.HashBytes(HelloWorldBytes);

            Assert.IsTrue(expected.ToArray().SequenceEqual(result.ToArray()));
        }

        [TestMethod]
        public void SHA384TestHelloWorld()
        {
            SHA384Hash expected = new SHA384Hash(ComputeHash<SHA384CryptoServiceProvider>(HelloWorldBytes));
            SHA384Hash result = SHA384Hash.HashBytes(HelloWorldBytes);

            Assert.AreEqual(expected, result);
        }

        [TestMethod]
        public void SHA384TestBinaryHashCode()
        {
            SHA384Hash expected = new SHA384Hash(SHA384_HASH_H);
            SHA384Hash result = SHA384Hash.HashBytes(HelloWorldBytes);

            Assert.IsTrue(expected.ToArray().SequenceEqual(result.ToArray()));
        }

        [TestMethod]
        public void SHA512TestHelloWorld()
        {
            SHA512Hash expected = new SHA512Hash(ComputeHash<SHA512CryptoServiceProvider>(HelloWorldBytes));
            SHA512Hash result = SHA512Hash.HashBytes(HelloWorldBytes);

            Assert.AreEqual(expected, result);
        }

        [TestMethod]
        public void SHA512TestBinaryHashCode()
        {
            SHA512Hash expected = new SHA512Hash(SHA512_HASH_H);
            SHA512Hash result = SHA512Hash.HashBytes(HelloWorldBytes);

            Assert.IsTrue(expected.ToArray().SequenceEqual(result.ToArray()));
        }

        [TestMethod]
        public void RIPEMD160TestHelloWorld()
        {
            RIPEMD160Hash expected = new RIPEMD160Hash(ComputeHash<RIPEMD160Managed>(HelloWorldBytes));
            RIPEMD160Hash result = RIPEMD160Hash.HashBytes(HelloWorldBytes);

            Assert.AreEqual(expected, result);
        }

        [TestMethod]
        public void RIPEMD160TestBinaryHashCode()
        {
            RIPEMD160Hash expected = new RIPEMD160Hash(RIPEMD160_HASH_H);
            RIPEMD160Hash result = RIPEMD160Hash.HashBytes(HelloWorldBytes);

            Assert.IsTrue(expected.ToArray().SequenceEqual(result.ToArray()));
        }
    }
}

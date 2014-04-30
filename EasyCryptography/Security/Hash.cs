using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Variel.Security
{
    public static class Hash
    {
        #region MD5Hash
        public static string MD5Hash(string input)
        {
            var inByte = Encoding.UTF8.GetBytes(input);
            var hashed = MD5Hash(inByte);

            return hashed;
        }

        public static string MD5Hash(byte[] input)
        {
            var sha = MD5CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }

        public static string MD5Hash(Stream input)
        {
            var sha = MD5CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion

        #region SHA1Hash
        public static string SHA1Hash(string input)
        {
            var inByte = Encoding.UTF8.GetBytes(input);
            var hashed = SHA1Hash(inByte);

            return hashed;
        }

        public static string SHA1Hash(byte[] input)
        {
            var sha = SHA1CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }

        public static string SHA1Hash(Stream input)
        {
            var sha = SHA1CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion

        #region SHA256Hash
        public static string SHA256Hash(string input)
        {
            var inByte = Encoding.UTF8.GetBytes(input);
            var hashed = SHA256Hash(inByte);

            return hashed;
        }

        public static string SHA256Hash(byte[] input)
        {
            var sha = SHA256CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }

        public static string SHA256Hash(Stream input)
        {
            var sha = SHA256CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion

        #region SHA512Hash
        public static string SHA512Hash(string input)
        {
            var inByte = Encoding.UTF8.GetBytes(input);
            var hashed = SHA512Hash(inByte);

            return hashed;
        }

        public static string SHA512Hash(byte[] input)
        {
            var sha = SHA256CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }

        public static string SHA512Hash(Stream input)
        {
            var sha = SHA256CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion
    }
}

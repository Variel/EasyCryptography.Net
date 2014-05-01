using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Variel.Security
{
    /// <summary>
    /// 사용할 해시 알고리즘을 선택합니다.
    /// </summary>
    public enum HashAlgorithm
    {
        MD5,
        SHA1,
        SHA256,
        SHA512
    }

    /// <summary>
    /// string, Array byte, stream 값을 받아 해시 값으로 변환해줍니다.
    /// </summary>
    public static class Hash
    {
        /// <summary>
        /// 알고리즘을 선택하여 값을 입력하면, 해시 알고리즘에 의해 나온 결과 값을 얻을 수 있습니다.
        /// </summary>
        /// <param name="hashAlgorithm">적용하고자 하는 알고리즘</param>
        /// <param name="inputString">변환하고자 하는 문자열</param>
        /// <returns>해시 알고리즘에 의해 나온 결과 값을 반환합니다.</returns>
        public static string Generate(HashAlgorithm hashAlgorithm, string inputString)
        {
            return Generate(hashAlgorithm, Encoding.UTF8.GetBytes(inputString));
        }

        /// <summary>
        /// 알고리즘을 선택하여 값을 입력하면, 해시 알고리즘에 의해 나온 결과 값을 얻을 수 있습니다.
        /// </summary>
        /// <param name="hashAlgorithm">적용하고자 하는 알고리즘</param>
        /// <param name="buffer">변환하고자 하는 바이트 배열</param>
        /// <returns>해시 알고리즘에 의해 나온 결과 값을 반환합니다.</returns>
        public static string Generate(HashAlgorithm hashAlgorithm, byte[] buffer)
        {
            return Generate(hashAlgorithm, new MemoryStream(buffer));
        }

        /// <summary>
        /// 알고리즘을 선택하여 값을 입력하면, 해시 알고리즘에 의해 나온 결과 값을 얻을 수 있습니다.
        /// </summary>
        /// <param name="hashAlgorithm">적용하고자 하는 알고리즘</param>
        /// <param name="inputStream">변환하고자 하는 Stream</param>
        /// <returns>해시 알고리즘에 의해 나온 결과 값을 반환합니다.</returns>
        public static string Generate(HashAlgorithm hashAlgorithm, Stream inputStream)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.MD5:
                    return md5Hash(inputStream);

                case HashAlgorithm.SHA1:
                    return sha1Hash(inputStream);

                case HashAlgorithm.SHA256:
                    return sha256Hash(inputStream);

                case HashAlgorithm.SHA512:
                    return sha256Hash(inputStream);

                default:
                    throw new ArgumentNullException("HashProvider is null");
            }
        }

        #region MD5Hash
        private static string md5Hash(Stream input)
        {
            var sha = MD5CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion

        #region SHA1Hash
        private static string sha1Hash(Stream input)
        {
            var sha = SHA1CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion

        #region SHA256Hash
        private static string sha256Hash(Stream input)
        {
            var sha = SHA256CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion

        #region SHA512Hash
        private static string sha512Hash(Stream input)
        {
            var sha = SHA256CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion
    }
}

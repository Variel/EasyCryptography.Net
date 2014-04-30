using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Variel.Security
{
    /// <summary>
    /// 사용할 해시 알고리즘을 선택합니다.
    /// </summary>
    public enum HashProvider
    {
        MD5,
        SHA1,
        SHA256,
        SHA512
    }

    /// <summary>
    /// string, Array byte, stream 값을 받아 해시 값으로 변환해줍니다.
    /// </summary>
    public static class HashService
    {
        /// <summary>
        /// 알고리즘을 선택하여 값을 입력하면, 해시 알고리즘에 의해 나온 결과 값을 얻을 수 있습니다.
        /// </summary>
        /// <param name="hashProvider">적용하고자 하는 알고리즘</param>
        /// <param name="inputString">변환하고자 하는 문자열</param>
        /// <returns>해시 알고리즘에 의해 나온 결과 값을 반환합니다.</returns>
        public static string GenerateHash(HashProvider hashProvider, string inputString)
        {
            return GenerateHash(hashProvider, Encoding.UTF8.GetBytes(inputString));
        }

        /// <summary>
        /// 알고리즘을 선택하여 값을 입력하면, 해시 알고리즘에 의해 나온 결과 값을 얻을 수 있습니다.
        /// </summary>
        /// <param name="hashProvider">적용하고자 하는 알고리즘</param>
        /// <param name="buffer">변환하고자 하는 바이트 배열</param>
        /// <returns>해시 알고리즘에 의해 나온 결과 값을 반환합니다.</returns>
        public static string GenerateHash(HashProvider hashProvider, byte[] buffer)
        {
            return GenerateHash(hashProvider, new MemoryStream(buffer));
        }

        /// <summary>
        /// 알고리즘을 선택하여 값을 입력하면, 해시 알고리즘에 의해 나온 결과 값을 얻을 수 있습니다.
        /// </summary>
        /// <param name="hashProvider">적용하고자 하는 알고리즘</param>
        /// <param name="inputStream">변환하고자 하는 Stream</param>
        /// <returns>해시 알고리즘에 의해 나온 결과 값을 반환합니다.</returns>
        public static string GenerateHash(HashProvider hashProvider, Stream inputStream)
        {
            switch (hashProvider)
            {
                case HashProvider.MD5:
                    return MD5Hash(inputStream);

                case HashProvider.SHA1:
                    return SHA1Hash(inputStream);

                case HashProvider.SHA256:
                    return SHA256Hash(inputStream);

                case HashProvider.SHA512:
                    return SHA256Hash(inputStream);

                default:
                    throw new ArgumentNullException("HashProvider is null");
            }
        }

        #region MD5Hash
        private static string MD5Hash(Stream input)
        {
            var sha = MD5CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion

        #region SHA1Hash
        private static string SHA1Hash(Stream input)
        {
            var sha = SHA1CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion

        #region SHA256Hash
        private static string SHA256Hash(Stream input)
        {
            var sha = SHA256CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion

        #region SHA512Hash
        private static string SHA512Hash(Stream input)
        {
            var sha = SHA256CryptoServiceProvider.Create();
            var hashed = sha.ComputeHash(input);

            return BitConverter.ToString(hashed);
        }
        #endregion
    }
}

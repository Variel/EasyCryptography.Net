using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using HashAlgo = System.Security.Cryptography.HashAlgorithm;

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
        /// <param name="input">변환하고자 하는 바이트 배열</param>
        /// <param name="shortFormat">짧은 포맷의 결과를 반환할지 여부를 결정합니다</param>
        /// <returns>해시 알고리즘에 의해 나온 결과 값을 반환합니다.</returns>
        public static string Generate(HashAlgorithm hashAlgorithm, byte[] input, bool shortFormat = false)
        {
            return Generate(hashAlgorithm, new MemoryStream(input), shortFormat);
        }

        /// <summary>
        /// 알고리즘을 선택하여 값을 입력하면, 해시 알고리즘에 의해 나온 결과 값을 얻을 수 있습니다.
        /// </summary>
        /// <param name="hashAlgorithm">적용하고자 하는 알고리즘</param>
        /// <param name="inputStream">변환하고자 하는 Stream</param>
        /// <param name="shortFormat">짧은 포맷의 결과를 반환할지 여부를 결정합니다</param>
        /// <returns>해시 알고리즘에 의해 나온 결과 값을 반환합니다.</returns>
        public static string Generate(HashAlgorithm hashAlgorithm, Stream inputStream, bool shortFormat = false)
        {
            var provider = GetProvider(hashAlgorithm);
            var hashed = provider.ComputeHash(inputStream);

            if (!shortFormat)
                return BitConverter.ToString(hashed).Replace("-", "");

            return hashed.ToShortString();
        }

        private static HashAlgo GetProvider(HashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.MD5:
                    return MD5.Create();

                case HashAlgorithm.SHA1:
                    return SHA1.Create();

                case HashAlgorithm.SHA256:
                    return SHA256.Create();

                case HashAlgorithm.SHA512:
                    return SHA512.Create();

                default:
                    throw new ArgumentException("Undefined Hash Algorithm");
            }
        }
    }
}

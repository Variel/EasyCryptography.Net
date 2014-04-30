using System.IO;
using System.Security.Cryptography;

namespace Variel.Security
{
    public static class Cryptography
    {
        #region AES Encryption
        public static byte[] EncryptAES(string key, byte[] salt, byte[] data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                var cs = GetEncryptStreamAES(key, salt, ms);

                cs.Write(data, 0, data.Length);

                cs.FlushFinalBlock();
                cs.Close();

                return ms.ToArray();
            }
        }

        public static byte[] EncryptAES(string key, byte[] salt, Stream input)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                var cs = GetEncryptStreamAES(key, salt, ms);

                CopyStream(ms, cs);

                cs.FlushFinalBlock();
                cs.Close();

                return ms.ToArray();
            }
        }

        public static byte[] EncryptAES(byte[] key, byte[] salt, byte[] data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                var cs = GetEncryptStreamAES(key, salt, ms);

                cs.Write(data, 0, data.Length);

                cs.FlushFinalBlock();
                cs.Close();

                return ms.ToArray();
            }
        }

        public static byte[] EncryptAES(byte[] key, byte[] salt, Stream input)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                var cs = GetEncryptStreamAES(key, salt, ms);

                CopyStream(ms, cs);

                cs.FlushFinalBlock();
                cs.Close();

                return ms.ToArray();
            }
        }

        public static CryptoStream GetEncryptStreamAES(string key, byte[] salt, Stream output)
        {
            var r = RijndaelManaged.Create();
            PasswordDeriveBytes pw = new PasswordDeriveBytes(key, salt);

            CryptoStream cs = new CryptoStream(output, r.CreateEncryptor(pw.GetBytes(32), pw.GetBytes(16)), CryptoStreamMode.Write);

            return cs;
        }

        public static CryptoStream GetEncryptStreamAES(byte[] key, byte[] salt, Stream output)
        {
            var r = RijndaelManaged.Create();
            PasswordDeriveBytes pw = new PasswordDeriveBytes(key, salt);

            CryptoStream cs = new CryptoStream(output, r.CreateEncryptor(pw.GetBytes(32), pw.GetBytes(16)), CryptoStreamMode.Write);

            return cs;
        }
        #endregion

        #region AES Decryption
        public static byte[] DecryptAES(string key, byte[] salt, byte[] input)
        {
            MemoryStream output = new MemoryStream();

            using (MemoryStream ms = new MemoryStream(input))
            {
                DecryptAES(key, salt, ms, output);
            }

            return output.ToArray();
        }

        public static byte[] DecryptAES(string key, byte[] salt, Stream input)
        {
            MemoryStream output = new MemoryStream();

            DecryptAES(key, salt, input, output);

            return output.ToArray();
        }

        public static void DecryptAES(string key, byte[] salt, Stream input, Stream output)
        {
            CryptoStream cs = GetDecryptStreamAES(key, salt, input);
            CopyStream(cs, output);
            cs.Close();
        }

        public static byte[] DecryptAES(byte[] key, byte[] salt, byte[] input)
        {
            MemoryStream output = new MemoryStream();

            using (MemoryStream ms = new MemoryStream(input))
            {
                DecryptAES(key, salt, ms, output);
            }

            return output.ToArray();
        }

        public static byte[] DecryptAES(byte[] key, byte[] salt, Stream input)
        {
            MemoryStream output = new MemoryStream();

            DecryptAES(key, salt, input, output);

            return output.ToArray();
        }

        public static void DecryptAES(byte[] key, byte[] salt, Stream input, Stream output)
        {
            CryptoStream cs = GetDecryptStreamAES(key, salt, input);
            CopyStream(cs, output);
            cs.Close();
        }


        public static CryptoStream GetDecryptStreamAES(string key, byte[] salt, Stream input)
        {
            var r = RijndaelManaged.Create();
            PasswordDeriveBytes pw = new PasswordDeriveBytes(key, salt);

            CryptoStream cs = new CryptoStream(input, r.CreateDecryptor(pw.GetBytes(32), pw.GetBytes(16)), CryptoStreamMode.Read);

            return cs;
        }
        public static CryptoStream GetDecryptStreamAES(byte[] key, byte[] salt, Stream input)
        {
            var r = RijndaelManaged.Create();
            PasswordDeriveBytes pw = new PasswordDeriveBytes(key, salt);

            CryptoStream cs = new CryptoStream(input, r.CreateDecryptor(pw.GetBytes(32), pw.GetBytes(16)), CryptoStreamMode.Read);

            return cs;
        }
        #endregion

        #region RSA Encryption
        public static byte[] EncryptRSA(byte[] input, RSAParameters key)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(key);

            return rsa.Encrypt(input, false);
        }

        public static byte[] EncryptRSA(byte[] input, string xmlKey)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(xmlKey);

            return rsa.Encrypt(input, false);
        }
        #endregion

        #region RSA Decryption
        public static byte[] DecryptRSA(byte[] input, RSAParameters key)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(key);

            return rsa.Decrypt(input, false);
        }
        public static byte[] DecryptRSA(byte[] input, string xmlKey)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(xmlKey);

            return rsa.Decrypt(input, false);
        }
        #endregion

        #region RSA KeyGeneration
        public static RSAParameters CreateRSAParameter()
        {
            return RSA.Create().ExportParameters(true);
        }
        #endregion

        //Is it do same as Stream.CopyTo?
        private static void CopyStream(Stream original, Stream target)
        {
            const int bufferSize = 2048;
            byte[] buffer = new byte[bufferSize];
            int readCount;

            while ((readCount = original.Read(buffer, 0, bufferSize)) != 0)
                target.Write(buffer, 0, readCount);
        }
    }
}

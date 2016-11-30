//
//  File Name: Crypto.cs
//  Project Name: Crypto
//
//  Created by Alexandro Luongo on 30/11/2016.
//  Copyright © 2016 Alexandro Luongo. All rights reserved.
//

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PwnFast
{
    /// <summary>
    /// Crypto: Class used to perform cryptographic operations using PokeFast's algorithm.
    /// </summary>
    public static class Crypto
    {
        /// <summary>
        /// CRYPTO_IV: Vector used to initialize the crypto flow.
        /// </summary>
        private static readonly string CRYPTO_IV = "AAAAAAAAAAAAAAAA";

        /// <summary>
        /// CRYPTO_KEY: Secret key used to initialize the crypto flow.
        /// </summary>
        private static readonly byte[] CRYPTO_KEY = new byte[] { 16, 69, 199, 252, 145, 123, 239, 32, 249, 75, 192, 195, 85, 197, 148, 53 };

        /// <summary>
        /// CFB Mode does not require padding, but official PokeFast server 
        /// checks for it in order to validate requests.
        /// </summary>
        /// <param name="Data">The array of bytes to pad.</param>
        /// <returns>Returns the padded array.</returns>
        private static byte[] Pad(byte[] Data)
        {
            var Result = new List<byte>();

            Result.AddRange(Data);

            var Extra = 16 - (Data.Length % 16);

            if (Extra < 16)
            {
                for (int i = 0; i < Extra; i++)
                {
                    Result.Add((byte)Extra);
                }
            }

            return Result.ToArray();
        }

        /// <summary>
        /// Encrypt an array of bytes.
        /// Algorithm used is Rijndael AES with a block and key size of 128 bits.
        /// </summary>
        /// <param name="Data">The array of bytes to encrypt.</param>
        /// <returns>Returns the encrypted array.</returns>
        internal static byte[] Encrypt(byte[] Data)
        {
            byte[] Result;

            Data = Pad(Data);

            using (RijndaelManaged AES = new RijndaelManaged())
            {
                AES.KeySize = 128;
                AES.BlockSize = 128;

                AES.Key = CRYPTO_KEY;
                AES.IV = Encoding.UTF8.GetBytes(CRYPTO_IV);
                
                AES.Mode = CipherMode.CFB;
                AES.Padding = PaddingMode.None;

                using (ICryptoTransform Crypto = AES.CreateEncryptor())
                {
                    Result = Crypto.TransformFinalBlock(Data, 0, Data.Length);
                }

                return Result.Take(Data.Length).ToArray();
            }
        }

        /// <summary>
        /// Decrypt an array of bytes.
        /// Algorithm used is Rijndael AES with a block and key size of 128 bits.
        /// </summary>
        /// <param name="Data">The array of bytes to decrypt.</param>
        /// <returns>Returns the decrypted array.</returns>
        internal static byte[] Decrypt(byte[] Data)
        {
            byte[] Result;

            Data = Pad(Data);

            using (RijndaelManaged AES = new RijndaelManaged())
            {
                AES.Key = CRYPTO_KEY;
                AES.IV = Encoding.UTF8.GetBytes(CRYPTO_IV);
                
                AES.Mode = CipherMode.CFB;
                AES.Padding = PaddingMode.None;

                using (ICryptoTransform Crypto = AES.CreateDecryptor())
                {
                    Result = Crypto.TransformFinalBlock(Data, 0, Data.Length);
                }

                return Result.Take(Data.Length).ToArray();
            }
        }
    }
}

// CryptoManager.cs  –  C# 7.3‑compatible, COM‑visible
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

[assembly: ComVisible(true)]

namespace CryptoLibrary
{
    /// <summary>
    /// AES‑256/CBC + HMAC‑SHA256 envelope and PBKDF2 password hashing
    /// (C# 7.3 friendly – no 'using var', no range operators)
    /// </summary>
    [ComVisible(true)]
    [Guid("8F212DE4-6ED5-4B25-8144-51D85D8A9C19")]
    [ProgId("CryptoLibrary.CryptoManager")]
    [ClassInterface(ClassInterfaceType.AutoDual)]
    public class CryptoManager
    {
        // =====================================================================
        //  Symmetric encryption  (Encrypt / Decrypt)
        // =====================================================================

        /// <returns>Base‑64:  SALT(16)|IV(16)|CIPHER|HMAC(32)</returns>
        public string Encrypt(string plainText, string secret)
        {
            try
            {
                // ----- derive 32‑byte key from pass‑phrase + random salt -----
                byte[] salt = RandomBytes(16);
                var kdf = new Rfc2898DeriveBytes(secret, salt, 100_000);
                byte[] key = kdf.GetBytes(32);

                string output;

                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = key;
                    aes.GenerateIV();

                    byte[] iv = aes.IV;
                    ICryptoTransform enc = aes.CreateEncryptor();
                    byte[] cipher = enc.TransformFinalBlock(
                                         Encoding.UTF8.GetBytes(plainText), 0, plainText.Length);

                    byte[] hmac = Hmac(key, salt, iv, cipher);
                    output = Convert.ToBase64String(Concat(salt, iv, cipher, hmac));
                }
                return output;
            }
            catch (Exception ex)
            {
                throw new COMException("Encrypt failed: " + ex.Message, ex);
            }
        }

        public string Decrypt(string cipherPackage, string secret)
        {
            try
            {
                byte[] all = Convert.FromBase64String(cipherPackage);

                // ------ split the payload without C# 8 range operators ------
                byte[] salt = new byte[16];
                byte[] iv = new byte[16];
                byte[] hmac = new byte[32];

                Buffer.BlockCopy(all, 0, salt, 0, 16);
                Buffer.BlockCopy(all, 16, iv, 0, 16);
                Buffer.BlockCopy(all, all.Length - 32, hmac, 0, 32);

                int cipherLen = all.Length - 16 - 16 - 32;
                byte[] cipher = new byte[cipherLen];
                Buffer.BlockCopy(all, 32, cipher, 0, cipherLen);

                byte[] key = new Rfc2898DeriveBytes(secret, salt, 100_000).GetBytes(32);
                byte[] exp = Hmac(key, salt, iv, cipher);

                if (!FixedTimeEquals(exp, hmac))
                    throw new CryptographicException("HMAC mismatch – wrong key or tampered data.");

                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = key;
                    aes.IV = iv;

                    ICryptoTransform dec = aes.CreateDecryptor();
                    byte[] plain = dec.TransformFinalBlock(cipher, 0, cipher.Length);
                    return Encoding.UTF8.GetString(plain);
                }
            }
            catch (Exception ex)
            {
                throw new COMException("Decrypt failed: " + ex.Message, ex);
            }
        }

        // =====================================================================
        //  PBKDF2 password hash / verify
        // =====================================================================

        /// <returns>Base‑64:  SALT(16)|HASH(32)</returns>
        public string HashPassword(string password)
        {
            try
            {
                byte[] salt = RandomBytes(16);
                var kdf = new Rfc2898DeriveBytes(password, salt, 150_000);
                byte[] hash = kdf.GetBytes(32);
                return Convert.ToBase64String(Concat(salt, hash));
            }
            catch (Exception ex)
            {
                throw new COMException("HashPassword failed: " + ex.Message, ex);
            }
        }

        public bool VerifyPassword(string password, string stored)
        {
            try
            {
                byte[] all = Convert.FromBase64String(stored);

                byte[] salt = new byte[16];
                Buffer.BlockCopy(all, 0, salt, 0, 16);

                byte[] hash = new byte[32];
                Buffer.BlockCopy(all, 16, hash, 0, 32);

                byte[] test = new Rfc2898DeriveBytes(password, salt, 150_000).GetBytes(32);
                return FixedTimeEquals(hash, test);
            }
            catch
            {
                return false;
            }
        }

        // =====================================================================
        //  Helpers
        // =====================================================================

        private static byte[] RandomBytes(int len)
        {
            byte[] b = new byte[len];
            using (var rng = new RNGCryptoServiceProvider())   // .NET Framework‑friendly
            {
                rng.GetBytes(b);                               // fills the array with cryptographically‑secure random bytes
            }
            return b;
        }

        private static byte[] Concat(params byte[][] arrays)
        {
            int len = 0;
            foreach (var a in arrays) len += a.Length;

            byte[] result = new byte[len];
            int pos = 0;
            foreach (var a in arrays)
            {
                Buffer.BlockCopy(a, 0, result, pos, a.Length);
                pos += a.Length;
            }
            return result;
        }

        private static byte[] Hmac(byte[] key, params byte[][] chunks)
        {
            using (var h = new HMACSHA256(key))
            {
                foreach (var c in chunks) h.TransformBlock(c, 0, c.Length, null, 0);
                h.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                return h.Hash;
            }
        }

        /// <summary>Constant‑time comparison to avoid timing attacks.</summary>
        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}

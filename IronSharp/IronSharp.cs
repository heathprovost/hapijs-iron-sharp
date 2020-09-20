using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace IronSharp
{
    public static class IronSharp
    {
        public readonly struct Options
        {
            public int Ttl { get; }
            public int TimestampSkew { get; }
            public int LocaltimeOffset { get; }
            public Options(int ttl, int timestampSkew = (60 * 1000), int localtimeOffset = 0)
            {
                Ttl = ttl;
                TimestampSkew = timestampSkew;
                LocaltimeOffset = localtimeOffset;
            }
        }

        public static readonly Options DEFAULTS = new Options(ttl: 0);

        private const string MAC_FORMAT_VERSION = "2";
        private const string MAC_PREFIX = "Fe26." + MAC_FORMAT_VERSION;
        private const int MAC_PARTS_COUNT = 8;

        private const int ITERATIONS = 1;
        private const int MIN_PASSWORD_LEN = 32;
        private const int SALT_BITS = 256;
        private const int KEY_BITS = 256;
        private const int IV_BITS = 128;

        private readonly struct Derivables
        {
            public byte[] CipherKey { get; }
            public byte[] CipherIv { get; }
            public string CipherSalt { get; }
            public byte[] HmacKey { get; }
            public string HmacSalt { get; }
            public Derivables(string password, byte[] cipherKey = null, byte[] cipherIv = null, string cipherSalt = null, byte[] hmacKey = null, string hmacSalt = null)
            {
                if (string.IsNullOrEmpty(password))
                {
                    throw new Exception("Empty password");
                }
                if (password.Length < MIN_PASSWORD_LEN)
                {
                    throw new Exception("Password string too short (min " + MIN_PASSWORD_LEN + " characters required)");
                }
                CipherSalt = cipherSalt ?? BytesToHex(RandomBits(SALT_BITS));
                CipherKey = cipherKey ?? PBKDF2(password, CipherSalt, ITERATIONS);
                CipherIv = cipherIv ?? RandomBits(IV_BITS);
                HmacSalt = hmacSalt ?? BytesToHex(RandomBits(SALT_BITS));
                HmacKey = hmacKey ?? PBKDF2(password, HmacSalt, ITERATIONS);

                string BytesToHex(byte[] bytes, bool toLowerCase = true)
                {
                    if (bytes == null) return null;
                    byte addByte = 0x57;
                    char[] c = new char[bytes.Length * 2];
                    byte b;
                    for (int i = 0; i < bytes.Length; ++i)
                    {
                        b = ((byte)(bytes[i] >> 4));
                        c[i * 2] = (char)(b > 9 ? b + addByte : b + 0x30);
                        b = ((byte)(bytes[i] & 0xF));
                        c[i * 2 + 1] = (char)(b > 9 ? b + addByte : b + 0x30);
                    }
                    return new string(c);
                }

                byte[] RandomBits(int numberOfBits)
                {
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        var buffer = new byte[numberOfBits / 8];
                        rng.GetBytes(buffer);
                        return buffer;
                    }
                }

                byte[] PBKDF2(string pw, string salt, int iterations)
                {
                    using (var pbkdf2 = new Rfc2898DeriveBytes(pw, Encoding.UTF8.GetBytes(salt), iterations))
                    {
                        return pbkdf2.GetBytes(KEY_BITS / 8);
                    }
                }

            }
        }

        private static string Base64urlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
              .Replace('+', '-')
              .Replace('/', '_')
              .Replace("=", "");
        }

        private static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+');
            output = output.Replace('_', '/');
            switch (output.Length % 4)
            {
                case 0:
                    break;
                case 2:
                    output += "==";
                    break;
                case 3:
                    output += "=";
                    break;
                default:
                    throw new Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output);
            return converted;
        }

        private static string Encrypt(string password, string plaintext, Derivables derived)
        {
            byte[] encrypted;
            using (AesManaged aes = new AesManaged())
            {
                aes.Key = derived.CipherKey;
                aes.IV = derived.CipherIv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                ICryptoTransform encryptor = aes.CreateEncryptor();
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plaintext);
                        }
                        encrypted = ms.ToArray();
                    }
                }
            }
            return Base64urlEncode(encrypted);
        }

        private static string Decrypt(string password, byte[] ciphertext, Derivables derived)
        {
            string decrypted;
            using (AesManaged aes = new AesManaged())
            {
                aes.Key = derived.CipherKey;
                aes.IV = derived.CipherIv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                ICryptoTransform decryptor = aes.CreateDecryptor();
                using (MemoryStream ms = new MemoryStream(ciphertext))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            decrypted = sr.ReadToEnd();
                        }
                    }
                }
            }
            return decrypted;
        }


        private static string Hmac(string data, Derivables derived)
        {
            using (var hasher = new HMACSHA256(derived.HmacKey))
            {
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] hashed = hasher.ComputeHash(dataBytes);
                return Base64urlEncode(hashed);
            }
        }

        private static bool TimingSafeEquals(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
                diff |= (uint)(a[i] ^ b[i]);
            return diff == 0;
        }

        public static string Seal(string data, string password, Options options)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + options.LocaltimeOffset;
            var derived = new Derivables(password);
            var encrypted = Encrypt(password, data, derived);
            var expiration = (options.Ttl > 0) ? (now + options.Ttl) + "" : "";
            var macBaseString = MAC_PREFIX + "**" + derived.CipherSalt + "*" + Base64urlEncode(derived.CipherIv) + "*" + encrypted + "*" + expiration;
            var mac = Hmac(macBaseString, derived);
            var ironed = macBaseString + "*" + derived.HmacSalt + "*" + mac;
            return ironed;
        }

        public static string Unseal(string data, string password, Options options)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + options.LocaltimeOffset;
            var parts = data.Split('*');
            if (parts.Length != MAC_PARTS_COUNT) {
                throw new Exception("Incorrect number of sealed components");
            }
            var macPrefix = parts[0];
            var passwordId = parts[1];
            var cipherSalt = parts[2];
            var cipherIv = parts[3];
            var encryptedB64 = parts[4];
            var expiration = parts[5];
            var hmacSalt = parts[6];
            var hmac = parts[7];
            var macBaseString  = macPrefix + '*' + passwordId + '*' + cipherSalt + '*' + cipherIv + '*' + encryptedB64 + '*' + expiration;
            if (macPrefix != MAC_PREFIX) {
                throw new Exception("Wrong mac prefix");
            }
            if (!string.IsNullOrEmpty(expiration))
            {
                if (long.TryParse(expiration, out long exp))
                {
                    if (exp <= (now - options.TimestampSkew))
                    {
                        throw new Exception("Expired seal");
                    }
                }
                else
                {
                    throw new Exception("Invalid expiration");
                }
            }
            if (string.IsNullOrEmpty(password))
            {
                throw new Exception("Empty password");
            }
            var derived = new Derivables(password, cipherSalt: cipherSalt, cipherIv: Base64UrlDecode(cipherIv), hmacSalt: hmacSalt);
            var digest = Hmac(macBaseString, derived);
            if (!TimingSafeEquals(Encoding.UTF8.GetBytes(digest), Encoding.UTF8.GetBytes(hmac)))
            {
                throw new Exception("Bad hmac value");
            }
            var encrypted = Base64UrlDecode(encryptedB64);
            var decrypted = Decrypt(password, encrypted, derived);
            return decrypted;
        }

    }

}

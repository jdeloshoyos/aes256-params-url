using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Linq;
using System.IO;

namespace ejemplo_cifrado_aes256
{
    class MetodosCifrado
    {
        public static string EncriptaParametros(string payload, string clave)
        {
            // Encripta la información. Devuelve un Base64 conteniendo el payload cifrado con AES-256

            // Convertimos el secreto a un hash de 256 bits, para usar eso como clave de cifrado con AES-256
            byte[] ClaveHash = GeneraHash(clave);
            Console.WriteLine("Hash de clave: " + ByteArrayAString(ClaveHash));

            // Encriptamos en AES-256 el payload, usando esta clave
            byte[] payload_cifrado;
            byte[] iv;
            using (Aes myAes = Aes.Create())
            {
                payload_cifrado = EncryptStringToBytes_Aes(payload, ClaveHash, myAes.IV);
                iv = myAes.IV;
            }

            // Encodeamos la data cifrada en Base64
            string resultado = Convert.ToBase64String(payload_cifrado);
            // Convertimos Base64 a una versión URL-safe
            resultado = resultado.Replace('+', '-').Replace('/', '_');

            // Lo mismo con el vector de inicialización. Lo tenemos que adjuntar al texto cifrado, para ser usado por el descifrado.
            string iv_b64 = Convert.ToBase64String(iv);
            iv_b64 = iv_b64.Replace('+', '-').Replace('/', '_');

            return iv_b64 + "." + resultado;
        }

        public static string DecriptaParametros(string payload, string clave)
        {
            // Decripta la información pasada en Base64. Devuelve un string con el payload original en texto plano

            // Convertimos el secreto a un hash de 256 bits, para usar eso como clave de cifrado con AES-256
            byte[] ClaveHash = GeneraHash(clave);
            Console.WriteLine("Hash de clave: " + ByteArrayAString(ClaveHash));

            // Decodeamos la data que viene como Base64. Volvemos de una versión URL-safe a un Base64 estándar (para eso los replace)
            // Ojo, que el payload en Base64 tiene dos partes, separadas por un punto. El punto separa el vector de inicialización,
            // necesario para el descifrado AES, del ciphertext propiamente tal. Debemos separarlos primero.
            string[] payload_partes = payload.Split(".");

            // Vector de inicialización
            string iv = payload_partes[0].Replace('_', '/').Replace('-', '+');
            byte[] iv_bytes = Convert.FromBase64String(iv);

            // Payload propiamente tal
            string payload_texto = payload_partes[1].Replace('_', '/').Replace('-', '+');
            byte[] payload_bytes = Convert.FromBase64String(payload_texto);

            // Decriptamos con AES-256 el payload cifrado
            string resultado;
            resultado = DecryptStringFromBytes_Aes(payload_bytes, ClaveHash, iv_bytes);

            return resultado;
        }


        /**********************
         * MÉTODOS AUXILIARES *
         **********************/

        private static byte[] GeneraHash(string clave)
        {
            // Devuelve un byte array con el hash SHA-256 para una clave en texto
            byte[] secreto_hash;

            using (SHA256 mySHA256 = SHA256.Create())
            {
                byte[] clave_bytes = Encoding.ASCII.GetBytes(clave);
                secreto_hash = mySHA256.ComputeHash(clave_bytes);
            }

            return secreto_hash;
        }

        private static string ByteArrayAString(byte[] array)
        {
            // Muestra el array de bytes en un formato legible
            string resultado = "";

            for (int i = 0; i < array.Length; i++)
            {
                resultado += $"{array[i]:X2}";
                //if ((i % 4) == 3) resultado += " ";   // Para separar en grupos de 4 bytes
            }

            return resultado;
        }

        /********************************
         * CIFRADO Y DESCIFRADO AES-256 *
         ********************************/

        // Las siguientes clases están tomadas directo de la documentación de Microsoft para uso de AES-256
        // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=netcore-3.1

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}

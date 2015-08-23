using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace de.bag.owh
{
    internal static class Helper
    {
        /// <summary>
        /// Generische Hilfsfunktion für die Erzeugung und ausgabe von Hashes
        /// </summary>
        /// <typeparam name="T">Typ der Kryptos (implizit)</typeparam>
        /// <param name="crypto">Art der Krypto</param>
        /// <param name="password">Wert, der gehased werden soll</param>
        public static void Enc<T>(T crypto, Byte[] password) where T : HashAlgorithm
        {
            var hash = crypto.ComputeHash(password);
            var hashStr = BitConverter.ToString(hash);
            Console.WriteLine("{0}: \t{1}\n\r", typeof(T).Name, hashStr.Replace("-", "").ToLower());
        }


        /// <summary>
        /// Läd Pepper aus einer externen Quelle
        /// Zur Vereinfachung wurde hier eine eingebettete Resource verwendet
        /// Normaler Weise muss hier eine externe Quelle angebunden werden!
        /// Dies hätte die Lauffähigkeit des Demos erschwert
        /// </summary>
        /// <returns>Entschlüsselter Pepper Wert</returns>
        internal static string LoadPepper()
        {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("de.bag.owh.Base64EncodedPepper.txt"))
            {
                using (var encodedPepper = new StreamReader(stream))
                {
                    return Encoding.UTF8.GetString(Convert.FromBase64String(encodedPepper.ReadToEnd().ToString()));
                }
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using CryptSharp;
using SHA3;
using System.Reflection;
using System.IO;

namespace de.bag.owh
{
    class Program
    {
        #region UI
        static void Main(string[] args)
        {
            Console.Write("Please enter an imagined Password that we will user for the demo:");
            var password = string.Empty;
            
            while(string.IsNullOrEmpty(password))
                password = Console.ReadLine();

            var doExit = false;
            while(!doExit)
            {
                Console.Clear();
                Console.WriteLine("Password:{0}", password);
                Console.WriteLine("============================");
                Console.WriteLine("==          MENU          ==");
                Console.WriteLine("============================");
                Console.WriteLine("1: SimpleTest (Run all hash-algorithms one time)");
                Console.WriteLine("2: MassTest (1250 iterations of BCrypt algorithm with m-time cost factor compared to 1250 SHA-3 hashes");
                Console.WriteLine("0: Exit");
                Console.Write("Choose:");
                switch(Console.ReadLine())
                {
                    case "1": 
                        SimpleTests(password); 
                        break;
                    case "2":
                        MassTest(password);
                        break;
                    case "0":
                        doExit = true;
                        break;
                }
            }            
        }

        private static void MassTest(string password)
        {
            int costfactor = 0;
            int iterations = 1250;
            Console.Clear();
            Console.WriteLine("Password:{0}", password);

            Console.WriteLine("============================");
            Console.WriteLine("==        MASS TEST       ==");
            Console.WriteLine("============================");

            Console.Write("Enter cost factor for bcrypt (between 4-31; default is 6): ");
            if (!int.TryParse(Console.ReadLine(), out costfactor))
            {
                costfactor = 6;
            }

            if (costfactor < 4)
                costfactor = 4;
            else if (costfactor > 31)
                costfactor = 31;


            Console.Write("Crypting the password {0} times with a cost factor of {1}...\n\r", iterations, costfactor);
            var startStime = DateTime.Now;
            for(var i = 1; i <= iterations; i++)
            {
                var b1 = BlowfishCrypter.Blowfish.Crypt(string.Concat("{0}{1}", password, i), BlowfishCrypter.Blowfish.GenerateSalt(costfactor));
                if(i%50 == 0)
                    Console.Write("{0} ", i);
            }
            var endTime = DateTime.Now.Subtract(startStime);

            Console.WriteLine("done");
            Console.WriteLine("Operation took {0} to complete.", endTime.ToString("c"));
            Console.WriteLine("");


            Console.Write("Crypting the password {0} times using SHA-3 with 512Bit length...\n\r", iterations);
            startStime = DateTime.Now;
            for (var i = 1; i <= iterations; i++)            
            {
                var bytes = new ASCIIEncoding().GetBytes(string.Concat("{0}{1}", password, i));                
                var sha3 = new SHA3.SHA3Managed(512);
                sha3.ComputeHash(bytes);
                if (i % 50 == 0)
                    Console.Write("{0} ", i);
            }
            endTime = DateTime.Now.Subtract(startStime);

            Console.WriteLine("done");
            Console.WriteLine("Operation took {0} to complete.\n\r", endTime.ToString("c"));
            Console.WriteLine("Press any key to return to menu");
            Console.ReadKey();
        }

        private static void SimpleTests(string password)
        {
            Console.Clear();
            Console.WriteLine("Password:{0}", password);

            Console.WriteLine("============================");
            Console.WriteLine("==       SIMPLE TEST      ==");
            Console.WriteLine("============================");

            HashPassword(password);

            Console.WriteLine("\n\rSalted hash:");
            SaltPassword(password, "@cd3wwBLqQtreBpa4GGHaSuNO0B1337xOr");

            Console.WriteLine("\n\rBlowfish hash:");
            BlowfishPassword(password);

            Console.WriteLine("\n\rBlowfish + Pepper hash:");

            string pepper = Helper.LoadPepper();            
            BlowfishPepper(password, pepper);

            Console.WriteLine("\n\rSHA3 (512) hash:");
            SHA3(password);

            Console.WriteLine("Press any key to return to menu");
            Console.ReadKey();
        }        
        #endregion

        #region MD5 + SHA1-3
        /// <summary>
        /// Sammelaufruf für diverse Varianten von MD5 und SHA1+2 in der nativen und der HMAC Variante
        /// </summary>
        /// <param name="password">Die zu hashende Zeichenkette</param>
        private static void HashPassword(string password)
        {            
            var bytes = new ASCIIEncoding().GetBytes(password);
            Helper.Enc(new SHA1Cng(), bytes);
            Helper.Enc(new SHA256Cng(), bytes);
            Helper.Enc(new SHA512Cng(), bytes);
            
            Helper.Enc(new MD5Cng(), bytes);

            Helper.Enc(new HMACSHA1(), bytes);
            Helper.Enc(new HMACSHA256(), bytes);
            Helper.Enc(new HMACSHA384(), bytes);
            Helper.Enc(new HMACSHA512(), bytes);
            Helper.Enc(new HMACMD5(), bytes);
        }

        /// <summary>
        /// Erzeugt einen SHA-3 hash
        /// </summary>
        /// <param name="password">Die zu hashende Zeichenkette</param>
        private static void SHA3(string password)
        {
            var bytes = new ASCIIEncoding().GetBytes(password);
            Helper.Enc(new SHA3.SHA3Managed(512), bytes);
        }
        #endregion

        #region Salt
        /// <summary>
        /// Versieht eine variable Zeichenkette mit einem Salt und verwendet das Ergebnis, um <see cref="HasPassword"/> damit aufzurufen
        /// </summary>
        /// <param name="password">Die variable Zeichenkette</param>
        /// <param name="salt">Der Salt-Wert</param>
        private static void SaltPassword(string password, string salt)
        {
            HashPassword(string.Concat(password, salt));
        }
        #endregion

        #region Blowfish + Pepper
        /// <summary>
        /// Erzeugt einen BCrypt Hash
        /// </summary>
        /// <param name="password">Die zu hashende Zeichenkette</param>
        private static void BlowfishPassword(string password)
        {
            //Beispiel mit 2a und 10 Runden 
            var b0 = BlowfishCrypter.Blowfish.Crypt(password, BlowfishCrypter.Blowfish.GenerateSalt(10));
            Console.WriteLine("Blowfish (payload 10): {0}", b0);
            Console.WriteLine("Check: {0}", BlowfishCrypter.CheckPassword(new ASCIIEncoding().GetBytes(password), b0));

            //Beispiel mit 2y und 10 runden
            var b1 = BlowfishCrypter.Blowfish.Crypt(password, BlowfishCrypter.Blowfish.GenerateSalt(new CrypterOptions { { CrypterOption.Variant, BlowfishCrypterVariant.Corrected }, { CrypterOption.Rounds, 10 } }));
            Console.WriteLine("Blowfish (payload 10): {0}", b1);
            Console.WriteLine("Check: {0}", BlowfishCrypter.CheckPassword(new ASCIIEncoding().GetBytes(password), b1));

            ///Beispiel mit Standardeinstellung (2a und 6 Runden)
            var b2 = BlowfishCrypter.Blowfish.Crypt(password);
            Console.WriteLine("Blowfish (payload 6): {0}", b2);
            Console.WriteLine("Check: {0}", BlowfishCrypter.CheckPassword(new ASCIIEncoding().GetBytes(password), b2));
        }

        //BCrypt / Blowfish und Pepper
        /// <summary>
        /// Erzeugt einen BCrypt hash mit vorheriger Erzeugung eines peppers
        /// </summary>
        /// <param name="password">Der variable Wert für den Hash</param>
        /// <param name="pepper">Der geladene Pepper-Wert</param>
        private static void BlowfishPepper(string password, string pepper)
        {
            var b1 = BlowfishCrypter.Blowfish.Crypt(SHA3Pepper(password, pepper), BlowfishCrypter.Blowfish.GenerateSalt(new CrypterOptions { { CrypterOption.Variant, BlowfishCrypterVariant.Corrected }, { CrypterOption.Rounds, 10 } }));
            Console.WriteLine("Blowfish (payload 10): {0}", b1);
            Console.WriteLine("Check: {0}", BlowfishCrypter.CheckPassword(new ASCIIEncoding().GetBytes(SHA3Pepper(password, pepper)), b1));
        }        

        /// <summary>
        /// Erzeugt die Eingabe für BCrypt mit Hilfe des SHA-3 Algorithmus aus eingegebenen Passwort und geladenem Pepper
        /// </summary>
        /// <param name="password">Der variable Wert für den Hash</param>
        /// <param name="pepper">Der geladene Pepper-Wert</param>
        /// <returns>Der SHA-3 Hash, welcher als Eingabe für BCrypt dient.</returns>
        private static string SHA3Pepper(string password, string pepper)
        {
            var bytes = new ASCIIEncoding().GetBytes(string.Concat(password, pepper));
            var crypto = new SHA3Managed(256);
            var hash = crypto.ComputeHash(bytes);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
        #endregion
     
    }
}

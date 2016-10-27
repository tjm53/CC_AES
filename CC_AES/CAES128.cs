namespace CC_AES
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;

    /// <summary>
    /// Classe AES128 qui contient les traitements mathématiques AES_CMAC et AES_CTR en 128 bits
    /// </summary>
    public static class CAES128
    {
        /// <summary> Taille de la clé en bits </summary>
        private const int KeySize = 128;

        /// <summary> Valeur zéro </summary>
        private static readonly byte[] constZero = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        /// <summary> Constante RB </summary>
        private static byte[] constRb = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 };

        /// <summary>
        /// Calcul du HashMac selon l'algorithme AES_CMAC
        /// </summary>
        /// <param name="input">Données à traiter</param>
        /// <param name="key">Clé à utiliser</param>
        /// <returns>16 octets du hashMac</returns>
        public static byte[] AES_CMAC(byte[] input, byte[] key)
        {
            byte[] tempX = (byte[])constZero.Clone();
            byte[] tempY;
            int runNb;
            byte[] mac = new byte[KeySize];

            // Padding de input "input"
            byte[] lastBlock = LastBlockPadding(input, key);

            // Calcul du nombre de run à faire (au moins 1);
            runNb = Math.Max(1, (input.Length + 15) / 16);

            // Algorithme de AES_CMAC
            for (int i = 0; i < runNb - 1; i++)
            {
                tempY = Xor128(tempX, input.Where((val, idx) => idx >= 16 * i && idx < 16 * (i + 1)).ToArray());
                tempX = EncryptRijndael(tempY, key);
            }

            tempY = Xor128(tempX, lastBlock);
            tempX = EncryptRijndael(tempY, key);

            return tempX;
        }

        /// <summary>
        /// Chiffrement en AES Compteur
        /// </summary>
        /// <param name="input">Données à chiffrer</param>
        /// <param name="key">Clé de chiffrement</param>
        /// <param name="iv">IV à utiliser</param>
        /// <returns>Données chiffrées (même longeur que input)</returns>
        public static byte[] AES_CTR(byte[] input, byte[] key, byte[] iv)
        {
            // Si la données à chiffer est null, renvoyer null
            if (input == null)
            {
                return null;
            }

            byte[] ret = new byte[input.Length];


            // Pour chaque bloc de 16 octets de input
            for (int i = 0; i < ((input.Length - 1) / 16) + 1; i++)
            {
                // Chiffrement de l'IV avec la clé
                byte[] encryptedIV = EncryptRijndael(iv, key);

                byte[] data = (byte[])constZero.Clone();

                // Sélection des octets de input
                Array.Copy(input, 16 * i, data, 0, Math.Min(16, ret.Length - (i * 16)));

                // Incrément de l'IV pour le prochain bloc
                iv = Increment(iv);

                // les blocs concernés sont copiés dans le tableau de résultat
                Array.Copy(Xor128(data, encryptedIV), 0, ret, i * 16, Math.Min(16, ret.Length - (i * 16)));
            }

            return ret;
        }

        #region Méthodes de chiffrement
        /// <summary>
        /// Calcule l'AES ECB d'un tableau d'octets en fonction d'une clé
        /// </summary>
        /// <param name="input">Tableau à chiffrer</param>
        /// <param name="key">Clé de chiffrement</param>
        /// <returns> Tableau chiffré </returns>
        private static byte[] EncryptRijndael(byte[] input, byte[] key)
        {
            // Le chiffrement ne se fait que sur un tableau de 16 octets
            if (input.Length == 16)
            {
                // Configuration de l'algorithme de chiffrement
                RijndaelManaged rijAlg = new RijndaelManaged
                {
                    KeySize = KeySize,
                    Key = key,
                    BlockSize = 128,
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.Zeros
                };

                // Mécanisme de chiffrement
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Chiffrement
                return encryptor.TransformFinalBlock(input, 0, input.Length);
            }
            else
            {
                // Si l'input ne fait pas la bonne longueur
                throw new ArgumentOutOfRangeException();
            }
        }
        #endregion

        #region Méthodes Communes

        /// <summary>
        /// Complète si nécessaire le dernier bloc de données pour atteindre 16 octets
        /// </summary>
        /// <param name="input">Données à padder</param>
        /// <param name="key">Clé utilisée dans le process</param>
        /// <returns>Données paddées</returns>
        private static byte[] LastBlockPadding(byte[] input, byte[] key)
        {
            bool flag;
            int length = input.Length;
            int runNb = (length + 15) / 16;

            // Génération des clés intermédiaires
            // Peut être mutualisés si changement de la clé
            byte[][] tempK = GenerateSubkey(key);
            byte[] k1 = tempK[0];
            byte[] k2 = tempK[1];

            if (runNb == 0)
            {
                flag = false;
            }
            else
            {
                flag = (length % 16) == 0;
            }

            if (flag)
            {
                // Si il ne faut pas padder le dernier bloc
                return Xor128(input.Where((val, idx) => idx >= 16 * (runNb - 1)).ToArray(), k1);
            }
            else
            {
                // Si il faut padder le dernier bloc
                byte[] padded = Padding(input.Where((val, idx) => idx >= 16 * (runNb - 1)).ToArray());
                return Xor128(padded, k2);
            }
        }

        /// <summary>
        /// Méthode padding pour l'AES CMAC
        /// Ajoute 1 puis autant de 0 qu'il faut sur 16 octets au total
        /// </summary>
        /// <param name="lastb">Tableau initial</param>
        /// <returns>Tableau paddé</returns>
        private static byte[] Padding(byte[] lastb)
        {
            byte[] pad = new byte[16];

            // Les premiers octets sont les mêmes
            lastb.CopyTo(pad, 0);

            // L'octet suivant est 10000000 (0x80)
            if (lastb.Length < 16)
            {
                pad[lastb.Length] = 0x80;
            }

            // Tous les derniers octets sont à 00000000 (0x00)
            for (int j = lastb.Length + 1; j < 16; j++)
            {
                pad[j] = 0x00;
            }

            return pad;
        }

        /// <summary>
        /// Réalise un XOR sur 2 tableaux de 16 octets
        /// </summary>
        /// <param name="a">Première opérande</param>
        /// <param name="b">Seconde opérande</param>
        /// <returns>Résultat du XOR</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        private static byte[] Xor128(byte[] a, byte[] b)
        {
            byte[] ret = new byte[16];

            // Pour chaque octet, réalisation d'un XOR
            if (a.Length == 16 && b.Length == 16)
            {
                for (int i = 0; i < 16; i++)
                {
                    ret[i] = Convert.ToByte(a[i] ^ b[i]);
                }
            }
            else
            {
                // Si une des 2 opérandes ne fait pas 128 octets
                throw new ArgumentOutOfRangeException();
            }

            return ret;
        }

        /// <summary>
        /// Génération des clés intermédiaires K1 et K2 pour l'AES CMAC
        /// </summary>
        /// <param name="key">Clé de chiffrement</param>
        /// <returns>2 tableaux d'octets (K1 et K2)</returns>
        private static byte[][] GenerateSubkey(byte[] key)
        {
            byte[] emptyCrypt;
            byte[] k1;
            byte[] k2;
            byte[][] k3 = new byte[2][];
            byte[] z = (byte[])constZero.Clone();

            // Chiffrement d'une chaîne de zéros
            emptyCrypt = EncryptRijndael(z, key);

            if ((emptyCrypt[0] & 0x80) == 0)
            {
                // Si le résultat commence par 1 
                k1 = LeftshiftOnebit(emptyCrypt);
            }
            else
            {
                // Sinon
                k1 = Xor128(LeftshiftOnebit(emptyCrypt), constRb);
            }

            if ((k1[0] & 0x80) == 0)
            {
                // Si K1 commence par 1
                k2 = LeftshiftOnebit(k1);
            }
            else
            {
                // Sinon
                k2 = Xor128(LeftshiftOnebit(k1), constRb);
            }

            // Préparation de la valeur de retour
            k3[0] = k1;
            k3[1] = k2;

            return k3;
        }

        /// <summary>
        /// Décalage des bits vers la droite dans un tableau d'octet.
        /// 11000011 10011001 (0xC399) devient 10000111 00110010 (0x8742)
        /// </summary>
        /// <param name="input">Tableau à transformer</param>
        /// <returns>Tableau transformé</returns>
        private static byte[] LeftshiftOnebit(byte[] input)
        {
            byte[] output = new byte[input.Length];
            byte overflow = 0;

            // En partant du bloc de poids faible, décalage de 1
            // Le bit de poids faible est égale à la retenue
            for (int i = 15; i >= 0; i--)
            {
                output[i] = Convert.ToByte((input[i] << 1) % 0x100);
                output[i] |= overflow;
                overflow = ((input[i] & 0x80) == 0x80) ? (byte)1 : (byte)0;
            }

            return output;
        }

        /// <summary>
        /// Incrément d'un tableau d'octet
        /// 11000011 10011001 (0xC399) devient 11000011 10011010 (0xC39A)
        /// </summary>
        /// <param name="input">Tableau d'octet à incrémenter</param>
        /// <returns>Tableau incrémenté </returns>
        private static byte[] Increment(byte[] input)
        {
            byte[] output = new byte[input.Length];
            byte overflow = 0x01;

            // En partant du bloc de poids faible, aouter la retenue (la première vaut 1)
            for (int i = 15; i >= 0; i--)
            {
                int temp = input[i] + overflow;
                output[i] = Convert.ToByte(temp % 0x100);
                overflow = (temp >= 0x100) ? (byte)1 : (byte)0;
            }

            return output;
        }
        #endregion
    }
}

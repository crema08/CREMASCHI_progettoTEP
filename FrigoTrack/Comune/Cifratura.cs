using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Comune
{
    // Cifratura e decifratura dei messaggi con AES-GCM.
    // AES-GCM fa due cose insieme:
    //  - cifra il messaggio (nessuno lo può leggere senza la chiave)
    //  - produce un "tag" di controllo: se qualcuno modifica anche un solo byte,
    //    il tag non torna più e la decifratura fallisce.
    public static class Cifratura
    {
        // Trasforma il segreto condiviso K (numero enorme) in una chiave AES da 32 byte
        public static byte[] CreaChiave(BigInteger K)
        {
            // Trasformo K in byte
            byte[] byteK = K.ToByteArray();
            // L'hash SHA-256 è sempre lungo 32 byte: è la chiave AES a 256 bit
            return SHA256.HashData(byteK);
        }

        // Cifra un testo JSON e restituisce la busta pronta da spedire
        public static Busta Cifra(string json, byte[] chiave, string sessionId)
        {
            // Il testo in chiaro, trasformato in byte
            byte[] testo = Encoding.UTF8.GetBytes(json);

            // Nonce: 12 byte casuali, nuovi per ogni messaggio
            // (cifrando due volte lo stesso testo esce un risultato diverso)
            byte[] nonce = RandomNumberGenerator.GetBytes(12);

            // Qui finisce il testo cifrato (stessa lunghezza del testo in chiaro)
            byte[] cifrato = new byte[testo.Length];
            // Qui finisce il tag di controllo (16 byte)
            byte[] tag = new byte[16];

            // Cifratura vera e propria
            using (AesGcm aes = new AesGcm(chiave, 16))
            {
                aes.Encrypt(nonce, testo, cifrato, tag);
            }

            // Il nonce serve anche a chi decifra: lo metto davanti al testo cifrato
            byte[] nonceEcifrato = new byte[nonce.Length + cifrato.Length];
            nonce.CopyTo(nonceEcifrato, 0);
            cifrato.CopyTo(nonceEcifrato, nonce.Length);

            // Preparo la busta: i byte diventano testo con Base64
            Busta busta = new Busta();
            busta.SessionId = sessionId;
            busta.Ciphertext = Convert.ToBase64String(nonceEcifrato);
            busta.Tag = Convert.ToBase64String(tag);
            return busta;
        }

        // Decifra una busta e restituisce il JSON in chiaro.
        // Se la busta è stata manomessa (o la chiave è sbagliata) lancia un'eccezione.
        public static string Decifra(Busta busta, byte[] chiave)
        {
            // Da Base64 torno ai byte
            byte[] nonceEcifrato = Convert.FromBase64String(busta.Ciphertext);
            byte[] tag = Convert.FromBase64String(busta.Tag);

            // I primi 12 byte sono il nonce
            byte[] nonce = new byte[12];
            Array.Copy(nonceEcifrato, 0, nonce, 0, 12);

            // Il resto è il testo cifrato
            byte[] cifrato = new byte[nonceEcifrato.Length - 12];
            Array.Copy(nonceEcifrato, 12, cifrato, 0, cifrato.Length);

            // Qui finisce il testo decifrato
            byte[] testo = new byte[cifrato.Length];

            // Decifratura: se il tag non corrisponde lancia un'eccezione
            using (AesGcm aes = new AesGcm(chiave, 16))
            {
                aes.Decrypt(nonce, cifrato, tag, testo);
            }

            // Da byte torno al testo JSON
            return Encoding.UTF8.GetString(testo);
        }
    }
}

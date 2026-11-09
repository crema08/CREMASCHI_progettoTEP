using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace Comune
{
    // Funzioni per lo scambio di chiavi Diffie-Hellman.
    // Usiamo solo BigInteger.ModPow (potenza modulare), come chiede la consegna:
    // nessuna libreria fa lo scambio al posto nostro.
    public static class DiffieHellman
    {
        // Numero primo p del gruppo 14 dell'RFC 3526 (2048 bit), scritto in esadecimale.
        // Lo "00" iniziale serve perché C# lo legga come numero positivo.
        private const string PrimoHex =
            "00" +
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

        // p: il numero primo (pubblico)
        public static readonly BigInteger P = BigInteger.Parse(PrimoHex, NumberStyles.HexNumber);

        // g: il generatore del gruppo 14 (pubblico)
        public static readonly BigInteger G = 2;

        // Genera il numero segreto (a per il client, b per il server).
        // Non viene mai spedito in rete.
        public static BigInteger GeneraSegreto()
        {
            // 32 byte casuali = 256 bit, presi dal generatore sicuro (non da Random)
            byte[] byteCasuali = RandomNumberGenerator.GetBytes(32);
            // Trasformo i byte in un numero positivo
            return new BigInteger(byteCasuali, isUnsigned: true);
        }

        // Chiave pubblica: A = g^a mod p (lato client) oppure B = g^b mod p (lato server)
        public static BigInteger ChiavePubblica(BigInteger g, BigInteger segreto, BigInteger p)
        {
            return BigInteger.ModPow(g, segreto, p);
        }

        // Segreto condiviso: K = B^a mod p (lato client) oppure K = A^b mod p (lato server).
        // Viene uguale da tutte e due le parti perché entrambi calcolano g^(a*b) mod p.
        public static BigInteger SegretoCondiviso(BigInteger chiaveAltrui, BigInteger segreto, BigInteger p)
        {
            return BigInteger.ModPow(chiaveAltrui, segreto, p);
        }
    }
}

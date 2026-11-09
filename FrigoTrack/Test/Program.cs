using System.Numerics;
using System.Text;
using System.Text.Json;
using Comune;

namespace Test
{
    // Dati di una sessione aperta con il server
    class Sessione
    {
        public string Id;       // session_id ricevuto dal server
        public byte[] Chiave;   // chiave AES ricavata con Diffie-Hellman
    }

    // Test automatici del server. Il server deve essere già avviato.
    // Ogni test manda una richiesta e controlla che la risposta sia quella giusta.
    internal class Program
    {
        const string IndirizzoServer = "http://localhost:5000";

        static HttpClient http = new HttpClient();

        // Contatori dei risultati
        static int superati = 0;
        static int falliti = 0;

        static async Task Main(string[] args)
        {
            Console.WriteLine("Test FrigoTrack");
            Console.WriteLine("Avvia prima il server, poi premi INVIO...");
            Console.ReadLine();

            // I 5 test richiesti dalla consegna
            await TestHandshakeRiuscito();
            await TestMessaggioValido();
            await TestMessaggioNonValido();
            await TestBustaManomessa();
            await TestSessioneInesistente();

            // Test in più
            await TestEndpointInesistente();
            await TestAllarme();
            await TestLettureEChiusura();

            Console.WriteLine();
            Console.WriteLine("Risultato: " + superati + " superati, " + falliti + " falliti");
            Console.WriteLine("Premi INVIO per chiudere.");
            Console.ReadLine();
        }

        // ---------------------------------------------------------------
        // I TEST
        // ---------------------------------------------------------------

        // 1) Handshake riuscito: il server risponde 200 con session_id e B nel formato giusto
        static async Task TestHandshakeRiuscito()
        {
            Console.WriteLine();
            Console.WriteLine("1) Handshake riuscito");

            // Preparo una richiesta di handshake corretta
            BigInteger a = DiffieHellman.GeneraSegreto();
            RichiestaHandshake richiesta = new RichiestaHandshake();
            richiesta.P = DiffieHellman.P.ToString();
            richiesta.G = DiffieHellman.G.ToString();
            richiesta.A = DiffieHellman.ChiavePubblica(DiffieHellman.G, a, DiffieHellman.P).ToString();

            HttpResponseMessage risposta = await Post("/api/handshake", JsonSerializer.Serialize(richiesta));
            string testo = await risposta.Content.ReadAsStringAsync();

            Controlla("il server risponde 200", (int)risposta.StatusCode == 200);
            Controlla("la risposta rispetta lo schema", Validatore.Valida(testo, "handshake_risposta.schema.json") == null);
        }

        // 2) Messaggio valido: una misura corretta viene accettata
        static async Task TestMessaggioValido()
        {
            Console.WriteLine();
            Console.WriteLine("2) Messaggio valido");

            Sessione sessione = await Handshake();
            Misura misura = MisuraCorretta();

            // Cifro la misura e la mando
            Busta busta = Cifratura.Cifra(JsonSerializer.Serialize(misura), sessione.Chiave, sessione.Id);
            HttpResponseMessage risposta = await Post("/api/telemetry", JsonSerializer.Serialize(busta));

            // Decifro la risposta
            string json = await DecifraRisposta(risposta, sessione);

            Controlla("il server risponde 200", (int)risposta.StatusCode == 200);
            Controlla("la conferma rispetta lo schema", Validatore.Valida(json, "conferma.schema.json") == null);
        }

        // 3) Messaggio non valido: il server risponde 400 e dice qual è il campo sbagliato
        static async Task TestMessaggioNonValido()
        {
            Console.WriteLine();
            Console.WriteLine("3) Messaggio non valido (temperatura 99)");

            Sessione sessione = await Handshake();
            Misura misura = MisuraCorretta();
            misura.TemperatureC = 99;   // lo schema permette al massimo 40

            Busta busta = Cifratura.Cifra(JsonSerializer.Serialize(misura), sessione.Chiave, sessione.Id);
            HttpResponseMessage risposta = await Post("/api/telemetry", JsonSerializer.Serialize(busta));
            string json = await DecifraRisposta(risposta, sessione);
            Errore errore = JsonSerializer.Deserialize<Errore>(json);

            Controlla("il server risponde 400", (int)risposta.StatusCode == 400);
            Controlla("l'errore indica il campo temperature_c", errore.Field == "temperature_c");
        }

        // 4) Busta manomessa: cambio un byte del testo cifrato, il tag non torna più
        static async Task TestBustaManomessa()
        {
            Console.WriteLine();
            Console.WriteLine("4) Busta manomessa");

            Sessione sessione = await Handshake();
            Busta busta = Cifratura.Cifra(JsonSerializer.Serialize(MisuraCorretta()), sessione.Chiave, sessione.Id);

            // Simulo un attaccante: modifico l'ultimo byte del testo cifrato
            byte[] byteCifrati = Convert.FromBase64String(busta.Ciphertext);
            byteCifrati[byteCifrati.Length - 1] = (byte)(byteCifrati[byteCifrati.Length - 1] + 1);
            busta.Ciphertext = Convert.ToBase64String(byteCifrati);

            HttpResponseMessage risposta = await Post("/api/telemetry", JsonSerializer.Serialize(busta));

            Controlla("il server risponde 400", (int)risposta.StatusCode == 400);
        }

        // 5) Sessione inesistente: session_id che il server non conosce
        static async Task TestSessioneInesistente()
        {
            Console.WriteLine();
            Console.WriteLine("5) Sessione inesistente");

            // Chiave inventata e session_id mai creato dal server
            byte[] chiaveFinta = new byte[32];
            Busta busta = Cifratura.Cifra(JsonSerializer.Serialize(MisuraCorretta()), chiaveFinta, "00000000");

            HttpResponseMessage risposta = await Post("/api/telemetry", JsonSerializer.Serialize(busta));

            Controlla("il server risponde 401", (int)risposta.StatusCode == 401);
        }

        // 6) Endpoint inesistente: il server risponde 404
        static async Task TestEndpointInesistente()
        {
            Console.WriteLine();
            Console.WriteLine("6) Endpoint inesistente");

            HttpResponseMessage risposta = await Post("/api/pippo", "{}");

            Controlla("il server risponde 404", (int)risposta.StatusCode == 404);
        }

        // 7) Allarme: farmaci a 12 gradi (consentito da 2 a 8)
        static async Task TestAllarme()
        {
            Console.WriteLine();
            Console.WriteLine("7) Allarme temperatura");

            Sessione sessione = await Handshake();
            Misura misura = MisuraCorretta();
            misura.TemperatureC = 12;

            Busta busta = Cifratura.Cifra(JsonSerializer.Serialize(misura), sessione.Chiave, sessione.Id);
            HttpResponseMessage risposta = await Post("/api/telemetry", JsonSerializer.Serialize(busta));
            string json = await DecifraRisposta(risposta, sessione);
            Conferma conferma = JsonSerializer.Deserialize<Conferma>(json);

            Controlla("il server risponde 200", (int)risposta.StatusCode == 200);
            Controlla("la conferma contiene l'allarme", conferma.Alarm);
        }

        // 8) Letture e chiusura: le misure si possono leggere, dopo la chiusura la sessione non vale più
        static async Task TestLettureEChiusura()
        {
            Console.WriteLine();
            Console.WriteLine("8) Letture e chiusura sessione");

            Sessione sessione = await Handshake();

            // Mando una misura
            Misura misura = MisuraCorretta();
            Busta busta = Cifratura.Cifra(JsonSerializer.Serialize(misura), sessione.Chiave, sessione.Id);
            await Post("/api/telemetry", JsonSerializer.Serialize(busta));

            // Chiedo le misure dell'ultima ora
            RichiestaLetture richiesta = new RichiestaLetture();
            richiesta.SensorId = misura.SensorId;
            richiesta.From = DateTime.UtcNow.AddHours(-1).ToString("s") + "Z";
            richiesta.To = DateTime.UtcNow.AddMinutes(1).ToString("s") + "Z";
            busta = Cifratura.Cifra(JsonSerializer.Serialize(richiesta), sessione.Chiave, sessione.Id);
            HttpResponseMessage risposta = await Post("/api/readings", JsonSerializer.Serialize(busta));
            string json = await DecifraRisposta(risposta, sessione);
            RispostaLetture letture = JsonSerializer.Deserialize<RispostaLetture>(json);

            Controlla("readings risponde 200", (int)risposta.StatusCode == 200);
            Controlla("l'elenco rispetta lo schema", Validatore.Valida(json, "letture_risposta.schema.json") == null);
            Controlla("c'e' almeno una misura", letture.Count >= 1);

            // Chiudo la sessione
            RichiestaChiusura chiusura = new RichiestaChiusura();
            chiusura.Action = "close";
            busta = Cifratura.Cifra(JsonSerializer.Serialize(chiusura), sessione.Chiave, sessione.Id);
            risposta = await Post("/api/close", JsonSerializer.Serialize(busta));
            Controlla("close risponde 200", (int)risposta.StatusCode == 200);

            // Dopo la chiusura la stessa sessione deve essere rifiutata
            busta = Cifratura.Cifra(JsonSerializer.Serialize(misura), sessione.Chiave, sessione.Id);
            risposta = await Post("/api/telemetry", JsonSerializer.Serialize(busta));
            Controlla("dopo la chiusura il server risponde 401", (int)risposta.StatusCode == 401);
        }

        // ---------------------------------------------------------------
        // FUNZIONI DI AIUTO
        // ---------------------------------------------------------------

        // Stampa il risultato di un controllo e aggiorna i contatori
        static void Controlla(string descrizione, bool riuscito)
        {
            if (riuscito)
            {
                Console.WriteLine("   OK      " + descrizione);
                superati++;
            }
            else
            {
                Console.WriteLine("   FALLITO " + descrizione);
                falliti++;
            }
        }

        // Manda una POST con un corpo JSON
        static async Task<HttpResponseMessage> Post(string endpoint, string json)
        {
            StringContent contenuto = new StringContent(json, Encoding.UTF8, "application/json");
            return await http.PostAsync(IndirizzoServer + endpoint, contenuto);
        }

        // Fa l'handshake e restituisce la sessione (uguale a quello del client)
        static async Task<Sessione> Handshake()
        {
            BigInteger p = DiffieHellman.P;
            BigInteger g = DiffieHellman.G;
            BigInteger a = DiffieHellman.GeneraSegreto();
            BigInteger A = DiffieHellman.ChiavePubblica(g, a, p);

            RichiestaHandshake richiesta = new RichiestaHandshake();
            richiesta.P = p.ToString();
            richiesta.G = g.ToString();
            richiesta.A = A.ToString();

            HttpResponseMessage risposta = await Post("/api/handshake", JsonSerializer.Serialize(richiesta));
            string testo = await risposta.Content.ReadAsStringAsync();
            RispostaHandshake rh = JsonSerializer.Deserialize<RispostaHandshake>(testo);

            BigInteger K = DiffieHellman.SegretoCondiviso(BigInteger.Parse(rh.B), a, p);

            Sessione sessione = new Sessione();
            sessione.Id = rh.SessionId;
            sessione.Chiave = Cifratura.CreaChiave(K);
            return sessione;
        }

        // Legge la risposta del server: se è una busta la decifra
        static async Task<string> DecifraRisposta(HttpResponseMessage risposta, Sessione sessione)
        {
            string testo = await risposta.Content.ReadAsStringAsync();
            if (testo.Contains("\"ciphertext\""))
            {
                Busta busta = JsonSerializer.Deserialize<Busta>(testo);
                return Cifratura.Decifra(busta, sessione.Chiave);
            }
            return testo;
        }

        // Una misura corretta da usare nei test
        static Misura MisuraCorretta()
        {
            Misura m = new Misura();
            m.SensorId = "TEST-BG-001";
            m.Timestamp = DateTime.UtcNow.ToString("s") + "Z";
            m.CargoType = "pharma";
            m.TemperatureC = 4.6;
            m.Humidity = 55;
            m.Battery = 87;
            return m;
        }
    }
}

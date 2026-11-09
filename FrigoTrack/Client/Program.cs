using System.Numerics;
using System.Text;
using System.Text.Json;
using Comune;

namespace Client
{
    // Dati di una sessione aperta con il server
    class Sessione
    {
        public string Id;       // session_id ricevuto dal server
        public byte[] Chiave;   // chiave AES ricavata con Diffie-Hellman
    }

    internal class Program
    {
        // Indirizzo del server
        const string IndirizzoServer = "http://localhost:5000";

        // Quante misure manda ogni sensore e ogni quanto (in millisecondi)
        const int NumeroMisure = 5;
        const int Intervallo = 2000;

        // Oggetto che fa le richieste HTTP (uno solo per tutto il programma)
        static HttpClient http = new HttpClient();

        static async Task Main(string[] args)
        {
            Console.WriteLine("Client FrigoTrack - simulatore sensori");
            Console.WriteLine("Avvia prima il server, poi premi INVIO...");
            Console.ReadLine();

            // 1) Avvio i 3 sensori insieme: ognuno ha la sua sessione e la sua chiave
            Task sensore1 = SimulaSensore("CELLA-BG-007", "pharma");
            Task sensore2 = SimulaSensore("CAMION-MI-012", "food");
            Task sensore3 = SimulaSensore("CELLA-BS-003", "frozen");

            // Aspetto che tutti e tre abbiano finito
            await Task.WhenAll(sensore1, sensore2, sensore3);

            // 2) Dimostrazione con una misura NON valida
            await ProvaMisuraNonValida();

            Console.WriteLine();
            Console.WriteLine("Fine. Premi INVIO per chiudere.");
            Console.ReadLine();
        }

        // Tutto il lavoro di un sensore: handshake, misure, lettura, chiusura
        static async Task SimulaSensore(string sensorId, string tipoMerce)
        {
            // Prima di mandare qualsiasi dato faccio l'handshake per avere la chiave
            Sessione sessione = await Handshake(sensorId);
            if (sessione == null)
            {
                return;
            }

            // Mando le misure a intervalli regolari
            for (int i = 1; i <= NumeroMisure; i++)
            {
                // Creo una misura e la trasformo in JSON
                Misura misura = CreaMisura(sensorId, tipoMerce);
                string json = JsonSerializer.Serialize(misura);

                // Valido la misura con lo schema PRIMA di cifrarla
                Errore errore = Validatore.Valida(json, "misura.schema.json");
                if (errore != null)
                {
                    Console.WriteLine("[" + sensorId + "] misura non valida, campo " + errore.Field);
                    continue;
                }

                // Cifro, invio e decifro la risposta
                string risposta = await InviaCifrato(sessione, "/api/telemetry", json);
                if (risposta != null)
                {
                    Conferma conferma = JsonSerializer.Deserialize<Conferma>(risposta);
                    if (conferma.Alarm)
                    {
                        Console.WriteLine("[" + sensorId + "] " + conferma.Message);
                    }
                    else
                    {
                        Console.WriteLine("[" + sensorId + "] inviata " + misura.TemperatureC + " gradi -> " + conferma.Message);
                    }
                }

                // Aspetto prima della misura successiva
                await Task.Delay(Intervallo);
            }

            // Chiedo al server le misure salvate nell'ultima ora
            await LeggiMisure(sessione, sensorId);

            // Chiudo la sessione: il server cancella la chiave
            await ChiudiSessione(sessione, sensorId);
        }

        // Handshake Diffie-Hellman: restituisce la sessione (id + chiave), oppure null se fallisce
        static async Task<Sessione> Handshake(string sensorId)
        {
            // 1) Scelgo p, g e il mio segreto a, poi calcolo A = g^a mod p
            BigInteger p = DiffieHellman.P;
            BigInteger g = DiffieHellman.G;
            BigInteger a = DiffieHellman.GeneraSegreto();
            BigInteger A = DiffieHellman.ChiavePubblica(g, a, p);

            // 2) Mando p, g e A al server (in chiaro: sono dati pubblici)
            RichiestaHandshake richiesta = new RichiestaHandshake();
            richiesta.P = p.ToString();
            richiesta.G = g.ToString();
            richiesta.A = A.ToString();

            string json = JsonSerializer.Serialize(richiesta);
            StringContent contenuto = new StringContent(json, Encoding.UTF8, "application/json");
            HttpResponseMessage risposta = await http.PostAsync(IndirizzoServer + "/api/handshake", contenuto);

            if (!risposta.IsSuccessStatusCode)
            {
                Console.WriteLine("[" + sensorId + "] handshake fallito: " + (int)risposta.StatusCode);
                return null;
            }

            // 3) Ricevo session_id e B
            string testo = await risposta.Content.ReadAsStringAsync();
            RispostaHandshake rh = JsonSerializer.Deserialize<RispostaHandshake>(testo);
            BigInteger B = BigInteger.Parse(rh.B);

            // 4) Calcolo il segreto condiviso K = B^a mod p e ne ricavo la chiave AES
            BigInteger K = DiffieHellman.SegretoCondiviso(B, a, p);

            Sessione sessione = new Sessione();
            sessione.Id = rh.SessionId;
            sessione.Chiave = Cifratura.CreaChiave(K);

            Console.WriteLine("[" + sensorId + "] handshake ok, session_id " + sessione.Id);
            return sessione;
        }

        // Cifra un JSON, lo manda all'endpoint e restituisce la risposta decifrata.
        // Se il server risponde con un errore lo stampa e restituisce null.
        static async Task<string> InviaCifrato(Sessione sessione, string endpoint, string json)
        {
            // Metto il messaggio cifrato nella busta
            Busta busta = Cifratura.Cifra(json, sessione.Chiave, sessione.Id);
            string jsonBusta = JsonSerializer.Serialize(busta);

            // Mando la busta al server
            StringContent contenuto = new StringContent(jsonBusta, Encoding.UTF8, "application/json");
            HttpResponseMessage risposta = await http.PostAsync(IndirizzoServer + endpoint, contenuto);
            string testo = await risposta.Content.ReadAsStringAsync();

            // Se la risposta è una busta la decifro, altrimenti è un errore in chiaro
            string jsonRisposta;
            if (testo.Contains("\"ciphertext\""))
            {
                Busta bustaRisposta = JsonSerializer.Deserialize<Busta>(testo);
                jsonRisposta = Cifratura.Decifra(bustaRisposta, sessione.Chiave);
            }
            else
            {
                jsonRisposta = testo;
            }

            // Codice diverso da 200: stampo l'errore
            if (!risposta.IsSuccessStatusCode)
            {
                Console.WriteLine("  il server risponde " + (int)risposta.StatusCode + ": " + jsonRisposta);
                return null;
            }

            return jsonRisposta;
        }

        // Chiede al server le misure del sensore nell'ultima ora (POST /api/readings)
        static async Task LeggiMisure(Sessione sessione, string sensorId)
        {
            // Intervallo: da un'ora fa fino ad adesso, in formato ISO (es. 2026-11-02T08:15:30Z)
            RichiestaLetture richiesta = new RichiestaLetture();
            richiesta.SensorId = sensorId;
            richiesta.From = DateTime.UtcNow.AddHours(-1).ToString("s") + "Z";
            richiesta.To = DateTime.UtcNow.ToString("s") + "Z";

            // Valido prima di cifrare
            string json = JsonSerializer.Serialize(richiesta);
            Errore errore = Validatore.Valida(json, "letture_richiesta.schema.json");
            if (errore != null)
            {
                Console.WriteLine("[" + sensorId + "] richiesta non valida, campo " + errore.Field);
                return;
            }

            string risposta = await InviaCifrato(sessione, "/api/readings", json);
            if (risposta != null)
            {
                RispostaLetture letture = JsonSerializer.Deserialize<RispostaLetture>(risposta);
                Console.WriteLine("[" + sensorId + "] il server ha " + letture.Count + " misure dell'ultima ora");
            }
        }

        // Chiude la sessione (POST /api/close)
        static async Task ChiudiSessione(Sessione sessione, string sensorId)
        {
            RichiestaChiusura richiesta = new RichiestaChiusura();
            richiesta.Action = "close";

            // Valido prima di cifrare
            string json = JsonSerializer.Serialize(richiesta);
            Errore errore = Validatore.Valida(json, "chiusura_richiesta.schema.json");
            if (errore != null)
            {
                Console.WriteLine("[" + sensorId + "] richiesta non valida, campo " + errore.Field);
                return;
            }

            string risposta = await InviaCifrato(sessione, "/api/close", json);
            if (risposta != null)
            {
                Console.WriteLine("[" + sensorId + "] sessione chiusa");
            }
        }

        // Dimostrazione: una misura con temperatura 99 (lo schema permette massimo 40)
        static async Task ProvaMisuraNonValida()
        {
            Console.WriteLine();
            Console.WriteLine("--- Prova con una misura NON valida (temperatura 99) ---");

            string sensorId = "CELLA-BG-999";
            Sessione sessione = await Handshake(sensorId);
            if (sessione == null)
            {
                return;
            }

            // Creo una misura e ci metto una temperatura impossibile
            Misura misura = CreaMisura(sensorId, "pharma");
            misura.TemperatureC = 99;
            string json = JsonSerializer.Serialize(misura);

            // 1) Il client se ne accorge da solo grazie allo schema
            Errore errore = Validatore.Valida(json, "misura.schema.json");
            Console.WriteLine("Il client blocca la misura: " + errore.Error + ", campo " + errore.Field);

            // 2) La mando lo stesso, solo per vedere che anche il server la rifiuta
            Console.WriteLine("La mando lo stesso per vedere cosa risponde il server:");
            await InviaCifrato(sessione, "/api/telemetry", json);

            await ChiudiSessione(sessione, sensorId);
        }

        // Crea una misura con valori casuali in base al tipo di merce.
        // A volte la temperatura esce di poco dall'intervallo, così si vede l'allarme.
        static Misura CreaMisura(string sensorId, string tipoMerce)
        {
            // Random.Shared si può usare da più sensori insieme senza problemi
            double temperatura;
            if (tipoMerce == "pharma")
            {
                temperatura = 1.5 + Random.Shared.NextDouble() * 7;   // da 1.5 a 8.5 gradi
            }
            else if (tipoMerce == "food")
            {
                temperatura = -0.5 + Random.Shared.NextDouble() * 5;  // da -0.5 a 4.5 gradi
            }
            else
            {
                temperatura = -25 + Random.Shared.NextDouble() * 8;   // da -25 a -17 gradi
            }

            Misura m = new Misura();
            m.SensorId = sensorId;
            // Data e ora UTC in formato ISO, es. 2026-11-02T08:15:30Z
            m.Timestamp = DateTime.UtcNow.ToString("s") + "Z";
            m.CargoType = tipoMerce;
            m.TemperatureC = Math.Round(temperatura, 1);     // una cifra dopo la virgola
            m.Humidity = Random.Shared.Next(30, 80);         // umidità tra 30 e 79
            m.Battery = Random.Shared.Next(20, 101);         // batteria tra 20 e 100
            return m;
        }
    }
}

using System.Collections.Concurrent;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Comune;

namespace Server
{
    internal class Program
    {
        // Sessioni attive: session_id -> chiave AES di quella sessione.
        // ConcurrentDictionary si può usare da più thread insieme senza problemi.
        static ConcurrentDictionary<string, byte[]> sessioni = new ConcurrentDictionary<string, byte[]>();

        // Cartella dove salvo le misure: un file JSON per ogni sensore
        static string cartellaDati = Path.Combine(AppContext.BaseDirectory, "dati");

        // "Lucchetto": impedisce a due richieste di scrivere i file nello stesso momento
        static object lucchettoFile = new object();

        // Opzioni per scrivere i file JSON su più righe (più facili da leggere)
        static JsonSerializerOptions jsonLeggibile = new JsonSerializerOptions { WriteIndented = true };

        static void Main(string[] args)
        {
            // Creo la cartella dei dati (se esiste già non fa niente)
            Directory.CreateDirectory(cartellaDati);

            // HttpListener è un piccolo server HTTP già incluso in .NET
            HttpListener listener = new HttpListener();
            listener.Prefixes.Add("http://localhost:5000/");
            listener.Start();

            Console.WriteLine("Server FrigoTrack avviato su http://localhost:5000/");
            Console.WriteLine("Misure salvate in: " + cartellaDati);

            // Ciclo infinito: aspetto una richiesta alla volta...
            while (true)
            {
                HttpListenerContext context = listener.GetContext();
                // ...e la gestisco in un thread separato,
                // così intanto posso già ricevere le richieste degli altri client
                Task.Run(() => GestisciRichiesta(context));
            }
        }

        // Smista la richiesta all'endpoint giusto
        static void GestisciRichiesta(HttpListenerContext context)
        {
            try
            {
                string metodo = context.Request.HttpMethod;
                string percorso = context.Request.Url.AbsolutePath;
                Console.WriteLine(metodo + " " + percorso);

                // Tutti gli endpoint accettano solo POST
                if (metodo != "POST")
                {
                    RispondiInChiaro(context, 404, new Errore("endpoint non trovato", null));
                    return;
                }

                // L'handshake è l'unico messaggio in chiaro
                if (percorso == "/api/handshake")
                {
                    Handshake(context);
                    return;
                }

                // Gli altri endpoint ricevono una busta cifrata
                if (percorso == "/api/telemetry" || percorso == "/api/readings" || percorso == "/api/close")
                {
                    RiceviBusta(context, percorso);
                    return;
                }

                // Qualsiasi altro indirizzo non esiste
                RispondiInChiaro(context, 404, new Errore("endpoint non trovato", null));
            }
            catch (Exception ex)
            {
                // Un errore imprevisto non deve fermare il server
                Console.WriteLine("  errore: " + ex.Message);
                try
                {
                    RispondiInChiaro(context, 400, new Errore("richiesta non valida", null));
                }
                catch
                {
                    // La risposta era già stata chiusa: non posso fare altro
                }
            }
        }

        // ---------------------------------------------------------------
        // POST /api/handshake: scambio di chiavi Diffie-Hellman
        // ---------------------------------------------------------------
        static void Handshake(HttpListenerContext context)
        {
            string corpo = LeggiCorpo(context);

            // Controllo il formato della richiesta con il suo schema
            Errore errore = Validatore.Valida(corpo, "handshake_richiesta.schema.json");
            if (errore != null)
            {
                RispondiInChiaro(context, 400, errore);
                return;
            }

            RichiestaHandshake richiesta = JsonSerializer.Deserialize<RichiestaHandshake>(corpo);

            // Numeri ricevuti dal client: da testo a BigInteger
            BigInteger p = BigInteger.Parse(richiesta.P);
            BigInteger g = BigInteger.Parse(richiesta.G);
            BigInteger A = BigInteger.Parse(richiesta.A);

            // Controllo di sicurezza: A deve stare tra 2 e p-2.
            // Con A = 1 o A = p-1 il segreto K sarebbe facile da indovinare.
            if (A <= 1 || A >= p - 1)
            {
                RispondiInChiaro(context, 400, new Errore("chiave pubblica non valida", "A"));
                return;
            }

            // Il server sceglie il suo segreto b (non lo manda a nessuno)
            BigInteger b = DiffieHellman.GeneraSegreto();
            // Chiave pubblica del server: B = g^b mod p
            BigInteger B = DiffieHellman.ChiavePubblica(g, b, p);
            // Segreto condiviso: K = A^b mod p (uguale a quello che calcola il client)
            BigInteger K = DiffieHellman.SegretoCondiviso(A, b, p);
            // Dal segreto K ricavo la chiave AES da 32 byte
            byte[] chiave = Cifratura.CreaChiave(K);

            // session_id casuale: 4 byte = 8 caratteri esadecimali (es. "a3f9c2e1")
            string sessionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLower();

            // Salvo la chiave della nuova sessione
            sessioni[sessionId] = chiave;
            Console.WriteLine("  nuova sessione " + sessionId);

            // Rispondo con session_id e B (in chiaro: B è pubblica)
            RispostaHandshake risposta = new RispostaHandshake();
            risposta.SessionId = sessionId;
            risposta.B = B.ToString();
            RispondiInChiaro(context, 200, risposta);
        }

        // ---------------------------------------------------------------
        // Parte comune a /api/telemetry, /api/readings e /api/close:
        // apre la busta e poi passa il contenuto all'endpoint giusto.
        // REGOLA: prima decifro, poi valido. Se la decifratura fallisce rispondo 400 e basta.
        // ---------------------------------------------------------------
        static void RiceviBusta(HttpListenerContext context, string percorso)
        {
            string corpo = LeggiCorpo(context);

            // 1) La busta deve avere il formato giusto (session_id, ciphertext, tag)
            Errore errore = Validatore.Valida(corpo, "busta.schema.json");
            if (errore != null)
            {
                RispondiInChiaro(context, 400, errore);
                return;
            }
            Busta busta = JsonSerializer.Deserialize<Busta>(corpo);

            // 2) Cerco la chiave della sessione: se non c'è rispondo 401
            byte[] chiave;
            if (!sessioni.TryGetValue(busta.SessionId, out chiave))
            {
                RispondiInChiaro(context, 401, new Errore("sessione inesistente", "session_id"));
                return;
            }

            // 3) Decifro: se il tag non torna, la busta è stata manomessa
            string json;
            try
            {
                json = Cifratura.Decifra(busta, chiave);
            }
            catch (Exception)
            {
                Console.WriteLine("  decifratura fallita: busta manomessa o chiave sbagliata");
                RispondiInChiaro(context, 400, new Errore("decifratura fallita", "tag"));
                return;
            }
            Console.WriteLine("  decifrato: " + json);

            // 4) Solo ora passo il messaggio all'endpoint, che lo validerà con il suo schema
            if (percorso == "/api/telemetry")
            {
                Telemetria(context, busta.SessionId, chiave, json);
            }
            else if (percorso == "/api/readings")
            {
                Letture(context, busta.SessionId, chiave, json);
            }
            else
            {
                Chiusura(context, busta.SessionId, chiave, json);
            }
        }

        // ---------------------------------------------------------------
        // POST /api/telemetry: riceve una misura, la salva e risponde con una conferma
        // ---------------------------------------------------------------
        static void Telemetria(HttpListenerContext context, string sessionId, byte[] chiave, string json)
        {
            // Valido la misura: se è sbagliata rispondo 400 (cifrato) dicendo il campo
            Errore errore = Validatore.Valida(json, "misura.schema.json");
            if (errore != null)
            {
                Console.WriteLine("  misura non valida, campo: " + errore.Field);
                RispondiCifrato(context, 400, errore, sessionId, chiave);
                return;
            }

            Misura misura = JsonSerializer.Deserialize<Misura>(json);

            // Salvo la misura nel file del sensore
            SalvaMisura(misura);

            // Intervallo di sicurezza in base al tipo di merce
            double minimo;
            double massimo;
            if (misura.CargoType == "pharma")
            {
                minimo = 2;      // farmaci: tra 2 e 8 gradi
                massimo = 8;
            }
            else if (misura.CargoType == "food")
            {
                minimo = 0;      // alimenti freschi: tra 0 e 4 gradi
                massimo = 4;
            }
            else
            {
                minimo = -30;    // surgelati: tra -30 e -18 gradi
                massimo = -18;
            }

            // Preparo la conferma
            Conferma conferma = new Conferma();
            conferma.Status = "ok";
            conferma.SensorId = misura.SensorId;

            // Se la temperatura è fuori intervallo, aggiungo l'allarme
            if (misura.TemperatureC < minimo || misura.TemperatureC > massimo)
            {
                conferma.Alarm = true;
                conferma.Message = "ALLARME temperatura " + misura.TemperatureC + " fuori intervallo (" + minimo + " / " + massimo + ")";
                Console.WriteLine("  !!! " + misura.SensorId + ": " + conferma.Message);
            }
            else
            {
                conferma.Alarm = false;
                conferma.Message = "misura registrata";
            }

            RispondiCifrato(context, 200, conferma, sessionId, chiave);
        }

        // ---------------------------------------------------------------
        // POST /api/readings: restituisce le misure di un sensore in un intervallo di tempo
        // ---------------------------------------------------------------
        static void Letture(HttpListenerContext context, string sessionId, byte[] chiave, string json)
        {
            // Valido la richiesta
            Errore errore = Validatore.Valida(json, "letture_richiesta.schema.json");
            if (errore != null)
            {
                RispondiCifrato(context, 400, errore, sessionId, chiave);
                return;
            }

            RichiestaLetture richiesta = JsonSerializer.Deserialize<RichiestaLetture>(json);

            // Inizio e fine dell'intervallo richiesto
            DateTime da = DateTime.Parse(richiesta.From);
            DateTime a = DateTime.Parse(richiesta.To);

            // Leggo tutte le misure salvate di quel sensore
            List<Misura> tutte;
            lock (lucchettoFile)
            {
                tutte = LeggiMisure(richiesta.SensorId);
            }

            // Tengo solo quelle dentro l'intervallo
            List<Misura> trovate = new List<Misura>();
            foreach (Misura m in tutte)
            {
                DateTime quando = DateTime.Parse(m.Timestamp);
                if (quando >= da && quando <= a)
                {
                    trovate.Add(m);
                }
            }

            // Rispondo con l'elenco
            RispostaLetture risposta = new RispostaLetture();
            risposta.SensorId = richiesta.SensorId;
            risposta.Count = trovate.Count;
            risposta.Readings = trovate;
            RispondiCifrato(context, 200, risposta, sessionId, chiave);
        }

        // ---------------------------------------------------------------
        // POST /api/close: chiude la sessione e cancella la chiave
        // ---------------------------------------------------------------
        static void Chiusura(HttpListenerContext context, string sessionId, byte[] chiave, string json)
        {
            // Valido la richiesta
            Errore errore = Validatore.Valida(json, "chiusura_richiesta.schema.json");
            if (errore != null)
            {
                RispondiCifrato(context, 400, errore, sessionId, chiave);
                return;
            }

            // Cancello la chiave: da adesso questa sessione non esiste più
            byte[] chiaveCancellata;
            sessioni.TryRemove(sessionId, out chiaveCancellata);
            Console.WriteLine("  sessione " + sessionId + " chiusa");

            // Rispondo cifrando con la chiave che ho ancora in memoria
            RispostaChiusura risposta = new RispostaChiusura();
            risposta.Status = "closed";
            risposta.SessionId = sessionId;
            RispondiCifrato(context, 200, risposta, sessionId, chiave);
        }

        // ---------------------------------------------------------------
        // Salvataggio delle misure su file JSON
        // ---------------------------------------------------------------

        // Aggiunge una misura al file del suo sensore (es. dati/CELLA-BG-007.json)
        static void SalvaMisura(Misura misura)
        {
            // Il nome del file è sicuro perché lo schema ha già controllato sensor_id
            // (solo lettere maiuscole, trattini e numeri: niente "..\" o percorsi strani)
            string file = Path.Combine(cartellaDati, misura.SensorId + ".json");

            // Una richiesta alla volta: leggo, aggiungo e riscrivo il file
            lock (lucchettoFile)
            {
                List<Misura> lista = LeggiMisure(misura.SensorId);
                lista.Add(misura);
                File.WriteAllText(file, JsonSerializer.Serialize(lista, jsonLeggibile));
            }
        }

        // Legge tutte le misure di un sensore (lista vuota se il file non c'è ancora)
        static List<Misura> LeggiMisure(string sensorId)
        {
            string file = Path.Combine(cartellaDati, sensorId + ".json");
            if (!File.Exists(file))
            {
                return new List<Misura>();
            }
            string json = File.ReadAllText(file);
            return JsonSerializer.Deserialize<List<Misura>>(json);
        }

        // ---------------------------------------------------------------
        // Funzioni di aiuto per leggere e rispondere
        // ---------------------------------------------------------------

        // Legge il corpo della richiesta come testo
        static string LeggiCorpo(HttpListenerContext context)
        {
            using (StreamReader reader = new StreamReader(context.Request.InputStream))
            {
                return reader.ReadToEnd();
            }
        }

        // Risponde in chiaro: solo per l'handshake e per gli errori
        // che succedono prima di poter decifrare (busta rotta, sessione inesistente, tag sbagliato)
        static void RispondiInChiaro(HttpListenerContext context, int codice, object messaggio)
        {
            string json = JsonSerializer.Serialize(messaggio);
            Console.WriteLine("  -> " + codice);
            Invia(context, codice, json);
        }

        // Risponde con una busta cifrata con la chiave della sessione
        static void RispondiCifrato(HttpListenerContext context, int codice, object messaggio, string sessionId, byte[] chiave)
        {
            // Oggetto -> JSON
            string json = JsonSerializer.Serialize(messaggio);
            // JSON -> busta cifrata
            Busta busta = Cifratura.Cifra(json, chiave, sessionId);
            Console.WriteLine("  -> " + codice + " (cifrato)");
            Invia(context, codice, JsonSerializer.Serialize(busta));
        }

        // Spedisce davvero la risposta HTTP con il codice indicato
        static void Invia(HttpListenerContext context, int codice, string json)
        {
            byte[] dati = Encoding.UTF8.GetBytes(json);
            context.Response.StatusCode = codice;
            context.Response.ContentType = "application/json";
            context.Response.OutputStream.Write(dati, 0, dati.Length);
            context.Response.Close();
        }
    }
}

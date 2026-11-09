using System.Text.Json.Serialization;

namespace Comune
{
    // Classi dei messaggi scambiati tra client e server.
    // [JsonPropertyName] dice come si chiama il campo nel JSON
    // (in C# scriviamo SensorId, nel JSON diventa sensor_id).
    // Per ogni classe c'è il suo schema nella cartella schemas.

    // POST /api/handshake - richiesta del client (in chiaro) - handshake_richiesta.schema.json
    // I numeri sono enormi, quindi li mandiamo come stringhe di cifre.
    public class RichiestaHandshake
    {
        [JsonPropertyName("p")]
        public string P { get; set; }

        [JsonPropertyName("g")]
        public string G { get; set; }

        [JsonPropertyName("A")]
        public string A { get; set; }
    }

    // POST /api/handshake - risposta del server (in chiaro) - handshake_risposta.schema.json
    public class RispostaHandshake
    {
        [JsonPropertyName("session_id")]
        public string SessionId { get; set; }

        [JsonPropertyName("B")]
        public string B { get; set; }
    }

    // Busta cifrata: è l'unica cosa che viaggia in rete dopo l'handshake - busta.schema.json
    public class Busta
    {
        // Unico dato in chiaro: serve al server per trovare la chiave giusta
        [JsonPropertyName("session_id")]
        public string SessionId { get; set; }

        // Nonce + messaggio cifrato, in Base64
        [JsonPropertyName("ciphertext")]
        public string Ciphertext { get; set; }

        // Tag di controllo di AES-GCM, in Base64
        [JsonPropertyName("tag")]
        public string Tag { get; set; }
    }

    // Misura del sensore (dentro la busta di /api/telemetry) - misura.schema.json
    public class Misura
    {
        [JsonPropertyName("sensor_id")]
        public string SensorId { get; set; }

        [JsonPropertyName("timestamp")]
        public string Timestamp { get; set; }

        [JsonPropertyName("cargo_type")]
        public string CargoType { get; set; }

        [JsonPropertyName("temperature_c")]
        public double TemperatureC { get; set; }

        [JsonPropertyName("humidity")]
        public double Humidity { get; set; }

        [JsonPropertyName("battery")]
        public int Battery { get; set; }
    }

    // Conferma (ack) che il server manda dopo ogni misura - conferma.schema.json
    public class Conferma
    {
        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("sensor_id")]
        public string SensorId { get; set; }

        // true se la temperatura è fuori dall'intervallo di sicurezza
        [JsonPropertyName("alarm")]
        public bool Alarm { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }
    }

    // Richiesta delle misure salvate (dentro la busta di /api/readings) - letture_richiesta.schema.json
    public class RichiestaLetture
    {
        [JsonPropertyName("sensor_id")]
        public string SensorId { get; set; }

        // Inizio dell'intervallo di tempo
        [JsonPropertyName("from")]
        public string From { get; set; }

        // Fine dell'intervallo di tempo
        [JsonPropertyName("to")]
        public string To { get; set; }
    }

    // Risposta con l'elenco delle misure - letture_risposta.schema.json
    public class RispostaLetture
    {
        [JsonPropertyName("sensor_id")]
        public string SensorId { get; set; }

        [JsonPropertyName("count")]
        public int Count { get; set; }

        [JsonPropertyName("readings")]
        public List<Misura> Readings { get; set; }
    }

    // Richiesta di chiusura (dentro la busta di /api/close) - chiusura_richiesta.schema.json
    public class RichiestaChiusura
    {
        // Vale sempre "close"
        [JsonPropertyName("action")]
        public string Action { get; set; }
    }

    // Conferma di chiusura - chiusura_risposta.schema.json
    public class RispostaChiusura
    {
        // Vale sempre "closed"
        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("session_id")]
        public string SessionId { get; set; }
    }

    // Messaggio di errore - errore.schema.json
    public class Errore
    {
        // Descrizione dell'errore
        [JsonPropertyName("error")]
        public string Error { get; set; }

        // Campo sbagliato. Se è null non viene scritto nel JSON.
        [JsonPropertyName("field")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Field { get; set; }

        // Costruttore vuoto: serve per leggere un Errore da un JSON
        public Errore()
        {
        }

        // Costruttore comodo per creare un errore in una riga
        public Errore(string errore, string campo)
        {
            Error = errore;
            Field = campo;
        }
    }
}

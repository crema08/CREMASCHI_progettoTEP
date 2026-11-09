# FrigoTrack – Telemetria sicura per la catena del freddo

Sistema client-server HTTP in C#. I sensori di temperatura mandano le misure in JSON, cifrate con una chiave concordata tramite **Diffie-Hellman** e controllate con **JSON Schema**.

## Struttura del repository

| Percorso | Contenuto |
|---|---|
| `FrigoTrack/` | **tutto il programma**: è la cartella da scaricare e aprire con Visual Studio (`FrigoTrack/FrigoTrack.sln`) |
| `README.md`, `RELAZIONE.md` | documentazione e relazione |
| `5IB_Progetto_TEP.pdf` | testo della consegna |

Dentro `FrigoTrack/`:

| Cartella | Contenuto |
|---|---|
| `Server/` | server HTTP (HttpListener) su `http://localhost:5000` |
| `Client/` | simulatore di 3 sensori + prova con una misura non valida |
| `Test/` | test automatici (il server deve essere avviato) |
| `Comune/` | codice condiviso: Diffie-Hellman, cifratura AES-GCM, validazione, classi dei messaggi |
| `schemas/` | un JSON Schema per ogni tipo di messaggio |

## Requisiti

- Visual Studio 2022 o successivo (oppure .NET SDK 8 o successivo)
- Connessione a internet la prima volta: Visual Studio scarica da solo il pacchetto **NJsonSchema** (validazione JSON Schema)

## Avvio

**Da Visual Studio**
1. Aprire `FrigoTrack/FrigoTrack.sln`.
2. Tasto destro sulla soluzione → *Configura progetti di avvio* → *Progetti di avvio multipli*.
3. Mettere `Server` e `Client` su *Avvio* (oppure `Server` e `Test` per i test).
4. Premere *Avvia* e, nella finestra del client, premere INVIO quando il server è partito.

**Da terminale** (due finestre, nella cartella `FrigoTrack/`)
```
cd FrigoTrack
dotnet run --project Server
dotnet run --project Client
dotnet run --project Test
```

Le misure ricevute vengono salvate in `dati/` accanto all'eseguibile del server (il percorso esatto viene stampato all'avvio): un file JSON per ogni sensore.

## Diagramma di sequenza dell'handshake

```
   Client (sensore)                                     Server
        |                                                 |
        |  sceglie a casuale                              |
        |  A = g^a mod p                                  |
        |                                                 |
        |---- POST /api/handshake {p, g, A} ------------->|
        |                                                 |  controlla lo schema
        |                                                 |  sceglie b casuale
        |                                                 |  B = g^b mod p
        |                                                 |  K = A^b mod p
        |                                                 |  chiave = SHA-256(K)
        |                                                 |  salva session_id -> chiave
        |<--- 200 {session_id, B} ------------------------|
        |                                                 |
        |  K = B^a mod p   (uguale a quella del server)   |
        |  chiave = SHA-256(K)                            |
        |                                                 |
        |==== da qui in poi solo buste cifrate ==========>|
        |---- POST /api/telemetry {session_id, ciphertext, tag}
        |<--- 200 {session_id, ciphertext, tag} ----------|
```

`p` è il primo a 2048 bit del gruppo 14 dell'RFC 3526, `g = 2`. La chiave K non passa mai in rete.

## Protocollo

| Endpoint | Metodo | Corpo | Risposta |
|---|---|---|---|
| `/api/handshake` | POST | `{p, g, A}` in chiaro | `{session_id, B}` in chiaro |
| `/api/telemetry` | POST | busta con una misura | busta con la conferma (ed eventuale allarme) |
| `/api/readings` | POST | busta con la richiesta (sensore, intervallo) | busta con l'elenco delle misure |
| `/api/close` | POST | busta con `{action: "close"}` | busta con la conferma; la chiave viene cancellata |

**Busta cifrata** (l'unico dato in chiaro è `session_id`):
```json
{ "session_id": "a3f9c2e1", "ciphertext": "...Base64...", "tag": "...Base64..." }
```
- `ciphertext` = nonce (12 byte) + messaggio cifrato con AES-GCM, in Base64
- `tag` = tag di controllo di AES-GCM (16 byte), in Base64

**Regola del server:** prima decifra, poi valida. Se la decifratura o il tag falliscono risponde 400 senza elaborare nulla.

**Codici HTTP**

| Codice | Quando |
|---|---|
| 200 | tutto ok |
| 400 | JSON non valido, busta malformata, busta manomessa (tag sbagliato), messaggio che non rispetta lo schema |
| 401 | `session_id` inesistente o sessione già chiusa |
| 404 | endpoint inesistente |

## Messaggi

Ogni messaggio ha il suo schema in `FrigoTrack/schemas/`.

| Schema | Messaggio | Campi |
|---|---|---|
| `handshake_richiesta` | richiesta di handshake | `p`, `g`, `A` (stringhe di cifre) |
| `handshake_risposta` | risposta all'handshake | `session_id` (8 caratteri esadecimali), `B` |
| `busta` | busta cifrata | `session_id`, `ciphertext`, `tag` |
| `misura` | misura del sensore | `sensor_id` (es. `CELLA-BG-007`), `timestamp` (date-time), `cargo_type` (`food`, `pharma`, `frozen`), `temperature_c` (-40…40), `humidity` (0…100), `battery` (intero 0…100) |
| `conferma` | risposta a una misura | `status` (`ok`), `sensor_id`, `alarm` (true/false), `message` |
| `letture_richiesta` | richiesta delle misure | `sensor_id`, `from`, `to` (date-time) |
| `letture_risposta` | elenco delle misure | `sensor_id`, `count`, `readings` (array di misure) |
| `chiusura_richiesta` | chiusura sessione | `action` (`close`) |
| `chiusura_risposta` | conferma chiusura | `status` (`closed`), `session_id` |
| `errore` | messaggio di errore | `error`, `field` (campo sbagliato, se si sa) |

Esempio di misura (prima della cifratura):
```json
{ "sensor_id": "CELLA-BG-007", "timestamp": "2026-11-02T08:15:30Z", "cargo_type": "pharma",
  "temperature_c": 4.6, "humidity": 55, "battery": 87 }
```

Esempio di errore (temperatura 99):
```json
{ "error": "messaggio non valido: NumberTooBig", "field": "temperature_c" }
```

**Allarmi**: il server mette `alarm: true` nella conferma quando la temperatura esce dall'intervallo di sicurezza: farmaci (`pharma`) 2…8 °C, alimenti freschi (`food`) 0…4 °C, surgelati (`frozen`) -30…-18 °C.

## Test

Il progetto `Test` (con il server avviato) esegue:

1. handshake riuscito
2. messaggio valido
3. messaggio non valido (risposta 400 con il campo sbagliato)
4. busta manomessa (risposta 400)
5. sessione inesistente (risposta 401)
6. endpoint inesistente (risposta 404)
7. allarme temperatura
8. letture, chiusura sessione e rifiuto della sessione chiusa (401)

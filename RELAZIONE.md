# Relazione – FrigoTrack

## Scelte tecniche

**Linguaggio e struttura.** Il progetto è in C# (.NET 8) con Visual Studio e ha quattro progetti: Server, Client, Test e una libreria Comune con il codice usato da tutti (Diffie-Hellman, cifratura, validazione e classi dei messaggi). Così lo stesso codice non viene scritto due volte.

**Server HTTP.** Uso `HttpListener`, il server HTTP già incluso in .NET, senza framework esterni. Ogni richiesta viene gestita in un thread separato (`Task.Run`), quindi più sensori possono comunicare insieme. Le sessioni stanno in un `ConcurrentDictionary` (session_id → chiave), che si può usare da più thread senza errori.

**Diffie-Hellman.** Il gruppo è il 14 dell'RFC 3526 (primo da 2048 bit, g = 2). I segreti a e b sono numeri casuali da 256 bit presi da `RandomNumberGenerator`, il generatore sicuro di .NET. Tutti i calcoli usano solo `BigInteger.ModPow`. Il server controlla che A sia compreso tra 2 e p-2, per evitare valori che renderebbero K banale.

**Chiave e cifratura.** Dal segreto condiviso K ricavo la chiave con SHA-256, che produce sempre 32 byte: una chiave AES a 256 bit. Cifro con **AES-GCM**, che insieme alla cifratura produce un tag di controllo. Se un byte della busta viene modificato il tag non torna e la decifratura fallisce, quindi le modifiche vengono scoperte. Ogni messaggio usa un nonce casuale di 12 byte. Il nonce viene messo davanti al testo cifrato, così la busta resta di tre campi (session_id, ciphertext, tag).

**JSON Schema.** C'è uno schema per ogni messaggio, in file separati, con vincoli reali (type, required, enum, minimum/maximum, pattern, format, additionalProperties: false). La validazione usa la libreria NJsonSchema. Il client valida ogni messaggio prima di cifrarlo. Il server prima decifra e poi valida: se la decifratura fallisce risponde 400 senza elaborare nulla. Gli errori di validazione indicano il campo sbagliato e vengono rimandati cifrati.

**Salvataggio.** Le misure vengono salvate in un file JSON per ogni sensore. Un `lock` impedisce a due richieste di scrivere lo stesso file insieme. Il nome del file è sicuro perché `sensor_id` è già stato controllato dallo schema: solo maiuscole, trattini e numeri. Le misure si leggono con `/api/readings`, filtrate per sensore e intervallo di tempo.

**Allarmi.** Il server confronta la temperatura con l'intervallo del tipo di merce (farmaci 2–8 °C, alimenti 0–4 °C, surgelati -30/-18 °C) e, se la temperatura è fuori, mette `alarm: true` nella conferma.

## Limiti noti

- **Handshake non autenticato.** Diffie-Hellman da solo non verifica con chi si sta parlando. Un attaccante in mezzo (man-in-the-middle) potrebbe fare un handshake con il client e uno con il server. Servirebbero certificati o firme digitali.
- **p e g scelti dal client.** Il server accetta qualsiasi p e g. Un client malevolo potrebbe proporre un gruppo debole. Il server dovrebbe accettare solo gruppi noti.
- **Nessuna protezione dal replay.** Una busta intercettata può essere rimandata uguale e viene accettata di nuovo. Servirebbe un contatore o un controllo sul timestamp.
- **Errori in chiaro.** Gli errori che avvengono prima della decifratura (busta malformata, sessione inesistente, tag sbagliato) vanno in chiaro, perché il server non ha una chiave valida da usare. Non contengono dati dei sensori.
- **Sessioni solo in memoria.** Le sessioni non scadono e si perdono al riavvio del server.
- **Nessuna autorizzazione.** Una sessione valida può leggere le misure di qualsiasi sensore.
- **Salvataggio semplice.** Per ogni misura il file viene letto e riscritto tutto: va bene per un prototipo, non per grandi volumi (servirebbe un database).
- **HTTP.** Il contenuto è cifrato, ma chi osserva la rete vede comunque l'endpoint chiamato, l'orario e la dimensione dei messaggi.

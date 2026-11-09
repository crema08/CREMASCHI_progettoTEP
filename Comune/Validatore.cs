using NJsonSchema;
using NJsonSchema.Validation;

namespace Comune
{
    // Controlla che un JSON rispetti uno degli schemi della cartella schemas
    public static class Validatore
    {
        // Restituisce null se il JSON è valido,
        // altrimenti un Errore che dice quale campo è sbagliato.
        public static Errore Valida(string json, string nomeSchema)
        {
            // La cartella schemas viene copiata accanto al programma (vedi Comune.csproj)
            string percorso = Path.Combine(AppContext.BaseDirectory, "schemas", nomeSchema);

            // Carico lo schema dal file
            JsonSchema schema = JsonSchema.FromFileAsync(percorso).Result;

            // Controllo il JSON: ottengo l'elenco degli errori (vuoto se è tutto giusto)
            ICollection<ValidationError> errori;
            try
            {
                errori = schema.Validate(json);
            }
            catch (Exception)
            {
                // Il testo non è nemmeno un JSON leggibile
                return new Errore("JSON non leggibile", null);
            }

            // Nessun errore: il messaggio è valido
            if (errori.Count == 0)
            {
                return null;
            }

            // Prendo il primo errore e lo trasformo in un messaggio semplice
            ValidationError primo = errori.First();
            // Kind dice il tipo di errore (es. NumberTooBig), Property il nome del campo
            return new Errore("messaggio non valido: " + primo.Kind, primo.Property);
        }
    }
}

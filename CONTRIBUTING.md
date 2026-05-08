# Contribuire a PCAPCaper

Grazie per l'interesse nel progetto. PCAPCaper analizza file di rete, quindi le contribuzioni devono trattare con attenzione PCAP, IP, payload e servizi esterni.

## Workflow consigliato

1. Apri una issue o commenta una issue esistente per allineare obiettivo e scope.
2. Crea un branch dedicato:

```bash
git checkout -b feature/nome-breve
```

3. Mantieni la modifica focalizzata.
4. Aggiorna README o commenti quando cambi comportamento utente, API o sicurezza.
5. Apri una pull request usando il template.

## Setup locale

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Docker:

```bash
docker-compose up --build
```

## Verifiche prima della PR

Esegui almeno le verifiche applicabili:

```bash
python -m py_compile backend/main.py backend/models.py backend/analyzer.py backend/external_enrichment.py
npm run build
docker-compose up --build
```

Se non puoi eseguire un comando, dichiaralo nella PR.

## Linee guida codice

- Mantieni i commenti in italiano quando aggiungi logica non ovvia.
- Evita refactor non necessari nella stessa PR.
- Non introdurre dipendenze nuove se una soluzione semplice con lo stack esistente e sufficiente.
- Per UI e UX, mantieni lo stile coerente con Tailwind e componenti esistenti.
- Per il backend, mantieni gli endpoint espliciti e documentati.

## Privacy e dati sensibili

- Non committare file PCAP reali.
- Non committare payload, credenziali, token, cookie o dati personali.
- Anonimizza IP e hostnames negli esempi quando necessario.
- Le funzionalita che inviano dati a servizi esterni devono essere opt-in, visibili all'utente e documentate.
- Gli IP privati/locali/riservati non devono essere inviati a servizi esterni.

## Issue

Usa i template in `.github/ISSUE_TEMPLATE`:

- bug report per malfunzionamenti;
- feature request per nuove funzionalita;
- security report per rischi o vulnerabilita.

## Pull request

Una PR dovrebbe includere:

- descrizione del cambiamento;
- motivazione;
- test/verifiche eseguite;
- screenshot se cambia la UI;
- note privacy se vengono toccati PCAP, IP o servizi esterni.

## Licenza

Contribuendo accetti che il tuo contributo sia distribuito con la licenza del progetto.

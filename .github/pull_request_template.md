## Descrizione

Spiega in modo sintetico cosa cambia e perche.

## Tipo di modifica

- [ ] Bug fix
- [ ] Nuova funzionalita
- [ ] Refactor
- [ ] Documentazione
- [ ] Security hardening
- [ ] Build/CI/Docker

## Aree impattate

- [ ] Backend FastAPI
- [ ] Analisi PCAP / Scapy
- [ ] Frontend React
- [ ] Filtri pacchetto
- [ ] Arricchimento IP esterno
- [ ] Security panel
- [ ] Documentazione

## Verifiche eseguite

Indica i comandi eseguiti e il risultato.

```bash
# esempi
python -m py_compile backend/main.py backend/models.py backend/analyzer.py backend/external_enrichment.py
npm run build
docker-compose up --build
```

## Privacy e dati sensibili

- [ ] Non ho incluso file PCAP reali o dati sensibili nel commit.
- [ ] Non ho aggiunto log che espongono payload, credenziali o dati personali.
- [ ] Se la modifica invia dati a servizi esterni, il comportamento e opt-in e documentato.

## Screenshot / note UI

Allega screenshot o descrivi le modifiche visuali, se rilevante.

## Checklist

- [ ] Il codice e commentato dove la logica non e ovvia.
- [ ] La documentazione e aggiornata, se necessario.
- [ ] Le modifiche sono limitate allo scopo della PR.
- [ ] Ho controllato che non ci siano file temporanei o artefatti locali.

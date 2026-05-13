# PCAPCaper 🔍

**Analizzatore PCAP open source con interfaccia web moderna.**

Carica un file di cattura di rete e ottieni subito statistiche su protocolli, indirizzi IP, porte, conversazioni, DNS, HTTP, TLS, timeline del traffico, filtri pacchetto, payload ricostruiti, arricchimento IP esterno, mappa geografica, correlazione avanzata dei pacchetti, profili host, grafo di rete e analisi security.

> Ispirato a [apackets.com](https://apackets.com/), ma completamente open source e auto-ospitabile.

---

## Galleria

| | | | |
|---|---|---|---|
| ![Dashboard](./stuff/i/SCR-20260509-bmlx.png) | ![Analisi Flussi](./stuff/i/SCR-20260508-pdch.png) | ![Lista Pacchetti](./stuff/i/SCR-20260508-pglq.png) | ![Panoramica Rete](./stuff/i/SCR-20260508-rnut.png) |
| ![Timeline](./stuff/i/SCR-20260512-rzsg.png) | ![Tracce Avanzate](./stuff/i/SCR-20260509-jpwv.png) | ![Analisi Protocolli](./stuff/i/SCR-20260425-rptd.png) | |

---

## Avvio Rapido

### Docker (Consigliato)

```bash
git clone https://github.com/myblacksloth/aPCAPerX.git
cd aPCAPerX
docker compose up --build
```

Apri **`http://localhost:3000`** nel browser.

### Avvio Locale

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Frontend (nuovo terminale)
cd frontend
npm install && npm run dev
```

Apri **`http://localhost:5173`** nel browser.

Per istruzioni dettagliate, vedi [Guida Setup](doc/SETUP.md).

---

## Funzionalità

| Funzione | Descrizione |
| --- | --- |
| **Analisi Protocolli** | Grafico donut e tabella percentuali per i protocolli rilevati |
| **Conversazioni** | Flussi bidirezionali IP-to-IP con conteggi pacchetti e byte |
| **Filtri Pacchetti** | Sintassi stile Wireshark + builder GUI |
| **Profili Host** | Dettagli IP, DNS, HTTP/SNI, ASN/GeoIP, finding e timeline |
| **Grafo di Rete** | Visualizzazione host-to-host basata su flow 5-tuple |
| **Analisi DNS** | Estrazione query, tracking risoluzioni, e controlli reputazione (opt-in) |
| **Analisi HTTP** | Estrazione metadati HTTP in chiaro con correlazione request/response |
| **Analisi TLS** | SNI, versione, cipher, certificato, JA3/JA3S e anomalie |
| **Follow Stream** | Ricostruzione payload TCP/UDP con transcript client/server |
| **Arricchimento IP** | RDAP, ASN, reverse DNS e GeoIP (opt-in, con consenso utente) |
| **Security Finding** | Regole euristiche per connessioni rischiose e threat intel (opt-in) |
| **Mappa Traffico IP** | Mappa mondiale colorata in base al traffico per geolocalizzazione |
| **Tracce Avanzate** | Alberatura flow con correlazione pacchetti e ACK |
| **Chat IA** | Assistente locale leggero (Ollama) per analisi tecnica |

Formati supportati: `.pcap`, `.pcapng`, `.cap`  
Nessun limite upload predefinito. I limiti operativi sono configurabili.

---

## Caratteristiche Principali

### Privacy-by-Default

L'analisi standard è **completamente locale** sul file caricato. Le funzioni che contattano servizi esterni (arricchimento IP, reputazione DNS, threat intelligence) sono **opt-in** e mostrano un popup di consenso prima di inviare dati.

Gli indirizzi IP privati, locali, multicast e riservati **non vengono mai** inviati a servizi esterni.

### Ottimizzato per le Prestazioni

- Upload trasmessi a storage temporaneo in chunk
- Analisi PCAP eseguita in thread separato
- Dettagli pacchetti paginati; riepiloghi calcolati su tutto il capture
- Arricchimento esterno parallelizzato con worker limitati
- Risposte JSON limitate dalla configurazione per evitare rallentamenti

### Assistente IA Leggero

Chat integrata alimentata da un modello Ollama locale (`qwen2.5:0.5b` di default):
- Docker limitato a 1 CPU e 3 GB RAM
- Nessun byte grezzo di pacchetto inviato al modello; solo evidenze tecniche limitate
- Protezione timeout per evitare blocchi

---

## Screenshot

| Vista | Funzione |
| --- | --- |
| ![Dashboard](./stuff/i/SCR-20260509-bmlx.png) | Overview dashboard con top IP e distribuzione protocolli |
| ![DNS Analysis](./stuff/i/SCR-20260508-twqb.png) | Query DNS, risposte e indicatori di tunneling |
| ![HTTP Analysis](./stuff/i/SCR-20260508-uceg.png) | Richieste HTTP e risposte in chiaro |
| ![TLS Analysis](./stuff/i/SCR-20260508-uhnh.png) | Metadati handshake TLS e dettagli certificato |
| ![IP Traffic Map](./stuff/i/SCR-20260508-pbqj.png) | Mappa geolocalizzazione con colorazione traffico per paese |
| ![Security Report](./stuff/i/SCR-20260508-rnlr.png) | Finding security avanzate con threat intel |
| ![Network Graph](./stuff/i/SCR-20260508-rhxk.png) | Visualizzazione rete host-to-host |
| ![Follow Stream](./stuff/i/SCR-20260509-bcqx.png) | Ricostruzione payload TCP/UDP |

---

## Documentazione

- **[Setup & Installazione](doc/SETUP.md)** — Istruzioni setup locale e Docker
- **[Architettura](doc/ARCHITECTURE.md)** — Design sistema, tech stack e flusso analisi
- **[Guida Funzionalità](doc/FEATURES.md)** — Descrizioni dettagliate delle funzioni
- **[Configurazione](doc/CONFIGURATION.md)** — Variabili ambiente e tuning performance
- **[Assistente IA](doc/AI.md)** — Integrazione Ollama e configurazione
- **[Riferimento API](doc/API.md)** — Endpoint REST e formati request/response
- **[Struttura Progetto](doc/STRUCTURE.md)** — Organizzazione codebase
- **[Guida Sviluppo](doc/DEVELOPMENT.md)** — Linee guida contributi e stile codice

---

## Configurazione

Variabili ambiente principali:

| Variabile | Default | Scopo |
| --- | --- | --- |
| `PCAPCAPER_UPLOAD_MAX_MB` | `0` | Limite upload (0 = illimitato) |
| `PCAPCAPER_MAX_PACKET_LIST` | `1000` | Max dettagli pacchetti in JSON |
| `PCAPCAPER_TEMP_DIR` | `/tmp/pcapcaper` | Storage file temporanei |
| `PCAPCAPER_AI_ENABLED` | `1` | Abilita chat IA locale |
| `PCAPCAPER_AUTH_ENABLED` | `1` | Abilita account utente & autenticazione |

Per tutte le opzioni, vedi [Guida Configurazione](doc/CONFIGURATION.md).

---

## API

Endpoint principali:

- `POST /api/analyze` — Carica e analizza un file PCAP
- `POST /api/enrich-ips` — Arricchisci IP con dati esterni (opt-in)
- `POST /api/security-analysis` — Esegui analisi security avanzata (opt-in)
- `POST /api/dns-reputation` — Controlla domini DNS contro liste reputazione (opt-in)
- `POST /api/ai-chat` — Chiedi all'assistente IA sulla cattura

Per la documentazione API completa, vedi [API Docs](doc/API.md).

---

## Sviluppo

### Contribuire

I contributi sono benvenuti! Per favore:

1. Fai un fork del repository
2. Crea un branch feature: `git checkout -b feature/tuo-feature`
3. Scrivi codice chiaro e commentato in inglese
4. Aggiorna la documentazione se necessario
5. Invia una pull request

Vedi [Guida Sviluppo](doc/DEVELOPMENT.md) per linee guida dettagliate.

### Requisiti Codice

- ✅ Codice funzionante e testato
- ✅ Commenti chiari in inglese
- ✅ `.env.example` aggiornato se cambiano le config
- ✅ Niente credenziali, file PCAP, o dati personali nel commit
- ✅ Funzioni esterne devono essere opt-in con consenso utente

---

## Licenza

GNU Affero General Public License v3.0 — vedi [LICENSE](LICENSE) per i dettagli.

---

*PCAPCaper — Open Source PCAP Analyzer*  
*© 2026 — [myblacksloth](https://github.com/myblacksloth)*

**Disponibile in:** [English](README.md) · [Italiano](README.ITA.md)

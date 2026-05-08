![](./stuff/i/SCR-20260425-pjby.png)

![](./stuff/i/SCR-20260425-pjhs.png)

![](./stuff/i/SCR-20260425-pjla.png)

![](./stuff/i/SCR-20260425-pjrj.png)

![](./stuff/i/SCR-20260425-rptd.png)

![](./stuff/i/SCR-20260425-rwmv.png)

![](./stuff/i/SCR-20260508-pdch.png)

# PCAPCaper 🔍

**PCAPCaper** è un analizzatore open source di file PCAP/PCAPNG con interfaccia web moderna.
Carica un file di cattura di rete e ottieni in secondi statistiche complete su protocolli, indirizzi IP, porte, conversazioni e timeline del traffico.

> Ispirato a [apackets.com](https://apackets.com/), ma completamente open source e auto-ospitabile.

---

- [PCAPCaper 🔍](#pcapcaper-)
  - [✨ Funzionalità](#-funzionalità)
  - [Screenshot](#screenshot)
    - [Servizio di analisi degli indirizzi IP](#servizio-di-analisi-degli-indirizzi-ip)
    - [Mappa degli indirizzi IP](#mappa-degli-indirizzi-ip)
  - [🏗️ Architettura](#️-architettura)
  - [🧩 Stack tecnologico](#-stack-tecnologico)
    - [Backend](#backend)
    - [Frontend](#frontend)
    - [Infrastruttura](#infrastruttura)
  - [📊 Flusso di analisi](#-flusso-di-analisi)
  - [🚀 Avvio locale (senza Docker)](#-avvio-locale-senza-docker)
    - [Prerequisiti](#prerequisiti)
    - [1. Clona il repository](#1-clona-il-repository)
    - [2. Avvia il Backend](#2-avvia-il-backend)
    - [3. Avvia il Frontend](#3-avvia-il-frontend)
  - [🐳 Avvio con Docker](#-avvio-con-docker)
    - [Prerequisiti](#prerequisiti-1)
    - [Avvio completo](#avvio-completo)
    - [Comandi utili](#comandi-utili)
    - [Porte esposte](#porte-esposte)
  - [📡 API Reference](#-api-reference)
    - [`GET /api/health`](#get-apihealth)
    - [`POST /api/analyze`](#post-apianalyze)
  - [📁 Struttura del progetto](#-struttura-del-progetto)
  - [🔄 Diagramma dei componenti frontend](#-diagramma-dei-componenti-frontend)
  - [🤝 Contribuire](#-contribuire)
  - [📄 Licenza](#-licenza)


---

## ✨ Funzionalità

| Sezione | Dettagli |
|---|---|
| **Riepilogo** | Pacchetti totali, byte, durata, pacchetti/sec, dimensione media |
| **Protocolli** | Distribuzione con grafico donut + tabella percentuali (top 20) |
| **Top IP** | Indirizzi sorgente e destinazione più attivi con grafici a barre (top 20) |
| **Top Porte** | Porte TCP/UDP più usate con nome servizio (top 15 src + dst) |
| **Conversazioni** | Flussi bidirezionali IP↔IP ordinabili per pacchetti o byte (top 20) |
| **Timeline** | Area chart del traffico nel tempo con bucket adattivi |
| **Lista Pacchetti** | Primi 1000 pacchetti con ricerca full-text e paginazione |
| **Esporta JSON** | Scarica il risultato dell'analisi in formato JSON |

Formati supportati: `.pcap`, `.pcapng`, `.cap` · Limite dimensione: **100 MB**

---

## Screenshot

**dettaglio su indirizzi IP**

![](./stuff/i/SCR-20260508-otsa.png)

### Servizio di analisi degli indirizzi IP

![](./stuff/i/SCR-20260508-oxxe.png)

![](./stuff/i/SCR-20260508-oyca.png)

![](./stuff/i/SCR-20260508-oypg.png)

### Mappa degli indirizzi IP

![](./stuff/i/SCR-20260508-pbqj.png)

<!--
![](./stuff/i/.png)
-->

---

## 🏗️ Architettura

```mermaid
graph TB
    U["👤 Utente"]
    FE["🖥️ Frontend\nReact 18 + Vite\nNginx (Docker)\nporta 3000 / 5173"]
    BE["⚙️ Backend\nFastAPI + Python 3.11\nUvicorn ASGI\nporta 8000"]
    SC["📦 Scapy\nPCAP Parser\nDecoder protocolli"]

    U -->|"Drag & drop file PCAP"| FE
    FE -->|"POST /api/analyze\nmultipart/form-data"| BE
    BE -->|"PcapReader streaming"| SC
    SC -->|"Pacchetti decodificati"| BE
    BE -->|"JSON: statistiche complete"| FE
    FE -->|"Dashboard interattivo"| U

    style FE fill:#1e293b,stroke:#6366f1,color:#f1f5f9
    style BE fill:#1e293b,stroke:#22c55e,color:#f1f5f9
    style SC fill:#1e293b,stroke:#eab308,color:#f1f5f9
```

---

## 🧩 Stack tecnologico

### Backend
| Tecnologia | Versione | Ruolo |
|---|---|---|
| Python | 3.11 | Runtime |
| FastAPI | 0.115 | Framework REST API |
| Scapy | 2.6 | Lettura e decodifica PCAP |
| Uvicorn | 0.34 | Server ASGI |
| Pydantic | v2 | Validazione e serializzazione dati |

### Frontend
| Tecnologia | Versione | Ruolo |
|---|---|---|
| React | 18 | UI framework |
| TypeScript | 5.5 | Type safety |
| Vite | 5 | Build tool e dev server |
| Tailwind CSS | 3.4 | Utility-first CSS |
| Recharts | 2.12 | Grafici (Area, Bar, Pie) |
| Lucide React | — | Icone SVG |

### Infrastruttura
| Tecnologia | Ruolo |
|---|---|
| Docker + docker-compose | Containerizzazione |
| Nginx 1.27 | Serve il frontend + proxy verso il backend |

---

## 📊 Flusso di analisi

```mermaid
flowchart LR
    subgraph Upload
        A["File PCAP"] -->|"multipart POST"| B["Validazione\nestensione + dim."]
        B --> C["Salvataggio\nfile temporaneo"]
    end

    subgraph "Analisi - analyzer.py"
        C --> D["PcapReader\nstreaming"]
        D --> E["Per ogni pacchetto"]
        E --> F["_get_protocol()"]
        E --> G["Estrazione IP\nsrc / dst"]
        E --> H["Estrazione porte\nTCP / UDP"]
        F --> I["Contatori\nprotocolli"]
        G --> J["Contatori IP\ne conversazioni"]
        H --> K["Contatori\nporte"]
        E --> L["Bucket\ntimeline"]
        E --> M["Lista pacchetti\nmax 1000"]
    end

    subgraph Aggregazione
        I & J & K & L & M --> N["AnalysisResult\nPydantic"]
        N -->|"JSON"| O["Frontend\nDashboard"]
    end
```

---

## 🚀 Avvio locale (senza Docker)

### Prerequisiti
- Python **3.11** o superiore
- Node.js **20** o superiore
- `pip` e `npm`
- Su macOS: `brew install libpcap` (necessario per Scapy)
- Su Linux (Debian/Ubuntu): `sudo apt-get install libpcap-dev`

### 1. Clona il repository

```bash
git clone https://github.com/tuo-utente/pcapcaper.git
cd pcapcaper
```

### 2. Avvia il Backend

```bash
cd backend

# Crea e attiva un virtual environment (raccomandato)
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# oppure: .venv\Scripts\activate  # Windows

# Installa le dipendenze
pip install -r requirements.txt

# Avvia il server FastAPI con hot-reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Il backend sarà disponibile su `http://localhost:8000`  
Documentazione API interattiva: `http://localhost:8000/docs`

### 3. Avvia il Frontend

Apri un **nuovo terminale**:

```bash
cd frontend

# Installa le dipendenze npm
npm install

# Avvia il dev server Vite con proxy verso il backend
npm run dev
```

Il frontend sarà disponibile su `http://localhost:5173`

> Vite proxy-izza automaticamente le richieste `/api/*` verso `localhost:8000`,
> quindi non è necessario configurare nulla manualmente.

---

## 🐳 Avvio con Docker

### Prerequisiti
- Docker **24+**
- Docker Compose **v2** (incluso in Docker Desktop)

### Avvio completo

```bash
# Clona il repository (se non l'hai già fatto)
git clone https://github.com/tuo-utente/pcapcaper.git
cd pcapcaper

# Build delle immagini e avvio dei container
docker-compose up --build
```

Apri il browser su **`http://localhost:3000`** 🎉

### Comandi utili

```bash
# Avvio in background (detached)
docker-compose up --build -d

# Visualizza i log in tempo reale
docker-compose logs -f

# Ferma i container (mantieni le immagini)
docker-compose stop

# Ferma e rimuovi container e reti
docker-compose down

# Ricostruisci solo il backend dopo modifiche
docker-compose up --build backend
```

### Porte esposte

| Servizio  | Porta host | Porta container | Note |
|-----------|-----------|-----------------|------|
| Frontend  | 3000      | 80              | Interfaccia web |
| Backend   | 8000      | 8000            | API REST (opzionale, per debug) |

---

## 📡 API Reference

### `GET /api/health`

Verifica che il backend sia attivo.

**Risposta:**
```json
{ "status": "ok", "service": "pcap-analyzer" }
```

---

### `POST /api/analyze`

Analizza un file PCAP e restituisce le statistiche.

**Request:** `Content-Type: multipart/form-data`

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `file` | File | File `.pcap`, `.pcapng` o `.cap` (max 100 MB) |

**Risposta (200 OK):**
```json
{
  "filename": "capture.pcap",
  "summary": {
    "total_packets": 12543,
    "total_bytes": 9876543,
    "capture_start": "2024-03-15T10:23:01+00:00",
    "capture_end": "2024-03-15T10:28:47+00:00",
    "duration_seconds": 346.2,
    "avg_packet_size": 787.5,
    "packets_per_second": 36.2
  },
  "protocols": [
    { "protocol": "HTTPS", "count": 4521, "bytes": 6234512, "percentage": 36.04 }
  ],
  "top_src_ips": [ { "ip": "192.168.1.10", "count": 3201, "bytes": 4512000 } ],
  "top_dst_ips": [ ... ],
  "top_src_ports": [ { "port": 443, "service": "HTTPS", "count": 4521, "protocol": "TCP" } ],
  "top_dst_ports": [ ... ],
  "conversations": [
    { "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "packets": 120, "bytes": 9800, "protocols": ["DNS"] }
  ],
  "timeline": [
    { "timestamp": "10:23:01", "packets": 45, "bytes": 38000 }
  ],
  "packets": [
    {
      "number": 1, "timestamp": "10:23:01.123", "src_ip": "192.168.1.10",
      "dst_ip": "8.8.8.8", "protocol": "DNS", "length": 74,
      "src_port": 52341, "dst_port": 53, "info": "DNS Query: google.com"
    }
  ]
}
```

**Errori:**

| Codice | Causa |
|--------|-------|
| 400 | Estensione file non supportata o file vuoto |
| 413 | File troppo grande (> 100 MB) |
| 422 | File PCAP corrotto o senza pacchetti validi |
| 500 | Errore interno del server |

---

## 📁 Struttura del progetto

```
pcapcaper/
├── backend/
│   ├── main.py          # Entry point FastAPI: endpoint /api/health e /api/analyze
│   ├── analyzer.py      # Motore di analisi PCAP (Scapy + aggregazione statistica)
│   ├── models.py        # Modelli Pydantic per request/response
│   ├── requirements.txt # Dipendenze Python
│   └── Dockerfile       # Immagine Docker del backend
│
├── frontend/
│   ├── src/
│   │   ├── main.tsx                    # Entry point React
│   │   ├── App.tsx                     # Componente radice (routing stati)
│   │   ├── index.css                   # Stili globali + Tailwind
│   │   ├── types/
│   │   │   └── analysis.ts             # Tipi TypeScript (mirror dei modelli Python)
│   │   ├── utils/
│   │   │   └── format.ts               # Formattazione (byte, durata, colori)
│   │   └── components/
│   │       ├── FileUpload.tsx          # Area drag & drop per il caricamento
│   │       ├── Dashboard.tsx           # Layout del dashboard (contenitore)
│   │       ├── SummaryCards.tsx        # 6 card metriche principali
│   │       ├── ProtocolChart.tsx       # Donut chart + tabella protocolli
│   │       ├── TopIPsChart.tsx         # Bar chart IP sorgente/destinazione
│   │       ├── TopPortsChart.tsx       # Bar chart porte src/dst
│   │       ├── TimelineChart.tsx       # Area chart traffico nel tempo
│   │       ├── ConversationsTable.tsx  # Tabella conversazioni ordinabile
│   │       └── PacketTable.tsx         # Lista pacchetti con ricerca e paginazione
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts   # Proxy /api → backend (dev locale)
│   ├── tailwind.config.js
│   ├── nginx.conf       # Configurazione Nginx (Docker): serve SPA + proxy API
│   └── Dockerfile       # Multi-stage: build Node.js → serve Nginx
│
├── docker-compose.yml   # Orchestrazione dei due container
└── README.md
```

---

## 🔄 Diagramma dei componenti frontend

```mermaid
graph TD
    App["App.tsx\nstato globale"]
    FU["FileUpload\nDrag & drop"]
    DB["Dashboard\nLayout container"]
    SC["SummaryCards\n6 metriche"]
    PC["ProtocolChart\nDonut + tabella"]
    TI["TopIPsChart\nBar chart tab"]
    TL["TimelineChart\nArea chart"]
    TP["TopPortsChart\nBar chart tab"]
    CT["ConversationsTable\nOrdinabile"]
    PT["PacketTable\nRicerca + pagine"]

    App -->|"nessun risultato"| FU
    App -->|"risultato disponibile"| DB
    DB --> SC
    DB --> PC
    DB --> TI
    DB --> TL
    DB --> TP
    DB --> CT
    DB --> PT

    style App fill:#1e293b,stroke:#6366f1,color:#f1f5f9
    style DB fill:#1e293b,stroke:#334155,color:#f1f5f9
```

---

## 🤝 Contribuire

1. Fork del repository
2. Crea un branch: `git checkout -b feature/nome-feature`
3. Commit delle modifiche: `git commit -m "feat: descrizione"`
4. Push: `git push origin feature/nome-feature`
5. Apri una Pull Request

---

## 📄 Licenza

GNU Affero General Public License v3.0 — vedi [LICENSE](LICENSE) per i dettagli.

---

*PCAPCaper — Open Source PCAP Analyzer*

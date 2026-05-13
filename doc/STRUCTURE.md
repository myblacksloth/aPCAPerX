# Project Structure

```text
pcapcaper/
├── backend/
│   ├── main.py                  # FastAPI entry point: health, analyze, enrich-ips
│   ├── analyzer.py              # PCAP analysis engine based on Scapy
│   ├── flow_analysis.py         # TCP/UDP 5-tuple flow reconstruction
│   ├── dns_analysis.py          # Local DNS analysis
│   ├── http_analysis.py         # Cleartext HTTP analysis
│   ├── tls_analysis.py          # Metadata-only TLS analysis
│   ├── host_analysis.py         # Aggregated host/IP view
│   ├── external_enrichment.py   # Opt-in external IP enrichment
│   ├── security_analysis.py     # Advanced security and threat intelligence engine
│   ├── dns_intelligence.py      # Opt-in DNS reputation checks
│   ├── ai_chat.py               # Packet-scoped lightweight AI assistant
│   ├── models.py                # Pydantic request/response models
│   ├── requirements.txt         # Python dependencies
│   └── Dockerfile               # Backend Docker image
├── frontend/
│   ├── src/
│   │   ├── main.tsx             # React entry point
│   │   ├── App.tsx              # Root component
│   │   ├── index.css            # Global styles and Tailwind
│   │   ├── types/
│   │   │   └── analysis.ts      # TypeScript analysis types
│   │   ├── utils/
│   │   │   ├── format.ts        # Formatting helpers
│   │   │   └── packetFilters.ts # Wireshark-style filter parser
│   │   └── components/          # UI components, dashboard views, and AI chat widget
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts           # Dev proxy: /api -> backend
│   ├── tailwind.config.js
│   ├── nginx.conf               # Nginx SPA serving and API proxy
│   └── Dockerfile               # Frontend Docker image
├── docker-compose.yml           # Backend, frontend, and Ollama AI orchestration
├── doc/                         # Documentation
│   ├── ARCHITECTURE.md
│   ├── SETUP.md
│   ├── CONFIGURATION.md
│   ├── AI.md
│   ├── FEATURES.md
│   ├── API.md
│   ├── STRUCTURE.md
│   └── DEVELOPMENT.md
└── README.md
```

## Key Components

### Backend

- **analyzer.py** - Core PCAP parsing and analysis engine using Scapy
- **flow_analysis.py** - TCP/UDP 5-tuple flow reconstruction and state tracking
- **dns_analysis.py** - DNS query/response extraction and correlation
- **http_analysis.py** - Cleartext HTTP metadata extraction
- **tls_analysis.py** - TLS handshake metadata and certificate analysis
- **host_analysis.py** - IP/host profiling and role detection
- **security_analysis.py** - Advanced threat intelligence and findings
- **external_enrichment.py** - RDAP, ASN, reverse DNS, and GeoIP lookups
- **ai_chat.py** - Technical evidence building for AI assistant
- **models.py** - Pydantic data models for validation and serialization

### Frontend

- **components/** - React components for UI views and widgets
- **types/** - TypeScript interfaces for analysis data
- **utils/** - Helper functions for formatting and filtering
- **vite.config.ts** - Development server proxy configuration
- **nginx.conf** - Production serving and reverse proxy configuration

### Infrastructure

- **docker-compose.yml** - Orchestrates backend, frontend, database, and Ollama services
- **Dockerfile** (backend/frontend) - Container images for each service

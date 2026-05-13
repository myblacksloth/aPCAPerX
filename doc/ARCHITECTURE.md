# Architecture & Technology Stack

## System Architecture

```mermaid
graph TB
    U["User"]
    FE["Frontend\nReact 18 + Vite\nNginx in Docker\nports 3000 / 5173"]
    BE["Backend\nFastAPI + Python 3.11\nUvicorn ASGI\nport 8000"]
    SC["Scapy\nPCAP parser\nProtocol decoder"]
    EXT["Optional external tools\nRDAP/IANA\nTeam Cymru\nReverse DNS\nip-api"]
    SECEXT["Opt-in threat intelligence\nShodan InternetDB\nFeodo Tracker\nOptional URLhaus"]
    DNSEXT["Opt-in DNS reputation\nAdGuard DNS filter\nStevenBlack hosts\nOptional URLhaus"]
    AI["Lightweight AI\nOllama container\nconfigurable model"]

    U -->|"Drag and drop PCAP"| FE
    FE -->|"POST /api/analyze"| BE
    FE -->|"POST /api/enrich-ips\nuser click only"| BE
    FE -->|"POST /api/security-analysis\nafter consent"| BE
    FE -->|"POST /api/dns-reputation\nafter consent"| BE
    FE -->|"POST /api/ai-chat\nquestion + packets"| BE
    BE -->|"Streaming PcapReader"| SC
    BE -->|"Public IPs"| EXT
    BE -->|"Public IPs + metadata"| SECEXT
    BE -->|"Observed DNS domains"| DNSEXT
    BE -->|"Selected compact packets only"| AI
    EXT -->|"ASN, RDAP, GeoIP, PTR"| BE
    SECEXT -->|"CVEs, IOCs, C2, malware hosts"| BE
    DNSEXT -->|"Ads, tracking, malware lists"| BE
    AI -->|"Answer"| BE
    SC -->|"Decoded packets"| BE
    BE -->|"Complete statistics JSON"| FE
    FE -->|"Interactive dashboard"| U
```

## Technology Stack

### Backend

| Technology | Version | Role |
| --- | --- | --- |
| Python | 3.11 | Runtime |
| FastAPI | 0.115 | REST API framework |
| Scapy | 2.6 | PCAP reading and decoding |
| Uvicorn | 0.34 | ASGI server |
| Pydantic | v2 | Data validation and serialization |

### Frontend

| Technology | Version | Role |
| --- | --- | --- |
| React | 18 | UI framework |
| TypeScript | 5.5 | Type safety |
| Vite | 5 | Build tool and development server |
| Tailwind CSS | 3.4 | Utility-first CSS |
| Recharts | 2.12 | Charts |
| Lucide React | — | SVG icons |

### Infrastructure

| Technology | Role |
| --- | --- |
| Docker + Docker Compose | Containerization |
| Nginx 1.27 | Frontend serving and API proxy |
| Ollama | Lightweight local AI model container |

## Analysis Flow

```mermaid
flowchart LR
    subgraph Upload
        A["PCAP file"] -->|"multipart POST"| B["Validation\nextension + size"]
        B --> C["Temporary file\nstorage"]
    end

    subgraph "Analysis - analyzer.py"
        C --> D["PcapReader\nstreaming"]
        D --> E["For each packet"]
        E --> F["Protocol detection"]
        E --> G["Source/destination IP extraction"]
        E --> H["TCP/UDP port extraction"]
        F --> I["Protocol counters"]
        G --> J["IP counters\nand conversations"]
        H --> K["Port counters"]
        E --> L["Timeline buckets"]
        E --> M["Packet list"]
        E --> Q["IP services\nDNS, peers, ports"]
        E --> Z["5-tuple TCP/UDP flows"]
        E --> HT["Cleartext HTTP metadata"]
        E --> TLS["TLS handshake metadata"]
        E --> HOSTS["Host/IP profiles"]
    end

    subgraph Aggregation
        I & J & K & L & M & Q & Z & HT & TLS & HOSTS --> N["AnalysisResult\nPydantic"]
        N -->|"JSON"| O["Frontend dashboard"]
    end

    subgraph "Optional enrichment"
        O -->|"user click"| P["/api/enrich-ips"]
        P --> R["RDAP, ASN,\nReverse DNS, GeoIP"]
        R --> O
    end

    subgraph "Advanced security opt-in"
        O -->|"click + consent popup"| S["/api/security-analysis"]
        S --> T["Threat intelligence"]
        S --> U["Scoring, evidence,\nrecommendations"]
        T & U --> O
    end

    subgraph "DNS reputation opt-in"
        O -->|"DNS tab"| V["Local DNS classification"]
        V -->|"click + consent popup"| W["/api/dns-reputation"]
        W --> X["AdGuard, StevenBlack,\noptional URLhaus"]
        X --> O
    end
```

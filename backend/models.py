"""
Modelli dati Pydantic per la serializzazione delle risposte API.

Ogni classe descrive una sezione del report di analisi restituito
dal backend al frontend. Pydantic garantisce la validazione automatica
dei tipi e la serializzazione JSON.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class SummaryStats(BaseModel):
    """Statistiche generali sulla cattura di pacchetti."""
    # Numero totale di pacchetti presenti nel file
    total_packets: int
    # Volume totale in byte di tutti i pacchetti
    total_bytes: int
    # Timestamp ISO 8601 del primo pacchetto catturato
    capture_start: Optional[str] = None
    # Timestamp ISO 8601 dell'ultimo pacchetto catturato
    capture_end: Optional[str] = None
    # Durata totale della cattura in secondi
    duration_seconds: float
    # Dimensione media dei pacchetti in byte
    avg_packet_size: float
    # Numero medio di pacchetti al secondo durante la cattura
    packets_per_second: float


class ProtocolEntry(BaseModel):
    """Statistiche di utilizzo per un singolo protocollo di rete."""
    # Nome del protocollo (es. "TCP", "DNS", "HTTP")
    protocol: str
    # Numero di pacchetti che usano questo protocollo
    count: int
    # Volume totale in byte per questo protocollo
    bytes: int
    # Percentuale sul totale dei pacchetti (0–100)
    percentage: float


class IPExternalInfo(BaseModel):
    """Informazioni ottenute da servizi esterni per un indirizzo IP pubblico."""
    # Indirizzo IP arricchito
    ip: str
    # Stato dell'arricchimento: enriched, skipped o error
    status: str
    # Motivo sintetico in caso di skip o errore
    reason: Optional[str] = None
    # Servizi esterni che hanno restituito almeno un dato utile
    sources: List[str] = Field(default_factory=list)
    # Nome reverse DNS ottenuto tramite risoluzione PTR
    reverse_dns: Optional[str] = None
    # Autonomous System Number, se disponibile
    asn: Optional[str] = None
    # Nome/descrizione dell'Autonomous System
    as_name: Optional[str] = None
    # Prefisso BGP associato all'indirizzo
    bgp_prefix: Optional[str] = None
    # Registry RIR o fonte di assegnazione (ARIN, RIPE, APNIC...)
    registry: Optional[str] = None
    # Data di allocazione del prefisso, se esposta dalla fonte
    allocated: Optional[str] = None
    # Nazione stimata o dichiarata dai servizi esterni
    country: Optional[str] = None
    # Codice nazione ISO/RIR
    country_code: Optional[str] = None
    # Regione geografica, se disponibile
    region: Optional[str] = None
    # Città stimata, se disponibile
    city: Optional[str] = None
    # Latitudine stimata
    lat: Optional[float] = None
    # Longitudine stimata
    lon: Optional[float] = None
    # Timezone stimata
    timezone: Optional[str] = None
    # ISP rilevato da servizi GeoIP
    isp: Optional[str] = None
    # Organizzazione rilevata da servizi GeoIP/RDAP
    org: Optional[str] = None
    # Indicatore mobile restituito dal servizio GeoIP
    mobile: Optional[bool] = None
    # Indicatore proxy/VPN restituito dal servizio GeoIP
    proxy: Optional[bool] = None
    # Indicatore hosting/datacenter restituito dal servizio GeoIP
    hosting: Optional[bool] = None
    # Handle RDAP della risorsa IP
    rdap_handle: Optional[str] = None
    # Nome RDAP della risorsa IP
    rdap_name: Optional[str] = None
    # Tipo RDAP della risorsa IP
    rdap_type: Optional[str] = None
    # Inizio del range RDAP
    rdap_start_address: Optional[str] = None
    # Fine del range RDAP
    rdap_end_address: Optional[str] = None
    # Entità/contatti principali esposti da RDAP
    rdap_entities: List[str] = Field(default_factory=list)
    # Note RDAP sintetiche
    rdap_remarks: List[str] = Field(default_factory=list)
    # Errori non bloccanti incontrati sui singoli servizi
    errors: List[str] = Field(default_factory=list)


class IPEnrichmentRequest(BaseModel):
    """Richiesta di arricchimento esterno per una lista di IP."""
    # Lista di indirizzi IP estratti dal report PCAP
    ips: List[str]


class IPEnrichmentResponse(BaseModel):
    """Risposta dell'arricchimento esterno indicizzata per indirizzo IP."""
    # Mappa IP -> informazioni esterne recuperate
    results: Dict[str, IPExternalInfo]


class SecurityPacketObservation(BaseModel):
    """Pacchetto compatto inviato alla pipeline di sicurezza avanzata."""
    # Numero progressivo del pacchetto nel PCAP
    number: int
    # Timestamp mostrato dal frontend
    timestamp: str
    # IP sorgente, se disponibile
    src_ip: Optional[str] = None
    # IP destinazione, se disponibile
    dst_ip: Optional[str] = None
    # Protocollo rilevato dal parser
    protocol: str
    # Lunghezza del pacchetto in byte
    length: int
    # Porta sorgente TCP/UDP, se disponibile
    src_port: Optional[int] = None
    # Porta destinazione TCP/UDP, se disponibile
    dst_port: Optional[int] = None
    # Campo informativo sintetico del pacchetto
    info: str


class SecurityAnalysisRequest(BaseModel):
    """Richiesta per l'analisi di sicurezza avanzata opt-in."""
    # Pacchetti da analizzare; il frontend invia l'intero traffico disponibile.
    packets: List[SecurityPacketObservation]
    # Informazioni IP ottenute in precedenza con "Analizza con tool esterni".
    external_ip_info: Dict[str, IPExternalInfo] = Field(default_factory=dict)
    # Limite massimo di IP pubblici interrogati sui servizi di threat intelligence.
    max_ips: int = 80


class SecuritySourceStatus(BaseModel):
    """Stato di una fonte esterna usata durante l'analisi di sicurezza."""
    # Nome della fonte o del motore
    source: str
    # Stato sintetico: ok, partial, skipped, error
    status: str
    # Dettaglio operativo utile al frontend
    detail: str


class SecurityFindingModel(BaseModel):
    """Finding prodotto dalla correlazione tra traffico e threat intelligence."""
    # Identificatore stabile del finding
    id: str
    # Severita normalizzata: critical, high, medium, low, info
    severity: str
    # Categoria del rischio
    category: str
    # Titolo leggibile del problema
    title: str
    # Descrizione sintetica del perche il traffico e rilevante
    description: str
    # IP principale coinvolto
    ip: Optional[str] = None
    # Altri IP coinvolti come peer o contesto
    related_ips: List[str] = Field(default_factory=list)
    # Evidenze concrete ricavate da traffico/API
    evidence: List[str] = Field(default_factory=list)
    # Azioni consigliate per triage o contenimento
    recommendation: str
    # Fonti che supportano il finding
    sources: List[str] = Field(default_factory=list)
    # Confidenza stimata 0-100
    confidence: int
    # Score tecnico 0-100
    score: int
    # Riferimenti MITRE ATT&CK quando applicabili
    mitre: List[str] = Field(default_factory=list)


class SecurityIPAssessmentModel(BaseModel):
    """Valutazione aggregata per singolo indirizzo IP pubblico."""
    # Indirizzo IP valutato
    ip: str
    # Score massimo/aggregato del rischio per IP
    risk_score: int
    # Severita derivata dallo score
    severity: str
    # Numero pacchetti in cui l'IP compare
    packets: int
    # Byte inviati dall'IP verso altri host
    bytes_out: int
    # Byte ricevuti dall'IP da altri host
    bytes_in: int
    # Porte osservate in relazione all'IP
    ports: List[int] = Field(default_factory=list)
    # Protocolli osservati
    protocols: List[str] = Field(default_factory=list)
    # Numero di peer distinti
    peer_count: int
    # Paese stimato dall'arricchimento precedente
    country: Optional[str] = None
    # ASN stimato dall'arricchimento precedente
    asn: Optional[str] = None
    # Nome AS/organizzazione
    as_name: Optional[str] = None
    # Tag esterni, ad esempio Shodan InternetDB
    tags: List[str] = Field(default_factory=list)
    # CVE o vulnerabilita associate all'IP secondo fonti esterne
    vulnerabilities: List[str] = Field(default_factory=list)
    # ID dei finding associati
    findings: List[str] = Field(default_factory=list)


class SecurityAnalysisSummary(BaseModel):
    """Riepilogo numerico dell'analisi di sicurezza avanzata."""
    # IP totali estratti dai pacchetti
    total_ips: int
    # IP pubblici realmente valutati
    analyzed_public_ips: int
    # Conteggio finding critici
    critical: int
    # Conteggio finding alti
    high: int
    # Conteggio finding medi
    medium: int
    # Conteggio finding bassi
    low: int
    # Conteggio finding informativi
    info: int
    # Totale finding prodotti
    total_findings: int


class SecurityAnalysisResponse(BaseModel):
    """Risposta completa dell'analisi di sicurezza avanzata."""
    # Riepilogo per dashboard
    summary: SecurityAnalysisSummary
    # Finding ordinati per priorita
    findings: List[SecurityFindingModel]
    # Valutazione aggregata per IP
    ip_assessments: List[SecurityIPAssessmentModel]
    # Stato delle fonti interne/esterne usate
    sources: List[SecuritySourceStatus]
    # Errori non bloccanti incontrati
    errors: List[str] = Field(default_factory=list)


class IPServiceEntry(BaseModel):
    """Servizio osservato in associazione a un indirizzo IP."""
    # Nome del servizio dedotto da porta/protocollo (es. "HTTPS", "DNS")
    service: str
    # Porta TCP/UDP osservata, se disponibile
    port: Optional[int] = None
    # Protocollo di trasporto o rete (TCP, UDP, ICMP, ARP...)
    protocol: str
    # Ruolo dell'IP rispetto al servizio: client, server o endpoint
    direction: str
    # Numero di pacchetti osservati per questa associazione
    count: int
    # Peer remoti più frequenti osservati con questo servizio
    peers: List[str]


class IPEntry(BaseModel):
    """Statistiche per un singolo indirizzo IP (sorgente o destinazione)."""
    # Indirizzo IP in notazione dotted-decimal o IPv6
    ip: str
    # Numero di pacchetti inviati/ricevuti da questo indirizzo
    count: int
    # Volume totale in byte inviati/ricevuti
    bytes: int
    # Protocolli osservati per questo IP
    protocols: List[str] = Field(default_factory=list)
    # Nomi DNS osservati nel PCAP per questo indirizzo
    hostnames: List[str] = Field(default_factory=list)
    # Peer remoti più frequenti
    peers: List[str] = Field(default_factory=list)
    # Servizi dedotti dalle porte e dai protocolli osservati
    services: List[IPServiceEntry] = Field(default_factory=list)
    # Informazioni opzionali ottenute interrogando servizi esterni
    external: Optional[IPExternalInfo] = None


class PortEntry(BaseModel):
    """Statistiche per una singola porta di rete."""
    # Numero di porta (1–65535)
    port: int
    # Nome del servizio associato (es. "HTTP", "443", "SSH")
    service: str
    # Numero di pacchetti che usano questa porta
    count: int
    # Protocollo di trasporto: "TCP" o "UDP"
    protocol: str


class Conversation(BaseModel):
    """Flusso di comunicazione bidirezionale tra due indirizzi IP."""
    # Primo indirizzo IP della coppia (ordinati lessicograficamente)
    src_ip: str
    # Secondo indirizzo IP della coppia
    dst_ip: str
    # Numero totale di pacchetti scambiati in entrambe le direzioni
    packets: int
    # Volume totale in byte scambiati
    bytes: int
    # Lista dei protocolli osservati in questa conversazione
    protocols: List[str]


class TimelinePoint(BaseModel):
    """Un punto della timeline di traffico, aggregato per intervallo temporale."""
    # Orario del bucket nel formato HH:MM:SS (UTC)
    timestamp: str
    # Numero di pacchetti nel bucket
    packets: int
    # Volume in byte nel bucket
    bytes: int


class LayerField(BaseModel):
    """Singolo campo di un layer protocollare (nome + valore testuale)."""
    name: str
    value: str


class LayerInfo(BaseModel):
    """Un layer protocollare con il suo nome e i suoi campi."""
    name: str          # nome tecnico Scapy, es. "IP", "TCP"
    display: str       # nome human-readable, es. "Internet Protocol v4"
    fields: List[LayerField]


class PacketEntry(BaseModel):
    """Dettagli di un singolo pacchetto dalla lista dei pacchetti."""
    number: int
    timestamp: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: str
    length: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    info: str
    # Dati per l'inspector Wireshark-style
    raw_hex: Optional[str] = None          # byte grezzi come stringa hex
    layers: List[LayerInfo] = Field(default_factory=list)  # albero dei layer protocollari


class AnalysisResult(BaseModel):
    """
    Risultato completo dell'analisi di un file PCAP.

    Questa struttura è l'oggetto radice restituito dall'endpoint
    POST /api/analyze e consumato dal frontend per costruire il dashboard.
    """
    # Nome originale del file caricato dall'utente
    filename: str
    # Riepilogo statistico generale
    summary: SummaryStats
    # Distribuzione dei protocolli (top 20 per frequenza)
    protocols: List[ProtocolEntry]
    # Indirizzi IP più attivi come sorgente (top 20)
    top_src_ips: List[IPEntry]
    # Indirizzi IP più attivi come destinazione (top 20)
    top_dst_ips: List[IPEntry]
    # Porte sorgente più utilizzate (top 15)
    top_src_ports: List[PortEntry]
    # Porte di destinazione più utilizzate (top 15)
    top_dst_ports: List[PortEntry]
    # Conversazioni più attive per volume di dati (top 20)
    conversations: List[Conversation]
    # Andamento del traffico nel tempo
    timeline: List[TimelinePoint]
    # Lista dettagliata dei pacchetti
    packets: List[PacketEntry]
    # Informazioni opzionali ottenute con l'arricchimento esterno manuale
    external_ip_info: Dict[str, IPExternalInfo] = Field(default_factory=dict)

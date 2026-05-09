"""
Modelli data Pydantic per la serializzazione delle responses API.

Ogni classe descrive una sezione del report di analysis restituito
dal backend al frontend. Pydantic garantisce la validazione automatica
dei tipi e la serializzazione JSON.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class SummaryStats(BaseModel):
    """Statistiche generali sulla cattura di packets."""
    # Numero totale di packets presenti nel file
    total_packets: int
    # Volume totale in byte di tutti i packets
    total_bytes: int
    # Timestamp ISO 8601 del primo packet catturato
    capture_start: Optional[str] = None
    # Timestamp ISO 8601 dell'ultimo packet catturato
    capture_end: Optional[str] = None
    # Total duration della cattura in secondi
    duration_seconds: float
    # Dimensione media dei packets in byte
    avg_packet_size: float
    # Numero medio di packets al secondo during the capture
    packets_per_second: float


class ProtocolEntry(BaseModel):
    """Statistiche di utilizzo per un singolo protocol di rete."""
    # Nome del protocol (es. "TCP", "DNS", "HTTP")
    protocol: str
    # Numero di packets che usano questo protocol
    count: int
    # Volume totale in byte per questo protocol
    bytes: int
    # Percentuale sul totale dei packets (0–100)
    percentage: float


class IPExternalInfo(BaseModel):
    """Informazioni ottenute da external services per un indirizzo IP public."""
    # Indirizzo IP arricchito
    ip: str
    # Stato dell'arricchimento: enriched, skipped o error
    status: str
    # Motivo sintetico in caso di skip o error
    reason: Optional[str] = None
    # External services che hanno restituito almeno un dato utile
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
    # Nazione stimata o dichiarata dai external services
    country: Optional[str] = None
    # Codice nazione ISO/RIR
    country_code: Optional[str] = None
    # Regione geografica, se disponibile
    region: Optional[str] = None
    # Estimated city, se disponibile
    city: Optional[str] = None
    # Latitudine stimata
    lat: Optional[float] = None
    # Longitudine stimata
    lon: Optional[float] = None
    # Timezone stimata
    timezone: Optional[str] = None
    # ISP rilevato da services GeoIP
    isp: Optional[str] = None
    # Organizzazione rilevata da services GeoIP/RDAP
    org: Optional[str] = None
    # Mobile indicator returned by the GeoIP service
    mobile: Optional[bool] = None
    # Proxy/VPN indicator returned by the GeoIP service
    proxy: Optional[bool] = None
    # Hosting/datacenter indicator returned by the GeoIP service
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
    # Main entities/contacts exposed by RDAP
    rdap_entities: List[str] = Field(default_factory=list)
    # Note RDAP sintetiche
    rdap_remarks: List[str] = Field(default_factory=list)
    # Errori non bloccanti incontrati sui singoli services
    errors: List[str] = Field(default_factory=list)


class IPEnrichmentRequest(BaseModel):
    """Richiesta di arricchimento external per una lista di IP."""
    # Lista di IP addresses estratti dal report PCAP
    ips: List[str]


class IPEnrichmentResponse(BaseModel):
    """Risposta dell'arricchimento external indicizzata per indirizzo IP."""
    # IP map -> retrieved external information
    results: Dict[str, IPExternalInfo]


class SecurityPacketObservation(BaseModel):
    """Pacchetto compatto inviato alla pipeline di sicurezza advanced."""
    # Numero progressivo del packet nel PCAP
    number: int
    # Timestamp showsto dal frontend
    timestamp: str
    # Source IP, se disponibile
    src_ip: Optional[str] = None
    # Destination IP, se disponibile
    dst_ip: Optional[str] = None
    # Protocol rilevato dal parser
    protocol: str
    # Lunghezza del packet in byte
    length: int
    # Porta source TCP/UDP, se disponibile
    src_port: Optional[int] = None
    # Porta destination TCP/UDP, se disponibile
    dst_port: Optional[int] = None
    # Campo informativo sintetico del packet
    info: str


class SecurityAnalysisRequest(BaseModel):
    """Richiesta per l'analysis di sicurezza advanced opt-in."""
    # Packets da analizzare; il frontend invia l'intero traffico disponibile.
    packets: List[SecurityPacketObservation]
    # Informazioni IP ottenute in precedenza con "Analyze with external tools".
    external_ip_info: Dict[str, IPExternalInfo] = Field(default_factory=dict)
    # Limite massimo di IP pubblici interrogati sui services di threat intelligence.
    max_ips: int = 80


class SecuritySourceStatus(BaseModel):
    """Stato di una fonte esterna usata durante l'analysis di sicurezza."""
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
    # Sources supporting the finding
    sources: List[str] = Field(default_factory=list)
    # Confidenza stimata 0-100
    confidence: int
    # Score tecnico 0-100
    score: int
    # Riferimenti MITRE ATT&CK quando applicabili
    mitre: List[str] = Field(default_factory=list)


class SecurityIPAssessmentModel(BaseModel):
    """Valutazione aggregata per singolo indirizzo IP public."""
    # Indirizzo IP valutato
    ip: str
    # Score massimo/aggregato del rischio per IP
    risk_score: int
    # Severita derivata dallo score
    severity: str
    # Numero packets in cui l'IP compare
    packets: int
    # Byte inviati dall'IP verso altri host
    bytes_out: int
    # Byte ricevuti dall'IP da altri host
    bytes_in: int
    # Ports osservate in relazione all'IP
    ports: List[int] = Field(default_factory=list)
    # Protocols osservati
    protocols: List[str] = Field(default_factory=list)
    # Numero di peer distinti
    peer_count: int
    # Country stimato dall'arricchimento precedente
    country: Optional[str] = None
    # ASN stimato dall'arricchimento precedente
    asn: Optional[str] = None
    # Nome AS/organizzazione
    as_name: Optional[str] = None
    # External tags, for example Shodan InternetDB
    tags: List[str] = Field(default_factory=list)
    # CVE o vulnerabilita associate all'IP secondo fonti esterne
    vulnerabilities: List[str] = Field(default_factory=list)
    # ID dei finding associati
    findings: List[str] = Field(default_factory=list)


class SecurityAnalysisSummary(BaseModel):
    """Riepilogo numerico dell'analysis di sicurezza advanced."""
    # IP totali estratti dai packets
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
    """Risposta completa dell'analysis di sicurezza advanced."""
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


class DNSReputationRequest(BaseModel):
    """Richiesta opt-in per controllare domains DNS su liste esterne."""
    # Domains osservati nelle query DNS del PCAP
    domains: List[str]
    # Numero massimo di domains da confrontare con services e liste esterne
    max_domains: int = 250


class DNSDomainIntel(BaseModel):
    """Risultato di reputazione esterna per un singolo domainso."""
    # Domainso normalizzato
    domain: str
    # Stato: clean, listed o unknown
    status: str
    # Categorie assegnate dalle fonti o dal motore
    categories: List[str] = Field(default_factory=list)
    # Fonti che hanno prodotto un match
    sources: List[str] = Field(default_factory=list)
    # Rules or concise match details
    matched_rules: List[str] = Field(default_factory=list)
    # Score external 0-100
    score: int = 0


class DNSReputationResponse(BaseModel):
    """Risposta dell'analysis DNS esterna opt-in."""
    # Domain map -> reputation
    results: Dict[str, DNSDomainIntel]
    # Stato operativo delle fonti usate
    sources: List[SecuritySourceStatus]
    # Errori non bloccanti incontrati durante download/query
    errors: List[str] = Field(default_factory=list)


class DNSAnswerEntry(BaseModel):
    """Risposta DNS singola estratta da un record answer."""
    # Nome del record di risposta
    name: str
    # Tipo record leggibile, es. A, AAAA, CNAME, TXT
    record_type: str
    # Valore of the response: IP, nome canonico, testo TXT...
    value: str
    # TTL del record, se disponibile
    ttl: Optional[int] = None


class DNSQueryEntry(BaseModel):
    """Query DNS arricchita con eventuale correlated response."""
    # Numero packet della query
    packet_number: int
    # Timestamp ISO 8601 della query
    timestamp: str
    # IP client che ha inviato la query
    client: Optional[str] = None
    # IP resolver interrogato
    resolver: Optional[str] = None
    # Transaction ID DNS
    transaction_id: Optional[int] = None
    # Domainso richiesto
    query: str
    # Tipo record richiesto
    record_type: str
    # Codice risposta numerico, se e stata vista una risposta
    response_code: Optional[int] = None
    # Codice risposta leggibile, es. NOERROR, NXDOMAIN, SERVFAIL
    response_code_name: Optional[str] = None
    # Numero packet della correlated response
    response_packet_number: Optional[int] = None
    # Responses DNS associate alla query
    answers: List[DNSAnswerEntry] = Field(default_factory=list)
    # TTL osservati nelle responses
    ttls: List[int] = Field(default_factory=list)
    # IP estratti da responses A/AAAA
    answer_ips: List[str] = Field(default_factory=list)
    # Valori TXT estratti dalle responses
    txt_answers: List[str] = Field(default_factory=list)
    # Flag locale per evidenziare query TXT sospette
    suspicious_txt: bool = False
    # Motivi euristici associati alla query
    indicators: List[str] = Field(default_factory=list)


class DNSTopEntry(BaseModel):
    """Contatore DNS aggregato per domains, client o resolver."""
    # Valore aggregato
    value: str
    # Numero occorrenze
    count: int


class DNSTunnelingIndicator(BaseModel):
    """Indicatore euristico di possibile DNS tunneling."""
    # Domainso/base domain osservato
    domain: str
    # Score euristico 0-100
    score: int
    # Numero query verso questo domainso/base
    query_count: int
    # Number of unique subdomains observed
    unique_subdomains: int
    # Lunghezza massima di una label osservata
    max_label_length: int
    # Entropia massima approssimata osservata sulle label
    max_entropy: float
    # Motivi che hanno contribuito allo score
    reasons: List[str] = Field(default_factory=list)


class DNSFlowCorrelation(BaseModel):
    """Domain -> answer IP -> subsequent flow correlation."""
    # Domainso richiesto
    domain: str
    # IP restituito da DNS
    answer_ip: str
    # Flow 5-tuple successivi che coinvolgono l'IP
    flow_ids: List[str] = Field(default_factory=list)
    # Numeri dei packets DNS source
    dns_packet_numbers: List[int] = Field(default_factory=list)


class DNSStats(BaseModel):
    """Statistiche principali dell'analysis DNS locale."""
    # Numero totale di query DNS osservate
    total_queries: int
    # Numero totale di responses DNS osservate
    total_responses: int
    # Domains unici richiesti
    unique_domains: int
    # Numero responses NXDOMAIN
    nxdomain_count: int
    # Rapporto NXDOMAIN / responses
    nxdomain_ratio: float
    # Query TXT totali
    txt_query_count: int
    # Query TXT considerate sospette
    suspicious_txt_count: int


class DNSAnalysisResult(BaseModel):
    """Risultato completo dell'analysis DNS locale privacy-by-default."""
    # Riepilogo numerico
    stats: DNSStats
    # Query DNS con responses correlate quando disponibili
    queries: List[DNSQueryEntry] = Field(default_factory=list)
    # Most requested domains
    top_domains: List[DNSTopEntry] = Field(default_factory=list)
    # Most active DNS clients
    top_clients: List[DNSTopEntry] = Field(default_factory=list)
    # Most used resolvers
    top_resolvers: List[DNSTopEntry] = Field(default_factory=list)
    # Indicators di possibile DNS tunneling
    tunneling_indicators: List[DNSTunnelingIndicator] = Field(default_factory=list)
    # Domain -> answer IP -> subsequent flow correlations
    flow_correlations: List[DNSFlowCorrelation] = Field(default_factory=list)


class HTTPRequestEntry(BaseModel):
    """Cleartext HTTP request with optional correlated response."""
    # Numero packet della HTTP request
    packet_number: int
    # Timestamp ISO 8601 della richiesta
    timestamp: str
    # IP client
    client_ip: Optional[str] = None
    # Porta client
    client_port: Optional[int] = None
    # IP server
    server_ip: Optional[str] = None
    # Porta server
    server_port: Optional[int] = None
    # Metodo HTTP, es. GET, POST, PUT
    method: str
    # Host HTTP, se presente
    host: Optional[str] = None
    # URI/path richiesto
    uri: str
    # Header User-Agent, se presente
    user_agent: Optional[str] = None
    # Header Referer/Referrer, se presente
    referer: Optional[str] = None
    # Content-Type della richiesta, se presente
    content_type: Optional[str] = None
    # Dimensione payload richiesta dedotta da Content-Length o dal segmento
    payload_size: Optional[int] = None
    # True se gli header sembrano incompleti nel segmento osservato
    partial: bool = False
    # Numero packet della correlated response
    response_packet_number: Optional[int] = None
    # Status code HTTP of the response
    response_status_code: Optional[int] = None
    # Reason phrase HTTP of the response
    response_reason: Optional[str] = None
    # Header Server of the response
    response_server: Optional[str] = None
    # Content-Type of the response
    response_content_type: Optional[str] = None
    # Content-Length of the response
    response_content_length: Optional[int] = None
    # File name dedotto da URI o Content-Disposition
    response_file_name: Optional[str] = None
    # True se the response was parsed da header incompleti
    response_partial: bool = False


class HTTPTopEntry(BaseModel):
    """Contatore aggregato HTTP."""
    # Valore aggregato, ad esempio host o user-agent
    value: str
    # Numero occorrenze
    count: int


class HTTPStats(BaseModel):
    """Statistiche principali dell'analysis HTTP in chiaro."""
    # Requests HTTP osservate
    total_requests: int
    # Responses HTTP osservate
    total_responses: int
    # Requests con correlated response
    correlated_responses: int
    # Requests parziali/incomplete
    partial_requests: int
    # Responses parziali/incomplete
    partial_responses: int
    # Unique hosts observed
    unique_hosts: int


class HTTPAnalysisResult(BaseModel):
    """Risultato completo dell'analysis HTTP in chiaro."""
    # Riepilogo numerico
    stats: HTTPStats
    # Requests HTTP, arricchite con correlated response quando possibile
    requests: List[HTTPRequestEntry] = Field(default_factory=list)
    # Most contacted hosts
    top_hosts: List[HTTPTopEntry] = Field(default_factory=list)
    # Most frequent User-Agents
    top_user_agents: List[HTTPTopEntry] = Field(default_factory=list)
    # Limiti noti del parser, showsbili in README/UI
    limitations: List[str] = Field(default_factory=list)


class TLSEntry(BaseModel):
    """Connessione TLS ricostruita dai soli metadata osservabili."""
    # Numero packet del primo ClientHello osservato, se disponibile
    packet_number: int
    # Timestamp ISO 8601 del primo handshake osservato
    timestamp: str
    # IP client
    client_ip: Optional[str] = None
    # Porta client
    client_port: Optional[int] = None
    # IP server
    server_ip: Optional[str] = None
    # Porta server
    server_port: Optional[int] = None
    # Server Name Indication estratto dal ClientHello
    sni: Optional[str] = None
    # Versione TLS negoziata o stimata dagli handshake osservati
    tls_version: Optional[str] = None
    # Cipher suite negoziata, quando deducibile dal ServerHello
    cipher_suite: Optional[str] = None
    # Protocols ALPN annunciati o negoziati
    alpn: List[str] = Field(default_factory=list)
    # Subject del certificato leaf
    cert_subject: Optional[str] = None
    # Issuer del certificato leaf
    cert_issuer: Optional[str] = None
    # Inizio validita certificato
    cert_not_before: Optional[str] = None
    # Fine validita certificato
    cert_not_after: Optional[str] = None
    # Fingerprint SHA256 del certificato DER
    cert_sha256: Optional[str] = None
    # Fingerprint JA3 del ClientHello, se calcolabile
    ja3: Optional[str] = None
    # Stringa JA3 normalizzata usata per il fingerprint
    ja3_string: Optional[str] = None
    # Fingerprint JA3S del ServerHello, se calcolabile
    ja3s: Optional[str] = None
    # Stringa JA3S normalizzata usata per il fingerprint
    ja3s_string: Optional[str] = None
    # Anomalie dedotte dai metadata visibili
    anomalies: List[str] = Field(default_factory=list)
    # True se uno o most record TLS erano incompleti nel segmento osservato
    partial: bool = False


class TLSStats(BaseModel):
    """Statistiche principali dell'analysis TLS."""
    # Connessioni TLS osservate
    total_connections: int
    # Connessioni con SNI disponibile
    with_sni: int
    # Connessioni con certificato osservato
    with_certificate: int
    # Connessioni con almeno una anomalia
    anomalous_connections: int
    # Certificates expired relative to the capture timestamp
    expired_certificates: int
    # Connessioni che usano TLS vecchio o legacy
    legacy_tls: int


class TLSTopEntry(BaseModel):
    """Contatore aggregato TLS."""
    # Valore aggregato, ad esempio SNI, issuer o versione
    value: str
    # Numero occorrenze
    count: int


class TLSAnalysisResult(BaseModel):
    """Risultato completo dell'analysis TLS basata su metadata osservabili."""
    # Riepilogo numerico
    stats: TLSStats
    # Connessioni TLS ricostruite dal handshake
    connections: List[TLSEntry] = Field(default_factory=list)
    # Most frequent SNI
    top_sni: List[TLSTopEntry] = Field(default_factory=list)
    # Most frequent certificate issuers
    top_issuers: List[TLSTopEntry] = Field(default_factory=list)
    # Versioni TLS osservate
    top_versions: List[TLSTopEntry] = Field(default_factory=list)
    # Limiti noti del parser, showsbili in README/UI
    limitations: List[str] = Field(default_factory=list)


class HostTimelinePoint(BaseModel):
    """Punto temporale di attivita per un singolo host."""
    # Orario del bucket nel format HH:MM:SS UTC
    timestamp: str
    # Packets inviati dall'host nel bucket
    packets_sent: int
    # Packets ricevuti dall'host nel bucket
    packets_received: int
    # Byte inviati dall'host nel bucket
    bytes_sent: int
    # Byte ricevuti dall'host nel bucket
    bytes_received: int


class HostEntry(BaseModel):
    """Profilo aggregato di un host/IP osservato nel PCAP."""
    # Indirizzo IP dell'host
    ip: str
    # Ruolo stimato: client, server, misto o ignoto
    role: str
    # True se l'indirizzo appartiene a range privati/locali/riservati
    is_private: bool
    # Hostname dedotti da DNS osservato nel PCAP
    hostnames: List[str] = Field(default_factory=list)
    # Protocols osservati per l'host
    protocols: List[str] = Field(default_factory=list)
    # Ports remote contattate dall'host come client
    contacted_ports: List[int] = Field(default_factory=list)
    # Ports locali osservate come lato server/destination del flow
    exposed_ports: List[int] = Field(default_factory=list)
    # Byte inviati dall'host
    bytes_sent: int = 0
    # Byte ricevuti dall'host
    bytes_received: int = 0
    # Packets inviati dall'host
    packets_sent: int = 0
    # Packets ricevuti dall'host
    packets_received: int = 0
    # Identificativi dei flow collegati
    flow_ids: List[str] = Field(default_factory=list)
    # Query DNS generate dall'host
    dns_queries: List[str] = Field(default_factory=list)
    # Observed SNI in sessioni TLS dell'host
    sni_hosts: List[str] = Field(default_factory=list)
    # Cleartext HTTP hosts observed
    http_hosts: List[str] = Field(default_factory=list)
    # Finding o note operative associate all'host
    findings: List[str] = Field(default_factory=list)
    # Timeline compatta dell'attivita dell'host
    timeline: List[HostTimelinePoint] = Field(default_factory=list)


class HostAnalysisResult(BaseModel):
    """Risultato aggregato della vista Hosts."""
    # Numero observed hosts
    total_hosts: int
    # Profili host ordinati per volume totale
    hosts: List[HostEntry] = Field(default_factory=list)


class IPServiceEntry(BaseModel):
    """Servizio osservato in associazione a un indirizzo IP."""
    # Nome del service dedotto da port/protocol (es. "HTTPS", "DNS")
    service: str
    # Porta TCP/UDP osservata, se disponibile
    port: Optional[int] = None
    # Protocol di trasporto o rete (TCP, UDP, ICMP, ARP...)
    protocol: str
    # IP role for the service: client, server, or endpoint
    direction: str
    # Number of observed packets per questa associazione
    count: int
    # Most frequent remote peers observed with this service
    peers: List[str]


class IPEntry(BaseModel):
    """Statistiche per un singolo indirizzo IP (source o destination)."""
    # Indirizzo IP in notazione dotted-decimal o IPv6
    ip: str
    # Numero di packets inviati/ricevuti da questo indirizzo
    count: int
    # Volume totale in byte inviati/ricevuti
    bytes: int
    # Protocols osservati per questo IP
    protocols: List[str] = Field(default_factory=list)
    # Observed DNS names nel PCAP per questo indirizzo
    hostnames: List[str] = Field(default_factory=list)
    # Peer remoti most frequenti
    peers: List[str] = Field(default_factory=list)
    # Services inferred from observed ports and protocols
    services: List[IPServiceEntry] = Field(default_factory=list)
    # Informazioni opzionali ottenute interrogando external services
    external: Optional[IPExternalInfo] = None


class PortEntry(BaseModel):
    """Statistiche per una singola port di rete."""
    # Numero di port (1–65535)
    port: int
    # Associated service name (for example "HTTP", "443", "SSH")
    service: str
    # Numero di packets che usano questa port
    count: int
    # Protocol di trasporto: "TCP" o "UDP"
    protocol: str


class Conversation(BaseModel):
    """Flusso di comunicazione bidirezionale tra due IP addresses."""
    # Primo indirizzo IP della coppia (ordinati lessicograficamente)
    src_ip: str
    # Secondo indirizzo IP della coppia
    dst_ip: str
    # Numero totale di packets scambiati in entrambe le direzioni
    packets: int
    # Volume totale in byte scambiati
    bytes: int
    # List of protocols observed in this conversation
    protocols: List[str]


class FlowEntry(BaseModel):
    """Flow 5-tuple bidirezionale ricostruito dal backend."""
    # Identificativo stabile generato dal 5-tuple direzionale iniziale
    flow_id: str
    # Source IP del flow, considerato lato client/primo mittente osservato
    src_ip: str
    # Porta source del flow
    src_port: Optional[int] = None
    # Destination IP del flow, considerato lato server/primo destinatario osservato
    dst_ip: str
    # Porta destination del flow
    dst_port: Optional[int] = None
    # Protocol L4 del flow (TCP o UDP)
    protocol: str
    # Timestamp ISO 8601 del primo packet osservato
    first_seen: str
    # Timestamp ISO 8601 dell'ultimo packet osservato
    last_seen: str
    # Duration del flow in secondi
    duration_seconds: float
    # Numero totale di packets nel flow
    packets_total: int
    # Byte totali nel flow
    bytes_total: int
    # Packets nel verso client -> server
    packets_client_to_server: int
    # Packets nel verso server -> client
    packets_server_to_client: int
    # Byte nel verso client -> server
    bytes_client_to_server: int
    # Byte nel verso server -> client
    bytes_server_to_client: int
    # Flag TCP aggregati, vuoto per UDP
    tcp_flags: List[str] = Field(default_factory=list)
    # Stato approssimativo dedotto dai flag/direzionalita
    state: str
    # Numeri dei packets appartenenti al flow, usati dalla tab Advanced traces
    packet_numbers: List[int] = Field(default_factory=list)


class TimelinePoint(BaseModel):
    """Un punto della timeline di traffico, aggregato per intervallo temporale."""
    # Orario del bucket nel format HH:MM:SS (UTC)
    timestamp: str
    # Numero di packets nel bucket
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
    """Dettagli di un singolo packet dalla lista dei packets."""
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
    Risultato completo dell'analysis di un file PCAP.

    Questa struttura is l'oggetto radice restituito dall'endpoint
    POST /api/analyze e consumato dal frontend per costruire il dashboard.
    """
    # Original name of the file uploaded by the user
    filename: str
    # Riepilogo statistico generale
    summary: SummaryStats
    # Protocol distribution (top 20 by frequency)
    protocols: List[ProtocolEntry]
    # Most active source IP addresses (top 20)
    top_src_ips: List[IPEntry]
    # Most active destination IP addresses (top 20)
    top_dst_ips: List[IPEntry]
    # Ports source most used (top 15)
    top_src_ports: List[PortEntry]
    # Ports di destination most used (top 15)
    top_dst_ports: List[PortEntry]
    # Conversazioni most attive per volume di data (top 20)
    conversations: List[Conversation]
    # Flow 5-tuple ricostruiti in backend
    flows: List[FlowEntry] = Field(default_factory=list)
    # Analysis DNS locale privacy-by-default
    dns: Optional[DNSAnalysisResult] = None
    # Analysis HTTP in chiaro privacy-by-default
    http: Optional[HTTPAnalysisResult] = None
    # Analysis TLS basata sui metadata osservabili del handshake
    tls: Optional[TLSAnalysisResult] = None
    # Vista host/IP aggregata
    hosts: Optional[HostAnalysisResult] = None
    # Traffic trend over time
    timeline: List[TimelinePoint]
    # Lista detailsata dei packets
    packets: List[PacketEntry]
    # Informazioni opzionali ottenute con l'arricchimento external manuale
    external_ip_info: Dict[str, IPExternalInfo] = Field(default_factory=dict)

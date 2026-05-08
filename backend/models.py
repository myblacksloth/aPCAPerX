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

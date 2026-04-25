"""
Modelli dati Pydantic per la serializzazione delle risposte API.

Ogni classe descrive una sezione del report di analisi restituito
dal backend al frontend. Pydantic garantisce la validazione automatica
dei tipi e la serializzazione JSON.
"""

from typing import List, Optional
from pydantic import BaseModel


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


class IPEntry(BaseModel):
    """Statistiche per un singolo indirizzo IP (sorgente o destinazione)."""
    # Indirizzo IP in notazione dotted-decimal o IPv6
    ip: str
    # Numero di pacchetti inviati/ricevuti da questo indirizzo
    count: int
    # Volume totale in byte inviati/ricevuti
    bytes: int


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


class PacketEntry(BaseModel):
    """Dettagli di un singolo pacchetto dalla lista dei primi N pacchetti."""
    # Numero progressivo del pacchetto nel file (parte da 1)
    number: int
    # Orario di cattura del pacchetto nel formato HH:MM:SS.mmm
    timestamp: str
    # Indirizzo IP sorgente (None per pacchetti non-IP come STP)
    src_ip: Optional[str] = None
    # Indirizzo IP destinatario
    dst_ip: Optional[str] = None
    # Protocollo di più alto livello rilevato
    protocol: str
    # Lunghezza totale del pacchetto in byte
    length: int
    # Porta sorgente (None per protocolli non TCP/UDP)
    src_port: Optional[int] = None
    # Porta di destinazione
    dst_port: Optional[int] = None
    # Stringa informativa sul contenuto del pacchetto (stile Wireshark)
    info: str


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
    # Elenco dettagliato dei primi 1000 pacchetti
    packets: List[PacketEntry]

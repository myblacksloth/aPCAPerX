/**
 * Definizioni dei tipi TypeScript per le risposte API.
 *
 * Questi tipi rispecchiano esattamente i modelli Pydantic definiti nel backend
 * (backend/models.py). Qualsiasi modifica ai modelli Python deve essere
 * riportata qui per mantenere la coerenza tra frontend e backend.
 */

/** Statistiche generali sull'intera cattura */
export interface SummaryStats {
  /** Numero totale di pacchetti nel file PCAP */
  total_packets: number
  /** Volume totale in byte di tutti i pacchetti */
  total_bytes: number
  /** Timestamp ISO 8601 del primo pacchetto (null se non disponibile) */
  capture_start: string | null
  /** Timestamp ISO 8601 dell'ultimo pacchetto */
  capture_end: string | null
  /** Durata totale della cattura in secondi */
  duration_seconds: number
  /** Dimensione media dei pacchetti in byte */
  avg_packet_size: number
  /** Numero medio di pacchetti al secondo */
  packets_per_second: number
}

/** Statistiche per un singolo protocollo di rete */
export interface ProtocolEntry {
  /** Nome del protocollo (es. "TCP", "DNS", "HTTPS") */
  protocol: string
  /** Numero di pacchetti che utilizzano questo protocollo */
  count: number
  /** Volume totale in byte per questo protocollo */
  bytes: number
  /** Percentuale sul totale dei pacchetti (0–100) */
  percentage: number
}

/** Statistiche per un singolo indirizzo IP */
export interface IPEntry {
  /** Indirizzo IP in formato stringa (IPv4 o IPv6) */
  ip: string
  /** Numero di pacchetti associati a questo indirizzo */
  count: number
  /** Volume totale in byte associato a questo indirizzo */
  bytes: number
}

/** Statistiche per una singola porta di rete */
export interface PortEntry {
  /** Numero di porta (1–65535) */
  port: number
  /** Nome del servizio (es. "HTTP", "SSH") o numero porta come stringa */
  service: string
  /** Numero di pacchetti che usano questa porta */
  count: number
  /** Protocollo di trasporto: "TCP" o "UDP" */
  protocol: string
}

/** Flusso di comunicazione bidirezionale tra due indirizzi IP */
export interface Conversation {
  /** Primo IP della coppia (ordinati lessicograficamente) */
  src_ip: string
  /** Secondo IP della coppia */
  dst_ip: string
  /** Numero totale di pacchetti scambiati */
  packets: number
  /** Volume totale in byte scambiati */
  bytes: number
  /** Protocolli osservati in questa conversazione */
  protocols: string[]
}

/** Un punto della timeline di traffico */
export interface TimelinePoint {
  /** Orario nel formato HH:MM:SS (UTC) */
  timestamp: string
  /** Numero di pacchetti nel bucket temporale */
  packets: number
  /** Volume in byte nel bucket temporale */
  bytes: number
}

/** Campo singolo di un layer protocollare */
export interface LayerField {
  name: string
  value: string
}

/** Layer protocollare con i suoi campi */
export interface LayerInfo {
  /** Nome tecnico Scapy (es. "TCP") */
  name: string
  /** Nome leggibile (es. "Transmission Control Protocol") */
  display: string
  fields: LayerField[]
}

/** Dettagli di un singolo pacchetto */
export interface PacketEntry {
  number: number
  timestamp: string
  src_ip: string | null
  dst_ip: string | null
  protocol: string
  length: number
  src_port: number | null
  dst_port: number | null
  info: string
  /** Byte grezzi del pacchetto come stringa esadecimale */
  raw_hex: string | null
  /** Stack protocollare completo per l'inspector Wireshark-style */
  layers: LayerInfo[]
}

/** Risultato completo dell'analisi di un file PCAP — oggetto radice */
export interface AnalysisResult {
  /** Nome originale del file caricato */
  filename: string
  /** Statistiche generali della cattura */
  summary: SummaryStats
  /** Distribuzione dei protocolli (top 20) */
  protocols: ProtocolEntry[]
  /** Indirizzi IP più attivi come sorgente (top 20) */
  top_src_ips: IPEntry[]
  /** Indirizzi IP più attivi come destinazione (top 20) */
  top_dst_ips: IPEntry[]
  /** Porte sorgente più utilizzate (top 15) */
  top_src_ports: PortEntry[]
  /** Porte di destinazione più utilizzate (top 15) */
  top_dst_ports: PortEntry[]
  /** Conversazioni bidirezionali più attive (top 20) */
  conversations: Conversation[]
  /** Andamento del traffico nel tempo */
  timeline: TimelinePoint[]
  /** Lista dettagliata dei primi 1000 pacchetti */
  packets: PacketEntry[]
}

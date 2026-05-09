/**
 * Definizioni dei tipi TypeScript per le responses API.
 *
 * Questi tipi rispecchiano esattamente i modelli Pydantic definiti nel backend
 * (backend/models.py). Qualsiasi modifica ai modelli Python deve essere
 * riportta qui per mantenere la coerenza tra frontend e backend.
 */

/** General statistics for the whole capture */
export interface SummaryStats {
  /** Numero totale di packets nel file PCAP */
  total_packets: number
  /** Volume totale in byte di tutti i packets */
  total_bytes: number
  /** Timestamp ISO 8601 del primo packet (null se not available) */
  capture_start: string | null
  /** Timestamp ISO 8601 dell'ultimo packet */
  capture_end: string | null
  /** Total duration della cattura in secondi */
  duration_seconds: number
  /** Dimensione media dei packets in byte */
  avg_packet_size: number
  /** Numero medio di packets al secondo */
  packets_per_second: number
}

/** Statistiche per un singolo protocol di rete */
export interface ProtocolEntry {
  /** Nome del protocol (es. "TCP", "DNS", "HTTPS") */
  protocol: string
  /** Numero di packets che utilizzano questo protocol */
  count: number
  /** Volume totale in byte per questo protocol */
  bytes: number
  /** Percentuale sul totale dei packets (0–100) */
  percentage: number
}

/** Statistiche per un singolo indirizzo IP */
export interface IPExternalInfo {
  /** Indirizzo IP arricchito */
  ip: string
  /** Stato dell'arricchimento: enriched, skipped o error */
  status: string
  /** Motivo sintetico in caso di skip o error */
  reason: string | null
  /** External services that returned useful data */
  sources: string[]
  /** Nome reverse DNS ottenuto tramite PTR */
  reverse_dns: string | null
  /** Autonomous System Number */
  asn: string | null
  /** Nome/descrizione dell'Autonomous System */
  as_name: string | null
  /** Prefisso BGP associato all'indirizzo */
  bgp_prefix: string | null
  /** Registry RIR o fonte di assegnazione */
  registry: string | null
  /** Data di allocazione del prefisso */
  allocated: string | null
  /** Nazione stimata o dichiarata */
  country: string | null
  /** Codice nazione */
  country_code: string | null
  /** Regione geografica */
  region: string | null
  /** Estimated city */
  city: string | null
  /** Latitudine stimata */
  lat: number | null
  /** Longitudine stimata */
  lon: number | null
  /** Timezone stimata */
  timezone: string | null
  /** ISP rilevato */
  isp: string | null
  /** Organizzazione rilevata */
  org: string | null
  /** Indicatore mobile */
  mobile: boolean | null
  /** Indicatore proxy/VPN */
  proxy: boolean | null
  /** Indicatore hosting/datacenter */
  hosting: boolean | null
  /** Handle RDAP della risorsa IP */
  rdap_handle: string | null
  /** Nome RDAP della risorsa IP */
  rdap_name: string | null
  /** Tipo RDAP della risorsa IP */
  rdap_type: string | null
  /** Inizio range RDAP */
  rdap_start_address: string | null
  /** Fine range RDAP */
  rdap_end_address: string | null
  /** Main entities/contacts exposed by RDAP */
  rdap_entities: string[]
  /** Note RDAP sintetiche */
  rdap_remarks: string[]
  /** Non-blocking errors encountered on external services */
  errors: string[]
}

/** Risposta dell'arricchimento external IP */
export interface IPEnrichmentResponse {
  /** IP map -> retrieved external data */
  results: Record<string, IPExternalInfo>
}

/** Pacchetto compatto inviato alla tab Advanced Security */
export interface SecurityPacketObservation {
  number: number
  timestamp: string
  src_ip: string | null
  dst_ip: string | null
  protocol: string
  length: number
  src_port: number | null
  dst_port: number | null
  info: string
}

/** State of a source used in Security analysis */
export interface SecuritySourceStatus {
  source: string
  status: 'ok' | 'partial' | 'skipped' | 'error' | string
  detail: string
}

/** Finding prodotto dal motore Security avanzato */
export interface SecurityFinding {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string
  category: string
  title: string
  description: string
  ip: string | null
  related_ips: string[]
  evidence: string[]
  recommendation: string
  sources: string[]
  confidence: number
  score: number
  mitre: string[]
}

/** Valutazione aggregata di un singolo IP */
export interface SecurityIPAssessment {
  ip: string
  risk_score: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string
  packets: number
  bytes_out: number
  bytes_in: number
  ports: number[]
  protocols: string[]
  peer_count: number
  country: string | null
  asn: string | null
  as_name: string | null
  tags: string[]
  vulnerabilities: string[]
  findings: string[]
}

/** Riepilogo numerico dell'analysis Advanced Security */
export interface SecurityAnalysisSummary {
  total_ips: number
  analyzed_public_ips: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  total_findings: number
}

/** Risposta completa dell'endpoint /api/security-analysis */
export interface SecurityAnalysisResponse {
  summary: SecurityAnalysisSummary
  findings: SecurityFinding[]
  ip_assessments: SecurityIPAssessment[]
  sources: SecuritySourceStatus[]
  errors: string[]
}

/** Reputazione esterna per un domainso DNS */
export interface DNSDomainIntel {
  domain: string
  status: 'clean' | 'listed' | 'unknown' | string
  categories: string[]
  sources: string[]
  matched_rules: string[]
  score: number
}

/** Risposta dell'endpoint /api/dns-reputation */
export interface DNSReputationResponse {
  results: Record<string, DNSDomainIntel>
  sources: SecuritySourceStatus[]
  errors: string[]
}

/** Risposta DNS singola estratta dal backend */
export interface DNSAnswerEntry {
  name: string
  record_type: string
  value: string
  ttl: number | null
}

/** Query DNS locale con correlated response quando disponibile */
export interface DNSQueryEntry {
  packet_number: number
  timestamp: string
  client: string | null
  resolver: string | null
  transaction_id: number | null
  query: string
  record_type: string
  response_code: number | null
  response_code_name: string | null
  response_packet_number: number | null
  answers: DNSAnswerEntry[]
  ttls: number[]
  answer_ips: string[]
  txt_answers: string[]
  suspicious_txt: boolean
  indicators: string[]
}

/** Contatore aggregato DNS */
export interface DNSTopEntry {
  value: string
  count: number
}

/** Indicatore euristico di possibile DNS tunneling */
export interface DNSTunnelingIndicator {
  domain: string
  score: number
  query_count: number
  unique_subdomains: number
  max_label_length: number
  max_entropy: number
  reasons: string[]
}

/** Correlazione domainso -> IP risposta -> flow successivi */
export interface DNSFlowCorrelation {
  domain: string
  answer_ip: string
  flow_ids: string[]
  dns_packet_numbers: number[]
}

/** Statistiche principali DNS */
export interface DNSStats {
  total_queries: number
  total_responses: number
  unique_domains: number
  nxdomain_count: number
  nxdomain_ratio: number
  txt_query_count: number
  suspicious_txt_count: number
}

/** Analysis DNS locale privacy-by-default */
export interface DNSAnalysisResult {
  stats: DNSStats
  queries: DNSQueryEntry[]
  top_domains: DNSTopEntry[]
  top_clients: DNSTopEntry[]
  top_resolvers: DNSTopEntry[]
  tunneling_indicators: DNSTunnelingIndicator[]
  flow_correlations: DNSFlowCorrelation[]
}

/** Richiesta HTTP in chiaro con correlated response quando disponibile */
export interface HTTPRequestEntry {
  packet_number: number
  timestamp: string
  client_ip: string | null
  client_port: number | null
  server_ip: string | null
  server_port: number | null
  method: string
  host: string | null
  uri: string
  user_agent: string | null
  referer: string | null
  content_type: string | null
  payload_size: number | null
  partial: boolean
  response_packet_number: number | null
  response_status_code: number | null
  response_reason: string | null
  response_server: string | null
  response_content_type: string | null
  response_content_length: number | null
  response_file_name: string | null
  response_partial: boolean
}

/** Contatore aggregato HTTP */
export interface HTTPTopEntry {
  value: string
  count: number
}

/** Statistiche principali HTTP */
export interface HTTPStats {
  total_requests: number
  total_responses: number
  correlated_responses: number
  partial_requests: number
  partial_responses: number
  unique_hosts: number
}

/** Analysis HTTP in chiaro privacy-by-default */
export interface HTTPAnalysisResult {
  stats: HTTPStats
  requests: HTTPRequestEntry[]
  top_hosts: HTTPTopEntry[]
  top_user_agents: HTTPTopEntry[]
  limitations: string[]
}

/** Connessione TLS ricostruita dai soli metadata osservabili */
export interface TLSEntry {
  packet_number: number
  timestamp: string
  client_ip: string | null
  client_port: number | null
  server_ip: string | null
  server_port: number | null
  sni: string | null
  tls_version: string | null
  cipher_suite: string | null
  alpn: string[]
  cert_subject: string | null
  cert_issuer: string | null
  cert_not_before: string | null
  cert_not_after: string | null
  cert_sha256: string | null
  ja3: string | null
  ja3_string: string | null
  ja3s: string | null
  ja3s_string: string | null
  anomalies: string[]
  partial: boolean
}

/** Statistiche principali TLS */
export interface TLSStats {
  total_connections: number
  with_sni: number
  with_certificate: number
  anomalous_connections: number
  expired_certificates: number
  legacy_tls: number
}

/** Contatore aggregato TLS */
export interface TLSTopEntry {
  value: string
  count: number
}

/** Analysis TLS privacy-by-default basata su handshake osservabili */
export interface TLSAnalysisResult {
  stats: TLSStats
  connections: TLSEntry[]
  top_sni: TLSTopEntry[]
  top_issuers: TLSTopEntry[]
  top_versions: TLSTopEntry[]
  limitations: string[]
}

/** Host activity time point */
export interface HostTimelinePoint {
  timestamp: string
  packets_sent: number
  packets_received: number
  bytes_sent: number
  bytes_received: number
}

/** Profilo aggregato di un host/IP osservato nel PCAP */
export interface HostEntry {
  ip: string
  role: 'client' | 'server' | 'misto' | 'ignoto' | string
  is_private: boolean
  hostnames: string[]
  protocols: string[]
  contacted_ports: number[]
  exposed_ports: number[]
  bytes_sent: number
  bytes_received: number
  packets_sent: number
  packets_received: number
  flow_ids: string[]
  dns_queries: string[]
  sni_hosts: string[]
  http_hosts: string[]
  findings: string[]
  timeline: HostTimelinePoint[]
}

/** Vista host/IP aggregata */
export interface HostAnalysisResult {
  total_hosts: number
  hosts: HostEntry[]
}

/** Statistiche per un singolo indirizzo IP */
export interface IPServiceEntry {
  /** Nome del service dedotto da port/protocol */
  service: string
  /** Porta TCP/UDP osservata, se disponibile */
  port: number | null
  /** Protocol di trasporto o rete */
  protocol: string
  /** Ruolo osservato per l'IP rispetto al service */
  direction: string
  /** Number of observed packets */
  count: number
  /** Peer remoti most frequenti per questo service */
  peers: string[]
}

/** Statistiche per un singolo indirizzo IP */
export interface IPEntry {
  /** Indirizzo IP in format stringa (IPv4 o IPv6) */
  ip: string
  /** Numero di packets associati a questo indirizzo */
  count: number
  /** Volume totale in byte associato a questo indirizzo */
  bytes: number
  /** Protocols osservati per questo IP */
  protocols: string[]
  /** Observed DNS names nel PCAP per questo indirizzo */
  hostnames: string[]
  /** Peer remoti most frequenti */
  peers: string[]
  /** Services inferred from observed ports and protocols */
  services: IPServiceEntry[]
  /** Informazioni opzionali ottenute interrogando external services */
  external?: IPExternalInfo | null
}

/** Statistiche per una singola port di rete */
export interface PortEntry {
  /** Numero di port (1–65535) */
  port: number
  /** Nome del service (es. "HTTP", "SSH") o numero port come stringa */
  service: string
  /** Numero di packets che usano questa port */
  count: number
  /** Protocol di trasporto: "TCP" o "UDP" */
  protocol: string
}

/** Flusso di comunicazione bidirezionale tra due IP addresses */
export interface Conversation {
  /** Primo IP della coppia (ordinati lessicograficamente) */
  src_ip: string
  /** Secondo IP della coppia */
  dst_ip: string
  /** Numero totale di packets scambiati */
  packets: number
  /** Volume totale in byte scambiati */
  bytes: number
  /** Protocols osservati in questa conversazione */
  protocols: string[]
}

/** Flow 5-tuple ricostruito dal backend */
export interface FlowEntry {
  /** Identificativo stabile del flow */
  flow_id: string
  /** Source IP del primo verso osservato */
  src_ip: string
  /** Porta source */
  src_port: number | null
  /** Destination IP del primo verso osservato */
  dst_ip: string
  /** Porta destination */
  dst_port: number | null
  /** Protocol L4 */
  protocol: string
  /** Timestamp ISO del primo packet */
  first_seen: string
  /** Timestamp ISO dell'ultimo packet */
  last_seen: string
  /** Duration in secondi */
  duration_seconds: number
  /** Total packets */
  packets_total: number
  /** Byte totali */
  bytes_total: number
  /** Packets client -> server */
  packets_client_to_server: number
  /** Packets server -> client */
  packets_server_to_client: number
  /** Byte client -> server */
  bytes_client_to_server: number
  /** Byte server -> client */
  bytes_server_to_client: number
  /** Flag TCP aggregati */
  tcp_flags: string[]
  /** Stato approssimativo dedotto dal backend */
  state: string
  /** Numeri dei packets associati */
  packet_numbers: number[]
}

/** Un punto della timeline di traffico */
export interface TimelinePoint {
  /** Orario nel format HH:MM:SS (UTC) */
  timestamp: string
  /** Numero di packets nel bucket temporale */
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

/** Dettagli di un singolo packet */
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
  /** Byte grezzi del packet come stringa esadecimale */
  raw_hex: string | null
  /** Stack protocollare completo per l'inspector Wireshark-style */
  layers: LayerInfo[]
}

/** Risultato completo dell'analysis di un file PCAP — oggetto radice */
export interface AnalysisResult {
  /** Nome originale del file caricato */
  filename: string
  /** General capture statistics */
  summary: SummaryStats
  /** Protocol distribution (top 20) */
  protocols: ProtocolEntry[]
  /** Most active source IP addresses (top 20) */
  top_src_ips: IPEntry[]
  /** Most active destination IP addresses (top 20) */
  top_dst_ips: IPEntry[]
  /** Ports source most used (top 15) */
  top_src_ports: PortEntry[]
  /** Ports di destination most used (top 15) */
  top_dst_ports: PortEntry[]
  /** Conversazioni bidirezionali most attive (top 20) */
  conversations: Conversation[]
  /** Flow 5-tuple ricostruiti dal backend */
  flows: FlowEntry[]
  /** Analysis DNS locale privacy-by-default */
  dns?: DNSAnalysisResult | null
  /** Analysis HTTP in chiaro privacy-by-default */
  http?: HTTPAnalysisResult | null
  /** Analysis TLS basata sui metadata osservabili del handshake */
  tls?: TLSAnalysisResult | null
  /** Vista aggregata host/IP */
  hosts?: HostAnalysisResult | null
  /** Traffic trend over time */
  timeline: TimelinePoint[]
  /** Lista detailsata dei primi 1000 packets */
  packets: PacketEntry[]
  /** Informazioni opzionali ottenute con l'arricchimento external manuale */
  external_ip_info?: Record<string, IPExternalInfo>
}

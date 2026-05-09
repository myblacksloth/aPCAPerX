"""
Motore di analysis dei file PCAP/PCAPNG.

Questo modulo contiene tutta la logica di lettura e decodifica dei packets
network traffic through Scapy. It operates in streaming mode to handle large
dimensioni senza esaurire la memoria RAM.

Flusso di elaborazione per ogni packet:
    1. Lettura dal file PCAP
    2. Rilevamento del protocol di most alto livello
    3. Estrazione di IP addresses e ports
    4. Accumulo nelle strutture statistiche
    5. Aggregazione finale dei results
"""

import os
import socket
from datetime import datetime, timezone
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple

# Import Scapy: libreria Python per l'analysis di packets di rete
from scapy.all import PcapReader                   # lettore streaming di file PCAP
from scapy.layers.l2 import Ether, ARP             # livello data-link
from scapy.layers.inet import IP, TCP, UDP, ICMP   # livello rete e trasporto IPv4
from scapy.layers.inet6 import IPv6                # livello rete IPv6
from scapy.layers.dns import DNS                   # protocol DNS

from models import (
    AnalysisResult, SummaryStats, ProtocolEntry, IPEntry,
    PortEntry, Conversation, TimelinePoint, PacketEntry,
    LayerField, LayerInfo, IPServiceEntry,
)
from flow_analysis import FlowAnalyzer
from dns_analysis import DNSAnalyzer
from http_analysis import HTTPAnalyzer
from tls_analysis import TLSAnalyzer
from host_analysis import build_hosts
from config import MAX_PACKET_LIST


# ─── Costanti di configurazione ───────────────────────────────────────────────

# Port -> service name map for the most common well-known protocols.
# Viene usata per "indovinare" il protocol applicativo dalla port TCP/UDP.
PORT_SERVICES: Dict[int, str] = {
    20:    "FTP-DATA",
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    67:    "DHCP",
    68:    "DHCP",
    69:    "TFTP",
    80:    "HTTP",
    110:   "POP3",
    119:   "NNTP",
    123:   "NTP",
    143:   "IMAP",
    161:   "SNMP",
    162:   "SNMP-Trap",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    500:   "IKE",
    514:   "Syslog",
    587:   "SMTP-TLS",
    636:   "LDAPS",
    993:   "IMAPS",
    995:   "POP3S",
    1194:  "OpenVPN",
    1433:  "MSSQL",
    1521:  "Oracle",
    3306:  "MySQL",
    3389:  "RDP",
    5060:  "SIP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    27017: "MongoDB",
}


# ─── Nomi human-readable per i layer Scapy ────────────────────────────────────

_LAYER_DISPLAY: Dict[str, str] = {
    "Ether":      "Ethernet II",
    "IP":         "Internet Protocol v4",
    "IPv6":       "Internet Protocol v6",
    "TCP":        "Transmission Control Protocol",
    "UDP":        "User Datagram Protocol",
    "ICMP":       "Internet Control Message Protocol",
    "ICMPv6":     "Internet Control Message Protocol v6",
    "DNS":        "Domain Name System",
    "DNSQR":      "DNS Query Record",
    "DNSRR":      "DNS Resource Record",
    "ARP":        "Address Resolution Protocol",
    "DHCP":       "Dynamic Host Configuration Protocol",
    "BOOTP":      "Bootstrap Protocol",
    "NTP":        "Network Time Protocol",
    "STP":        "Spanning Tree Protocol",
    "SNMP":       "Simple Network Management Protocol",
    "Raw":        "Data",
    "Padding":    "Padding",
    "LLC":        "Logical Link Control",
    "Dot1Q":      "802.1Q Virtual LAN",
    "GRE":        "Generic Routing Encapsulation",
    "ESP":        "Encapsulating Security Payload",
    "AH":         "Authentication Header",
    "SCTP":       "Stream Control Transmission Protocol",
}


def _extract_layers(pkt) -> List[LayerInfo]:
    """
    Percorre lo stack protocollare del packet e restituisce un albero
    di layer con i relativi campi, pronto per la visualizzazione Wireshark-style.
    """
    result: List[LayerInfo] = []
    layer = pkt

    while layer is not None:
        cls_name = layer.__class__.__name__
        if cls_name == "NoPayload":
            break

        fields: List[LayerField] = []

        try:
            if hasattr(layer, "fields_desc"):
                for f in layer.fields_desc:
                    try:
                        internal = layer.getfieldval(f.name)
                        repr_val = f.i2repr(layer, internal)

                        # Converti bytes → hex
                        if isinstance(repr_val, bytes):
                            repr_val = repr_val.hex()
                        elif isinstance(internal, bytes) and str(repr_val).startswith(("b'", 'b"')):
                            repr_val = internal.hex()

                        val_str = str(repr_val)[:400]
                        fields.append(LayerField(name=f.name, value=val_str))
                    except Exception:
                        pass

            # Layer Raw: aggiungi il payload decodificato se sembra testo
            if cls_name == "Raw":
                try:
                    raw_bytes: bytes = layer.load
                    try:
                        text = raw_bytes.decode("utf-8", errors="replace")
                        # Se almeno il 70% dei caratteri is stampabile, showslo come testo
                        printable = sum(32 <= ord(c) < 127 for c in text[:200])
                        if printable >= len(text[:200]) * 0.7:
                            fields.append(LayerField(
                                name="[payload decoded]",
                                value=text[:1000],
                            ))
                    except Exception:
                        pass
                except Exception:
                    pass

        except Exception:
            pass

        display_name = _LAYER_DISPLAY.get(cls_name, cls_name)
        result.append(LayerInfo(name=cls_name, display=display_name, fields=fields))

        try:
            next_layer = layer.payload
            if next_layer is None or next_layer.__class__.__name__ == "NoPayload":
                break
            layer = next_layer
        except Exception:
            break

    return result


# ─── Funzioni di supporto private ─────────────────────────────────────────────

def _get_service(port: int, protocol: Optional[str] = None) -> str:
    """
    Returns the service name for the specified port.
    Se la port non is tra quelle note, restituisce il numero come stringa.
    """
    service = PORT_SERVICES.get(port)
    if service:
        return service

    if protocol:
        try:
            return socket.getservbyport(port, protocol.lower()).upper()
        except OSError:
            pass

    return str(port)


def _is_named_service_port(port: int, protocol: str) -> bool:
    """Indicates whether a port has a known service name."""
    if port in PORT_SERVICES:
        return True
    try:
        socket.getservbyport(port, protocol.lower())
        return True
    except OSError:
        return False


def _service_endpoint(
    src_port: int,
    dst_port: int,
    protocol: str,
) -> Tuple[int, str, str]:
    """
    Infers which port represents the application service in the packet.
    Returns port, service name, and server side ("src" or "dst").
    """
    src_known = _is_named_service_port(src_port, protocol)
    dst_known = _is_named_service_port(dst_port, protocol)

    if src_known and not dst_known:
        return src_port, _get_service(src_port, protocol), "src"

    return dst_port, _get_service(dst_port, protocol), "dst"


def _safe_dns_name(value) -> Optional[str]:
    """Converte nomi DNS bytes/string in testo pulito."""
    try:
        if isinstance(value, bytes):
            return value.decode(errors="replace").rstrip(".")
        return str(value).rstrip(".")
    except Exception:
        return None


def _raw_payload_bytes(pkt) -> Optional[bytes]:
    """Estrae il payload Raw di Scapy senza introdurre nuove dipendenze nel parser."""
    try:
        raw_layer = pkt.getlayer("Raw")
        if raw_layer is None:
            return None
        return bytes(raw_layer.load)
    except Exception:
        return None


def _record_dns_hostnames(pkt, dns_hostnames: Dict[str, set]) -> None:
    """
    Estrae associazioni IP -> hostname dalle responses DNS presenti nel PCAP.
    Does not perform external queries: uses only evidence contained in the capture.
    """
    if not pkt.haslayer(DNS):
        return

    try:
        dns = pkt[DNS]
        if dns.qr != 1 or dns.ancount <= 0:
            return

        for idx in range(int(dns.ancount)):
            try:
                answer = dns.an[idx]
                if getattr(answer, "type", None) not in (1, 28):
                    continue

                ip_value = str(answer.rdata)
                hostname = _safe_dns_name(answer.rrname)
                if ip_value and hostname:
                    dns_hostnames[ip_value].add(hostname)
            except Exception:
                continue
    except Exception:
        pass


def _remember_ip_activity(
    ip_service_counts: Counter,
    ip_service_peers: Dict[Tuple[str, str, Optional[int], str, str], Counter],
    ip_protocols: Dict[str, set],
    ip_peers: Dict[str, Counter],
    ip: Optional[str],
    peer: Optional[str],
    service: str,
    port: Optional[int],
    protocol: str,
    direction: str,
) -> None:
    """Aggiorna gli accumulatori di detailso associati a un IP."""
    if not ip:
        return

    key = (ip, service, port, protocol, direction)
    ip_service_counts[key] += 1
    ip_protocols[ip].add(protocol)
    if service and service != protocol:
        ip_protocols[ip].add(service)

    if peer:
        ip_peers[ip][peer] += 1
        ip_service_peers[key][peer] += 1


def _build_ip_entry(
    ip: str,
    count: int,
    byte_count: int,
    ip_service_counts: Counter,
    ip_service_peers: Dict[Tuple[str, str, Optional[int], str, str], Counter],
    ip_protocols: Dict[str, set],
    dns_hostnames: Dict[str, set],
    ip_peers: Dict[str, Counter],
) -> IPEntry:
    """Costruisce l'entry IP completa di services, peer, protocolli e nomi DNS."""
    services: List[IPServiceEntry] = []
    relevant = [
        (key, svc_count)
        for key, svc_count in ip_service_counts.items()
        if key[0] == ip
    ]

    for (_, service, port, protocol, direction), svc_count in sorted(
        relevant,
        key=lambda item: item[1],
        reverse=True,
    )[:12]:
        peers = [peer for peer, _ in ip_service_peers[(ip, service, port, protocol, direction)].most_common(8)]
        services.append(IPServiceEntry(
            service=service,
            port=port,
            protocol=protocol,
            direction=direction,
            count=svc_count,
            peers=peers,
        ))

    return IPEntry(
        ip=ip,
        count=count,
        bytes=byte_count,
        protocols=sorted(ip_protocols.get(ip, set())),
        hostnames=sorted(dns_hostnames.get(ip, set()))[:8],
        peers=[peer for peer, _ in ip_peers.get(ip, Counter()).most_common(10)],
        services=services,
    )


def _get_protocol(pkt) -> str:
    """
    Identifica il protocol di most alto livello presente nel packet.

    La rilevazione percorre lo stack dal livello most specifico (applicativo)
    al most generico (data-link), restituendo il primo protocol riconosciuto.
    For TCP and UDP, also checks ports to identify the application service.

    Restituisce "Other" per packets non riconosciuti (es. protocolli proprietari).
    """
    try:
        # ── Livello data-link speciale ─────────────────────────────────────
        if pkt.haslayer(ARP):
            return "ARP"

        # ── Livello trasporto: ICMP ────────────────────────────────────────
        if pkt.haslayer(ICMP):
            return "ICMP"

        # ── Livello trasporto: TCP ─────────────────────────────────────────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            # Checks the destination port first (remote service),
            # then the source port (service response)
            for port in (tcp.dport, tcp.sport):
                svc = PORT_SERVICES.get(port)
                if svc:
                    return svc
            return "TCP"

        # ── Livello trasporto: UDP ─────────────────────────────────────────
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            for port in (udp.dport, udp.sport):
                svc = PORT_SERVICES.get(port)
                if svc:
                    return svc
            # Ulteriore tentativo via layer DNS (copre MDNS sulla port 5353)
            if pkt.haslayer(DNS):
                return "DNS"
            return "UDP"

        # ── Livello rete: IPv6 ─────────────────────────────────────────────
        if pkt.haslayer(IPv6):
            return "IPv6"

        # ── Livello rete: IPv4 raw ─────────────────────────────────────────
        if pkt.haslayer(IP):
            # Mappe per i proto-number IP meno comuni
            ip_protos = {
                1: "ICMP", 6: "TCP", 17: "UDP",
                41: "IPv6", 47: "GRE", 50: "ESP",
                51: "AH",  89: "OSPF", 132: "SCTP",
            }
            return ip_protos.get(pkt[IP].proto, f"IP/{pkt[IP].proto}")

        # ── Livello data-link: Ethernet generico ──────────────────────────
        if pkt.haslayer(Ether):
            return "Ethernet"

    except Exception:
        # Un packet malformat non deve bloccare l'analysis
        pass

    return "Other"


def _get_info(pkt, protocol: str) -> str:
    """
    Genera una stringa informativa sintetica sul contenuto del packet.
    Imita il campo "Info" di Wireshark per i protocolli most comuni.
    """
    try:
        # ── DNS: shows the query name or response type ──────────
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qdcount > 0 and dns.qd is not None:
                try:
                    name = dns.qd.qname.decode(errors="replace").rstrip(".")
                    qr = "Query" if dns.qr == 0 else "Response"
                    return f"DNS {qr}: {name}"
                except Exception:
                    pass
            return "DNS Response"

        # ── ARP: "Who has X?" o "X is at Y" ───────────────────────────────
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            if arp.op == 1:   # ARP Request
                return f"Who has {arp.pdst}? Tell {arp.psrc}"
            if arp.op == 2:   # ARP Reply
                return f"{arp.psrc} is at {arp.hwsrc}"

        # ── ICMP: tipo e codice ────────────────────────────────────────────
        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            icmp_types = {
                0: "Echo Reply", 3: "Dest. Unreachable",
                8: "Echo Request", 11: "Time Exceeded",
                12: "Parameter Problem", 5: "Redirect",
            }
            base = icmp_types.get(icmp.type, f"Type={icmp.type}")
            return f"{base} (Code={icmp.code})"

        # ── TCP: flag attivi, numero di sequenza e lunghezza payload ───────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flag_map = [
                ("S", "SYN"), ("A", "ACK"), ("F", "FIN"),
                ("R", "RST"), ("P", "PSH"), ("U", "URG"),
            ]
            flags = [label for attr, label in flag_map if getattr(tcp.flags, attr, False)]
            flag_str = "[" + ", ".join(flags) + "]" if flags else "[]"
            payload_len = len(tcp.payload) if tcp.payload else 0
            return f"{flag_str} Seq={tcp.seq} Len={payload_len}"

        # ── UDP: lunghezza del datagramma ──────────────────────────────────
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            return f"Len={udp.len}"

    except Exception:
        # Ignora packets malformati e usa il nome del protocol come fallback
        pass

    return protocol


def _calc_bucket_size(duration: float) -> int:
    """
    Calcola la dimensione ottimale del bucket temporale per la timeline
    based on total capture duration.

    Obiettivo: produrre tra 60 e 200 punti nel grafico, indipendentemente
    from capture duration.

    Soglie:
        ≤ 1 min   → 1 secondo   per packet
        ≤ 10 min  → 5 secondi   per bucket
        ≤ 1 ora   → 30 secondi  per bucket
        ≤ 6 ore   → 2 minuti    per bucket
        > 6 ore   → 10 minuti   per bucket
    """
    if duration <= 60:
        return 1
    if duration <= 600:
        return 5
    if duration <= 3_600:
        return 30
    if duration <= 21_600:
        return 120
    return 600


# ─── Funzione principale di analysis ───────────────────────────────────────────

def analyze_pcap(file_path: str, filename: str) -> AnalysisResult:
    """
    Analyzes a PCAP/PCAPNG file e restituisce un report statistico completo.

    Reads packets in streaming mode through PcapReader, so even
    file da centinaia di MB vengono gestiti senza caricarli interamente in RAM.

    Args:
        file_path: Percorso assoluto al file PCAP temporaneo sul server.
        filename:  Nome originale del file (visualizzato nel frontend).

    Returns:
        AnalysisResult con tutte le statistiche estratte.

    Raises:
        ValueError: Se il file is corrotto, vuoto o non is un PCAP valido.
    """

    # ── Inizializzazione degli accumulatori statistici ─────────────────────
    total_packets: int = 0
    total_bytes:   int = 0

    # Timestamp del primo e dell'ultimo packet (secondi Unix in float)
    first_ts: Optional[float] = None
    last_ts:  Optional[float] = None

    # Contatore occorrenze e byte per ogni protocol rilevato
    proto_count: Counter = Counter()
    proto_bytes: Dict[str, int] = defaultdict(int)

    # Statistiche per IP addresses source e destination
    src_ip_count: Counter = Counter()
    dst_ip_count: Counter = Counter()
    src_ip_bytes: Dict[str, int] = defaultdict(int)
    dst_ip_bytes: Dict[str, int] = defaultdict(int)

    # Statistiche per ports: la chiave is (numero_port, "TCP"/"UDP")
    src_port_count: Counter = Counter()
    dst_port_count: Counter = Counter()

    # Dettagli associati agli IP per il popup Top IP
    ip_service_counts: Counter = Counter()
    ip_service_peers: Dict[Tuple[str, str, Optional[int], str, str], Counter] = defaultdict(Counter)
    ip_protocols: Dict[str, set] = defaultdict(set)
    ip_peers: Dict[str, Counter] = defaultdict(Counter)
    dns_hostnames: Dict[str, set] = defaultdict(set)

    # Conversazioni bidirezionali tra coppie di IP.
    # Chiave: (min(ip1,ip2), max(ip1,ip2)) so A→B e B→A sono la stessa coppia.
    conv_data: Dict[Tuple[str, str], Dict] = defaultdict(
        lambda: {"packets": 0, "bytes": 0, "protocols": set()}
    )

    # Bucket temporali per la timeline: chiave = secondo Unix (int)
    ts_buckets: Dict[int, Dict] = defaultdict(lambda: {"packets": 0, "bytes": 0})

    # Lista detailsata dei packets (limitata a MAX_PACKET_LIST elementi)
    packet_list: List[PacketEntry] = []

    # Analyzetore dedicato dei flow 5-tuple, aggiornato packet per packet.
    flow_analyzer = FlowAnalyzer()

    # Local DNS analyzer: sends no data externally and works only on the PCAP.
    dns_analyzer = DNSAnalyzer()

    # Analyzetore HTTP in chiaro: usa solo payload TCP leggibili, senza decifrare TLS.
    http_analyzer = HTTPAnalyzer()

    # Analyzetore TLS: estrae solo metadata visibili nel handshake, senza decifrare.
    tls_analyzer = TLSAnalyzer()

    # ── Streaming PCAP file reading ────────────────────────
    try:
        with PcapReader(file_path) as reader:
            for pkt in reader:
                total_packets += 1
                pkt_len = len(pkt)
                total_bytes += pkt_len

                # ── Timestamp del packet ────────────────────────────────
                try:
                    ts = float(pkt.time)
                except Exception:
                    ts = 0.0

                # Updates the capture time interval
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts

                # ── Rilevamento protocol ─────────────────────────────────
                protocol = _get_protocol(pkt)
                proto_count[protocol] += 1
                proto_bytes[protocol] += pkt_len
                _record_dns_hostnames(pkt, dns_hostnames)

                # ── Estrazione IP addresses ────────────────────────────────
                src_ip: Optional[str] = None
                dst_ip: Optional[str] = None
                src_port: Optional[int] = None
                dst_port: Optional[int] = None

                if pkt.haslayer(IP):
                    # Packets IPv4: estrai source e destination
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    # Packets IPv6: stesso approccio
                    src_ip = pkt[IPv6].src
                    dst_ip = pkt[IPv6].dst
                elif pkt.haslayer(ARP):
                    # ARP: usa i campi IP del protocol ARP
                    src_ip = pkt[ARP].psrc
                    dst_ip = pkt[ARP].pdst

                # Aggiorna i contatori degli IP addresses
                if src_ip:
                    src_ip_count[src_ip] += 1
                    src_ip_bytes[src_ip] += pkt_len
                if dst_ip:
                    dst_ip_count[dst_ip] += 1
                    dst_ip_bytes[dst_ip] += pkt_len

                # ── Estrazione ports TCP/UDP ───────────────────────────────
                if pkt.haslayer(TCP):
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    src_port_count[(src_port, "TCP")] += 1
                    dst_port_count[(dst_port, "TCP")] += 1
                    service_port, service_name, server_side = _service_endpoint(src_port, dst_port, "TCP")
                    _remember_ip_activity(
                        ip_service_counts, ip_service_peers, ip_protocols, ip_peers,
                        src_ip, dst_ip, service_name, service_port, "TCP",
                        "server" if server_side == "src" else "client",
                    )
                    _remember_ip_activity(
                        ip_service_counts, ip_service_peers, ip_protocols, ip_peers,
                        dst_ip, src_ip, service_name, service_port, "TCP",
                        "server" if server_side == "dst" else "client",
                    )
                elif pkt.haslayer(UDP):
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    src_port_count[(src_port, "UDP")] += 1
                    dst_port_count[(dst_port, "UDP")] += 1
                    service_port, service_name, server_side = _service_endpoint(src_port, dst_port, "UDP")
                    _remember_ip_activity(
                        ip_service_counts, ip_service_peers, ip_protocols, ip_peers,
                        src_ip, dst_ip, service_name, service_port, "UDP",
                        "server" if server_side == "src" else "client",
                    )
                    _remember_ip_activity(
                        ip_service_counts, ip_service_peers, ip_protocols, ip_peers,
                        dst_ip, src_ip, service_name, service_port, "UDP",
                        "server" if server_side == "dst" else "client",
                    )

                elif src_ip or dst_ip:
                    _remember_ip_activity(
                        ip_service_counts, ip_service_peers, ip_protocols, ip_peers,
                        src_ip, dst_ip, protocol, None, protocol, "endpoint",
                    )
                    _remember_ip_activity(
                        ip_service_counts, ip_service_peers, ip_protocols, ip_peers,
                        dst_ip, src_ip, protocol, None, protocol, "endpoint",
                    )

                # ── Aggiornamento flow 5-tuple ────────────────────────────
                # The flow_analysis module keeps a bidirectional flow view
                # but keeps the 5-tuple from the first observed direction.
                flow_analyzer.add_packet(
                    packet_number=total_packets,
                    ts=ts,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol="TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else protocol,
                    length=pkt_len,
                    pkt=pkt,
                )

                # ── Aggiornamento analysis DNS strutturata ─────────────────
                # Extracts queries, responses, rcode, TTL, and indicators from the DNS layer.
                dns_analyzer.add_packet(
                    packet_number=total_packets,
                    ts=ts,
                    pkt=pkt,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                )

                raw_tcp_payload = _raw_payload_bytes(pkt) if pkt.haslayer(TCP) else None

                # ── Aggiornamento analysis HTTP in chiaro ──────────────────
                # Parsing prudente: solo payload TCP Raw che sembrano HTTP testuale.
                http_analyzer.add_packet(
                    packet_number=total_packets,
                    ts=ts,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    payload=raw_tcp_payload,
                )

                # ── Aggiornamento analysis TLS/SSL ────────────────────────
                # The parser works on TLS handshake records present in Raw TCP
                # e non tenta mai di leggere contenuti cifrati.
                tls_analyzer.add_packet(
                    packet_number=total_packets,
                    ts=ts,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    payload=raw_tcp_payload,
                )

                # ── Aggiornamento conversazioni ────────────────────────────
                # Raggruppa sempre nella stessa chiave indipendentemente dalla direzione
                if src_ip and dst_ip and src_ip != dst_ip:
                    conv_key = (min(src_ip, dst_ip), max(src_ip, dst_ip))
                    conv_data[conv_key]["packets"]  += 1
                    conv_data[conv_key]["bytes"]    += pkt_len
                    conv_data[conv_key]["protocols"].add(protocol)

                # ── Aggiornamento timeline ─────────────────────────────────
                ts_buckets[int(ts)]["packets"] += 1
                ts_buckets[int(ts)]["bytes"]   += pkt_len

                # Conserviamo solo i primi N packets detailsati nel JSON per
                # evitare consumo eccessivo di memoria/browser su PCAP molto grandi.
                if MAX_PACKET_LIST == 0 or len(packet_list) < MAX_PACKET_LIST:
                    # ── Aggiunta alla lista detailsata ───────────────────
                    # Decodifica layer e raw hex sono costosi: li facciamo solo
                    # per i packets che finiranno realmente nella risposta.
                    try:
                        ts_dt  = datetime.fromtimestamp(ts, tz=timezone.utc)
                        ts_str = ts_dt.strftime("%H:%M:%S.%f")[:-3]
                    except Exception:
                        ts_str = "00:00:00.000"

                    try:
                        raw_hex = bytes(pkt).hex()
                    except Exception:
                        raw_hex = None

                    packet_list.append(PacketEntry(
                        number   = total_packets,
                        timestamp= ts_str,
                        src_ip   = src_ip,
                        dst_ip   = dst_ip,
                        protocol = protocol,
                        length   = pkt_len,
                        src_port = src_port,
                        dst_port = dst_port,
                        info     = _get_info(pkt, protocol),
                        raw_hex  = raw_hex,
                        layers   = _extract_layers(pkt),
                    ))

    except Exception as exc:
        # Reraises the exception with a user-readable message
        raise ValueError(f"Impossibile analizzare il file PCAP: {exc}") from exc

    # ── Validazione del risultato ──────────────────────────────────────────
    if total_packets == 0:
        raise ValueError("The PCAP file does not contain valid packets.")

    # ── Calcolo statistiche aggregate ─────────────────────────────────────
    # Duration della cattura: differenza tra ultimo e primo timestamp
    duration    = float(last_ts - first_ts) if (first_ts and last_ts and last_ts > first_ts) else 0.0
    # Packets al secondo (evita divisione per zero)
    pps         = total_packets / duration if duration > 0 else 0.0
    avg_size    = total_bytes / total_packets

    # Converts Unix timestamps to ISO 8601 strings for the JSON response
    start_str = datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat() if first_ts else None
    end_str   = datetime.fromtimestamp(last_ts,  tz=timezone.utc).isoformat() if last_ts  else None

    # ── Costruzione del riepilogo generale ────────────────────────────────
    summary = SummaryStats(
        total_packets     = total_packets,
        total_bytes       = total_bytes,
        capture_start     = start_str,
        capture_end       = end_str,
        duration_seconds  = round(duration, 3),
        avg_packet_size   = round(avg_size, 2),
        packets_per_second= round(pps, 2),
    )

    # ── Top 20 protocolli per frequenza ───────────────────────────────────
    protocols = [
        ProtocolEntry(
            protocol   = proto,
            count      = count,
            bytes      = proto_bytes[proto],
            percentage = round(count / total_packets * 100, 2),
        )
        for proto, count in proto_count.most_common(20)
    ]

    # ── Top 20 IP addresses source e destination ───────────────────────
    top_src_ips = [
        _build_ip_entry(
            ip, cnt, src_ip_bytes[ip],
            ip_service_counts, ip_service_peers, ip_protocols,
            dns_hostnames, ip_peers,
        )
        for ip, cnt in src_ip_count.most_common(20)
    ]
    top_dst_ips = [
        _build_ip_entry(
            ip, cnt, dst_ip_bytes[ip],
            ip_service_counts, ip_service_peers, ip_protocols,
            dns_hostnames, ip_peers,
        )
        for ip, cnt in dst_ip_count.most_common(20)
    ]

    # ── Top 15 ports source e destination ──────────────────────────────
    top_src_ports = [
        PortEntry(port=port, service=_get_service(port, proto), count=cnt, protocol=proto)
        for (port, proto), cnt in src_port_count.most_common(15)
    ]
    top_dst_ports = [
        PortEntry(port=port, service=_get_service(port, proto), count=cnt, protocol=proto)
        for (port, proto), cnt in dst_port_count.most_common(15)
    ]

    # ── Top 20 conversazioni ordinate per volume in byte ──────────────────
    sorted_convs = sorted(conv_data.items(), key=lambda x: x[1]["bytes"], reverse=True)
    conversations = [
        Conversation(
            src_ip    = k[0],
            dst_ip    = k[1],
            packets   = v["packets"],
            bytes     = v["bytes"],
            protocols = sorted(v["protocols"]),
        )
        for k, v in sorted_convs[:20]
    ]

    # ── Costruzione della timeline con bucket intelligenti ─────────────────
    # Raggruppa i secondi in bucket di dimensione variabile
    bsize = _calc_bucket_size(duration)
    agg: Dict[int, Dict] = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for ts_sec, data in ts_buckets.items():
        # Arrotonda al bucket most vicino
        bucket_key = (ts_sec // bsize) * bsize
        agg[bucket_key]["packets"] += data["packets"]
        agg[bucket_key]["bytes"]   += data["bytes"]

    timeline = [
        TimelinePoint(
            timestamp = datetime.fromtimestamp(bk, tz=timezone.utc).strftime("%H:%M:%S"),
            packets   = agg[bk]["packets"],
            bytes     = agg[bk]["bytes"],
        )
        for bk in sorted(agg)
    ]

    # ── Flow e DNS derivati dagli accumulatori modulari ───────────────────
    flows = flow_analyzer.to_entries()
    dns_result = dns_analyzer.to_result(flows)
    http_result = http_analyzer.to_result()
    tls_result = tls_analyzer.to_result(dns_hostnames)
    hosts_result = build_hosts(
        packets=packet_list,
        flows=flows,
        dns=dns_result,
        http=http_result,
        tls=tls_result,
        dns_hostnames=dns_hostnames,
    )

    # ── Restituzione del risultato completo ───────────────────────────────
    return AnalysisResult(
        filename      = filename,
        summary       = summary,
        protocols     = protocols,
        top_src_ips   = top_src_ips,
        top_dst_ips   = top_dst_ips,
        top_src_ports = top_src_ports,
        top_dst_ports = top_dst_ports,
        conversations = conversations,
        flows         = flows,
        dns           = dns_result,
        http          = http_result,
        tls           = tls_result,
        hosts         = hosts_result,
        timeline      = timeline,
        packets       = packet_list,
    )

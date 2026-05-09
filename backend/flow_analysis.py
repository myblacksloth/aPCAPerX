"""
Analysis dei flow 5-tuple.

This module keeps incremental state while streaming the PCAP.
Ogni nuovo packet TCP/UDP viene associato a un flow identificato dalla prima
observed direction:

    src_ip, src_port, dst_ip, dst_port, protocol L4

I packets nel verso inverso vengono riconosciuti tramite una chiave
bidirezionale e contribuiscono ai contatori server -> client dello stesso flow.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from config import MAX_FLOW_PACKET_NUMBERS


EndpointTuple = Tuple[str, Optional[int], str, Optional[int], str]
BidirectionalKey = Tuple[Tuple[str, Optional[int]], Tuple[str, Optional[int]], str]


@dataclass
class FlowStats:
    """Stato interno accumulato per un flow 5-tuple."""

    # Stable identifier computed from the 5-tuple of the first observed direction.
    flow_id: str
    # Indirizzo Source IP del flow, interpretato come lato client.
    src_ip: str
    # Porta source del flow.
    src_port: Optional[int]
    # Indirizzo Destination IP del flow, interpretato come lato server.
    dst_ip: str
    # Porta destination del flow.
    dst_port: Optional[int]
    # L4 protocol, for example TCP or UDP.
    protocol: str
    # Timestamp Unix del primo packet visto.
    first_ts: float
    # Timestamp Unix dell'ultimo packet visto.
    last_ts: float
    # Numero totale di packets del flow.
    packets_total: int = 0
    # Numero totale di byte del flow.
    bytes_total: int = 0
    # Packets nel verso client -> server.
    packets_client_to_server: int = 0
    # Packets nel verso server -> client.
    packets_server_to_client: int = 0
    # Byte nel verso client -> server.
    bytes_client_to_server: int = 0
    # Byte nel verso server -> client.
    bytes_server_to_client: int = 0
    # Aggregated TCP flags observed in the flow.
    tcp_flags: Set[str] = field(default_factory=set)
    # Flag TCP visti nel verso client -> server.
    client_tcp_flags: Set[str] = field(default_factory=set)
    # Flag TCP visti nel verso server -> client.
    server_tcp_flags: Set[str] = field(default_factory=set)
    # Numeri packet associati, utili al frontend per correlare la traccia.
    packet_numbers: List[int] = field(default_factory=list)


def _stable_flow_id(src_ip: str, src_port: Optional[int], dst_ip: str, dst_port: Optional[int], protocol: str) -> str:
    """Crea un identificativo breve ma stabile dal 5-tuple direzionale."""
    raw = f"{src_ip}|{src_port or 0}|{dst_ip}|{dst_port or 0}|{protocol.upper()}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _endpoint(ip: str, port: Optional[int]) -> Tuple[str, Optional[int]]:
    """Normalizza endpoint IP:port per usarlo nelle chiavi."""
    return ip, port


def _bidirectional_key(src_ip: str, src_port: Optional[int], dst_ip: str, dst_port: Optional[int], protocol: str) -> BidirectionalKey:
    """Crea una chiave indipendente dal verso per riconoscere request e response."""
    left = _endpoint(src_ip, src_port)
    right = _endpoint(dst_ip, dst_port)
    return (left, right, protocol) if left <= right else (right, left, protocol)


def _format_ts(ts: float) -> str:
    """Converte timestamp Unix in ISO 8601 UTC leggibile nel JSON."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _tcp_flags_from_packet(pkt) -> Set[str]:
    """Estrae flag TCP principali da un packet Scapy."""
    flags: Set[str] = set()
    try:
        raw_flags = str(pkt.sprintf("%TCP.flags%"))
    except Exception:
        raw_flags = ""

    mapping = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }

    for char, name in mapping.items():
        if char in raw_flags or name in raw_flags.upper():
            flags.add(name)

    return flags


def _tcp_state(flow: FlowStats) -> str:
    """Infers an approximate TCP state from flags observed in both directions."""
    if "RST" in flow.tcp_flags:
        return "reset"

    client_fin = "FIN" in flow.client_tcp_flags
    server_fin = "FIN" in flow.server_tcp_flags
    if client_fin and server_fin:
        return "closed"
    if client_fin or server_fin:
        return "closing"

    client_syn = "SYN" in flow.client_tcp_flags
    server_syn = "SYN" in flow.server_tcp_flags
    server_ack = "ACK" in flow.server_tcp_flags
    client_ack = "ACK" in flow.client_tcp_flags
    if client_syn and server_syn and client_ack:
        return "established"
    if client_syn and server_syn and server_ack:
        return "handshake_seen"
    if client_syn:
        return "opening"
    if flow.packets_client_to_server > 0 and flow.packets_server_to_client > 0:
        return "bidirectional_no_handshake"
    return "one_way"


def _udp_state(flow: FlowStats) -> str:
    """Deduce uno stato UDP approssimativo dalla presenza dei due versi."""
    if flow.packets_client_to_server > 0 and flow.packets_server_to_client > 0:
        return "request_response"
    return "one_way"


def _state(flow: FlowStats) -> str:
    """Seleziona la logica di stato in base al protocol L4."""
    if flow.protocol == "TCP":
        return _tcp_state(flow)
    if flow.protocol == "UDP":
        return _udp_state(flow)
    return "observed"


class FlowAnalyzer:
    """Modular accumulator for flows observed in the PCAP."""

    def __init__(self) -> None:
        # Bidirectional key map -> flow created from the first observed direction.
        self._flows: Dict[BidirectionalKey, FlowStats] = {}

    def add_packet(
        self,
        *,
        packet_number: int,
        ts: float,
        src_ip: Optional[str],
        src_port: Optional[int],
        dst_ip: Optional[str],
        dst_port: Optional[int],
        protocol: str,
        length: int,
        pkt=None,
    ) -> None:
        """Aggiunge un packet al flow corrispondente, se il 5-tuple e valido."""
        if not src_ip or not dst_ip:
            return
        if protocol not in {"TCP", "UDP"}:
            return
        if src_port is None or dst_port is None:
            return

        key = _bidirectional_key(src_ip, src_port, dst_ip, dst_port, protocol)
        flow = self._flows.get(key)

        if flow is None:
            flow = FlowStats(
                flow_id=_stable_flow_id(src_ip, src_port, dst_ip, dst_port, protocol),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                first_ts=ts,
                last_ts=ts,
            )
            self._flows[key] = flow

        flow.last_ts = max(flow.last_ts, ts)
        flow.first_ts = min(flow.first_ts, ts)
        flow.packets_total += 1
        flow.bytes_total += length
        # Evita liste enormi nei flow su catture molto grandi. I contatori restano
        # completi, ma il detailso packet_numbers viene campionato ai primi N.
        if MAX_FLOW_PACKET_NUMBERS == 0 or len(flow.packet_numbers) < MAX_FLOW_PACKET_NUMBERS:
            flow.packet_numbers.append(packet_number)

        is_client_to_server = (
            src_ip == flow.src_ip
            and src_port == flow.src_port
            and dst_ip == flow.dst_ip
            and dst_port == flow.dst_port
        )

        if is_client_to_server:
            flow.packets_client_to_server += 1
            flow.bytes_client_to_server += length
        else:
            flow.packets_server_to_client += 1
            flow.bytes_server_to_client += length

        if protocol == "TCP" and pkt is not None:
            flags = _tcp_flags_from_packet(pkt)
            flow.tcp_flags.update(flags)
            if is_client_to_server:
                flow.client_tcp_flags.update(flags)
            else:
                flow.server_tcp_flags.update(flags)

    def to_entries(self):
        """Converte lo stato interno nei modelli Pydantic serializzabili."""
        from models import FlowEntry

        entries = []
        for flow in self._flows.values():
            entries.append(FlowEntry(
                flow_id=flow.flow_id,
                src_ip=flow.src_ip,
                src_port=flow.src_port,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                first_seen=_format_ts(flow.first_ts),
                last_seen=_format_ts(flow.last_ts),
                duration_seconds=round(max(0.0, flow.last_ts - flow.first_ts), 6),
                packets_total=flow.packets_total,
                bytes_total=flow.bytes_total,
                packets_client_to_server=flow.packets_client_to_server,
                packets_server_to_client=flow.packets_server_to_client,
                bytes_client_to_server=flow.bytes_client_to_server,
                bytes_server_to_client=flow.bytes_server_to_client,
                tcp_flags=sorted(flow.tcp_flags),
                state=_state(flow),
                packet_numbers=flow.packet_numbers,
            ))

        return sorted(entries, key=lambda item: (item.first_seen, item.flow_id))

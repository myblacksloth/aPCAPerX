"""
Aggregated host/IP analysis.

This module builds a host-centered view of observed PCAP hosts using
data already extracted by the other analyzers: packets, 5-tuple flows, DNS, HTTP, and
TLS. Non effettua chiamate esterne: ASN e geolocalizzazione vengono showste dal
frontend when the user enables IP enrichment and `external_ip_info` is
popolato.
"""

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from models import (
    DNSAnalysisResult,
    HostAnalysisResult,
    HostEntry,
    HostTimelinePoint,
    HTTPAnalysisResult,
    PacketEntry,
    TLSAnalysisResult,
    FlowEntry,
)


@dataclass
class _HostAccumulator:
    """Stato interno usato per accumulare tutte le evidenze di un host."""

    ip: str
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    protocols: Set[str] = field(default_factory=set)
    hostnames: Set[str] = field(default_factory=set)
    contacted_ports: Set[int] = field(default_factory=set)
    exposed_ports: Set[int] = field(default_factory=set)
    flow_ids: Set[str] = field(default_factory=set)
    dns_queries: Set[str] = field(default_factory=set)
    sni_hosts: Set[str] = field(default_factory=set)
    http_hosts: Set[str] = field(default_factory=set)
    findings: Set[str] = field(default_factory=set)
    timeline: Dict[int, Dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: {
        "packets_sent": 0,
        "packets_received": 0,
        "bytes_sent": 0,
        "bytes_received": 0,
    }))


def _is_private_ip(ip: str) -> bool:
    """Classifies non-public addresses using the standard library."""
    try:
        value = ipaddress.ip_address(ip)
        return value.is_private or value.is_loopback or value.is_link_local or value.is_reserved or value.is_multicast
    except ValueError:
        return False


def _packet_second(timestamp: str) -> int:
    """Converte HH:MM:SS.mmm in secondo della giornata per aggregare la timeline."""
    try:
        parts = timestamp.split(":")
        if len(parts) != 3:
            return 0
        return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(float(parts[2]))
    except Exception:
        return 0


def _format_second(second: int) -> str:
    """Formatta un secondo della giornata in HH:MM:SS UTC."""
    return datetime.fromtimestamp(second, tz=timezone.utc).strftime("%H:%M:%S")


def _host_role(host: _HostAccumulator) -> str:
    """Stima il ruolo dell'host usando ports contattate/esposte e direzioni flow."""
    has_client = bool(host.contacted_ports)
    has_server = bool(host.exposed_ports)

    if has_client and has_server:
        return "misto"
    if has_server:
        return "server"
    if has_client:
        return "client"
    if host.packets_sent > 0 and host.packets_received == 0:
        return "client"
    if host.packets_received > 0 and host.packets_sent == 0:
        return "server"
    return "ignoto"


def _get(accumulators: Dict[str, _HostAccumulator], ip: Optional[str]) -> Optional[_HostAccumulator]:
    """Restituisce l'accumulatore per IP, creando il profilo se necessario."""
    if not ip:
        return None
    if ip not in accumulators:
        accumulators[ip] = _HostAccumulator(ip=ip)
    return accumulators[ip]


def _add_packet_evidence(accumulators: Dict[str, _HostAccumulator], packets: List[PacketEntry]) -> None:
    """Aggiorna byte, packets, protocolli e timeline per ogni host."""
    for packet in packets:
        second = _packet_second(packet.timestamp)
        src = _get(accumulators, packet.src_ip)
        dst = _get(accumulators, packet.dst_ip)

        if src:
            src.packets_sent += 1
            src.bytes_sent += packet.length
            src.protocols.add(packet.protocol)
            src.timeline[second]["packets_sent"] += 1
            src.timeline[second]["bytes_sent"] += packet.length

        if dst:
            dst.packets_received += 1
            dst.bytes_received += packet.length
            dst.protocols.add(packet.protocol)
            dst.timeline[second]["packets_received"] += 1
            dst.timeline[second]["bytes_received"] += packet.length


def _add_flow_evidence(accumulators: Dict[str, _HostAccumulator], flows: List[FlowEntry]) -> None:
    """Collega flow e ports contattate/esposte ai rispettivi host."""
    for flow in flows:
        client = _get(accumulators, flow.src_ip)
        server = _get(accumulators, flow.dst_ip)

        if client:
            client.flow_ids.add(flow.flow_id)
            client.protocols.add(flow.protocol)
            if flow.dst_port is not None:
                client.contacted_ports.add(flow.dst_port)

        if server:
            server.flow_ids.add(flow.flow_id)
            server.protocols.add(flow.protocol)
            if flow.dst_port is not None:
                server.exposed_ports.add(flow.dst_port)


def _add_dns_evidence(accumulators: Dict[str, _HostAccumulator], dns: Optional[DNSAnalysisResult]) -> None:
    """Adds generated queries and hostnames inferred from DNS responses."""
    if not dns:
        return

    for query in dns.queries:
        client = _get(accumulators, query.client)
        if client:
            client.dns_queries.add(query.query)
            client.protocols.add("DNS")

        for answer_ip in query.answer_ips:
            host = _get(accumulators, answer_ip)
            if host:
                host.hostnames.add(query.query)


def _add_http_evidence(accumulators: Dict[str, _HostAccumulator], http: Optional[HTTPAnalysisResult]) -> None:
    """Adds observed HTTP hosts and findings for cleartext traffic."""
    if not http:
        return

    for request in http.requests:
        if not request.host:
            continue
        client = _get(accumulators, request.client_ip)
        server = _get(accumulators, request.server_ip)
        if client:
            client.http_hosts.add(request.host)
            client.findings.add(f"HTTP in chiaro verso {request.host}")
        if server:
            server.http_hosts.add(request.host)
            server.hostnames.add(request.host)
            server.findings.add(f"Servizio HTTP in chiaro per host {request.host}")


def _add_tls_evidence(accumulators: Dict[str, _HostAccumulator], tls: Optional[TLSAnalysisResult]) -> None:
    """Aggiunge SNI, hostname certificati e anomalie TLS agli host coinvolti."""
    if not tls:
        return

    for connection in tls.connections:
        client = _get(accumulators, connection.client_ip)
        server = _get(accumulators, connection.server_ip)

        for host in (client, server):
            if host and connection.sni:
                host.sni_hosts.add(connection.sni)

        if server and connection.sni:
            server.hostnames.add(connection.sni)

        for anomaly in connection.anomalies:
            if client:
                client.findings.add(f"TLS: {anomaly} verso {connection.sni or connection.server_ip or 'server'}")
            if server:
                server.findings.add(f"TLS: {anomaly}")


def _timeline_points(host: _HostAccumulator) -> List[HostTimelinePoint]:
    """Converte la timeline interna nel modello serializzabile."""
    points: List[HostTimelinePoint] = []
    for second, data in sorted(host.timeline.items()):
        points.append(HostTimelinePoint(
            timestamp=_format_second(second),
            packets_sent=data["packets_sent"],
            packets_received=data["packets_received"],
            bytes_sent=data["bytes_sent"],
            bytes_received=data["bytes_received"],
        ))
    return points[:500]


def build_hosts(
    *,
    packets: List[PacketEntry],
    flows: List[FlowEntry],
    dns: Optional[DNSAnalysisResult],
    http: Optional[HTTPAnalysisResult],
    tls: Optional[TLSAnalysisResult],
    dns_hostnames: Dict[str, set],
) -> HostAnalysisResult:
    """Costruisce la sezione `hosts` del risultato di analysis."""
    accumulators: Dict[str, _HostAccumulator] = {}

    _add_packet_evidence(accumulators, packets)
    _add_flow_evidence(accumulators, flows)
    _add_dns_evidence(accumulators, dns)
    _add_http_evidence(accumulators, http)
    _add_tls_evidence(accumulators, tls)

    # Integra anche gli hostname IP -> DNS raccolti dal parser leggero storico.
    for ip, names in dns_hostnames.items():
        host = _get(accumulators, ip)
        if host:
            host.hostnames.update(names)

    entries = [
        HostEntry(
            ip=host.ip,
            role=_host_role(host),
            is_private=_is_private_ip(host.ip),
            hostnames=sorted(host.hostnames)[:30],
            protocols=sorted(host.protocols),
            contacted_ports=sorted(host.contacted_ports),
            exposed_ports=sorted(host.exposed_ports),
            bytes_sent=host.bytes_sent,
            bytes_received=host.bytes_received,
            packets_sent=host.packets_sent,
            packets_received=host.packets_received,
            flow_ids=sorted(host.flow_ids)[:200],
            dns_queries=sorted(host.dns_queries)[:200],
            sni_hosts=sorted(host.sni_hosts)[:100],
            http_hosts=sorted(host.http_hosts)[:100],
            findings=sorted(host.findings)[:100],
            timeline=_timeline_points(host),
        )
        for host in accumulators.values()
    ]

    entries.sort(key=lambda item: item.bytes_sent + item.bytes_received, reverse=True)
    return HostAnalysisResult(total_hosts=len(entries), hosts=entries)

"""
Analysis DNS locale privacy-by-default.

This module extracts DNS queries, responses, and anomalies directly from packets in the
PCAP. Non effettua chiamate di rete: tutte le informazioni derivano dalla
capture uploaded by the user. External sources are handled separately
dall'endpoint opt-in `/api/dns-reputation`.
"""

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from scapy.layers.dns import DNS

from models import (
    DNSAnalysisResult,
    DNSAnswerEntry,
    DNSFlowCorrelation,
    DNSQueryEntry,
    DNSStats,
    DNSTopEntry,
    DNSTunnelingIndicator,
    FlowEntry,
)


QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


@dataclass
class _PendingQuery:
    """Temporary state used to correlate DNS response and query."""

    entry: DNSQueryEntry
    ts: float


@dataclass
class _DomainSignals:
    """Metriche aggregate utili a stimare DNS tunneling."""

    query_count: int = 0
    subdomains: Set[str] = field(default_factory=set)
    max_label_length: int = 0
    max_entropy: float = 0.0


def _safe_dns_name(value) -> Optional[str]:
    """Converte bytes/string DNS in domainso leggibile e normalizzato."""
    try:
        if isinstance(value, bytes):
            text = value.decode("utf-8", errors="replace")
        else:
            text = str(value)
        text = text.rstrip(".").lower()
        return text if text and "." in text else None
    except Exception:
        return None


def _record_type(value) -> str:
    """Rende leggibile il tipo record DNS."""
    try:
        number = int(value)
    except Exception:
        return str(value)
    return QTYPE_NAMES.get(number, str(number))


def _rcode_name(value: int) -> str:
    """Makes the DNS response code readable."""
    return RCODE_NAMES.get(int(value), f"RCODE_{value}")


def _format_ts(ts: float) -> str:
    """Converte timestamp Unix in ISO 8601 UTC."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _base_domain(domain: str) -> str:
    """Stima un base domain usando le ultime due label, senza dipendere da PSL."""
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    return ".".join(parts[-2:])


def _subdomain_part(domain: str, base: str) -> str:
    """Restituisce la parte di sottodomainso precedente al base domain."""
    suffix = "." + base
    if domain.endswith(suffix):
        return domain[: -len(suffix)]
    return ""


def _shannon_entropy(text: str) -> float:
    """Calcola un'entropia approssimata utile a intercettare label randomiche."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _txt_values(value) -> List[str]:
    """Normalizza rdata TXT Scapy in lista di stringhe leggibili."""
    items = value if isinstance(value, list) else [value]
    result: List[str] = []
    for item in items:
        if isinstance(item, bytes):
            result.append(item.decode("utf-8", errors="replace"))
        else:
            result.append(str(item))
    return result


def _answer_value(answer) -> str:
    """Serializes the DNS response value compactly."""
    rdata = getattr(answer, "rdata", "")
    if isinstance(rdata, bytes):
        return rdata.decode("utf-8", errors="replace").rstrip(".")
    if isinstance(rdata, list):
        return " ".join(_txt_values(rdata))
    return str(rdata).rstrip(".")


def _query_indicators(domain: str, record_type: str) -> Tuple[bool, List[str]]:
    """Valuta indicatori puntuali sulla singola query."""
    indicators: List[str] = []
    labels = domain.split(".")
    longest = max((len(label) for label in labels), default=0)
    entropy = max((_shannon_entropy(label) for label in labels), default=0.0)

    if record_type == "TXT" and longest >= 30:
        indicators.append("Query TXT con label lunga")
    if record_type == "TXT" and entropy >= 4.0:
        indicators.append("Query TXT con entropia elevata")
    if record_type == "TXT" and len(domain) >= 70:
        indicators.append("Query TXT verso domainso molto lungo")

    return bool(indicators), indicators


class DNSAnalyzer:
    """Accumulatore streaming per query, responses e indicatori DNS."""

    def __init__(self) -> None:
        # Query indicizzate per transaction id e coppia client/resolver.
        self._pending: Dict[Tuple[int, Optional[str], Optional[str]], List[_PendingQuery]] = defaultdict(list)
        # Final list of observed queries, updated when a correlated response arrives.
        self._queries: List[DNSQueryEntry] = []
        # Conteggi principali per dashboard.
        self._domain_counter: Counter = Counter()
        self._client_counter: Counter = Counter()
        self._resolver_counter: Counter = Counter()
        self._rcode_counter: Counter = Counter()
        self._domain_signals: Dict[str, _DomainSignals] = defaultdict(_DomainSignals)
        self._total_responses = 0

    def add_packet(
        self,
        *,
        packet_number: int,
        ts: float,
        pkt,
        src_ip: Optional[str],
        dst_ip: Optional[str],
    ) -> None:
        """Estrae data DNS da un packet Scapy, se contiene layer DNS."""
        if not pkt.haslayer(DNS):
            return

        try:
            dns = pkt[DNS]
            if int(dns.qr) == 0:
                self._record_query(packet_number, ts, dns, src_ip, dst_ip)
            else:
                self._record_response(packet_number, dns, src_ip, dst_ip)
        except Exception:
            # Un packet DNS malformat non deve bloccare l'intera analysis PCAP.
            return

    def _record_query(self, packet_number: int, ts: float, dns, client: Optional[str], resolver: Optional[str]) -> None:
        """Registers one or more DNS questions contained in the query packet."""
        qdcount = int(getattr(dns, "qdcount", 0) or 0)
        for index in range(max(qdcount, 1)):
            try:
                question = dns.qd[index] if qdcount > 1 else dns.qd
            except Exception:
                continue

            domain = _safe_dns_name(getattr(question, "qname", None))
            if not domain:
                continue

            record_type = _record_type(getattr(question, "qtype", "n/a"))
            suspicious_txt, indicators = _query_indicators(domain, record_type)
            entry = DNSQueryEntry(
                packet_number=packet_number,
                timestamp=_format_ts(ts),
                client=client,
                resolver=resolver,
                transaction_id=int(getattr(dns, "id", 0)),
                query=domain,
                record_type=record_type,
                suspicious_txt=suspicious_txt,
                indicators=indicators,
            )

            self._queries.append(entry)
            self._pending[(entry.transaction_id or 0, client, resolver)].append(_PendingQuery(entry=entry, ts=ts))
            self._domain_counter[domain] += 1
            if client:
                self._client_counter[client] += 1
            if resolver:
                self._resolver_counter[resolver] += 1
            self._update_domain_signals(domain)

    def _record_response(self, packet_number: int, dns, resolver: Optional[str], client: Optional[str]) -> None:
        """Records response code and answers by associating them with the pending query."""
        self._total_responses += 1
        rcode = int(getattr(dns, "rcode", 0) or 0)
        self._rcode_counter[rcode] += 1
        answers = self._answers(dns)
        key = (int(getattr(dns, "id", 0)), client, resolver)
        pending = self._pending.get(key, [])

        for item in pending:
            item.entry.response_code = rcode
            item.entry.response_code_name = _rcode_name(rcode)
            item.entry.response_packet_number = packet_number
            item.entry.answers = answers
            item.entry.ttls = sorted({answer.ttl for answer in answers if answer.ttl is not None})
            item.entry.answer_ips = [
                answer.value for answer in answers
                if answer.record_type in {"A", "AAAA"} and answer.value
            ]
            item.entry.txt_answers = [
                answer.value for answer in answers
                if answer.record_type == "TXT" and answer.value
            ]

    def _answers(self, dns) -> List[DNSAnswerEntry]:
        """Extracts answer records from a DNS response."""
        result: List[DNSAnswerEntry] = []
        ancount = int(getattr(dns, "ancount", 0) or 0)
        for index in range(ancount):
            try:
                answer = dns.an[index]
                name = _safe_dns_name(getattr(answer, "rrname", None)) or ""
                record_type = _record_type(getattr(answer, "type", "n/a"))
                value = _answer_value(answer)
                ttl = getattr(answer, "ttl", None)
                result.append(DNSAnswerEntry(
                    name=name,
                    record_type=record_type,
                    value=value,
                    ttl=int(ttl) if ttl is not None else None,
                ))
            except Exception:
                continue
        return result

    def _update_domain_signals(self, domain: str) -> None:
        """Aggiorna metriche aggregate per possibili indicatori di tunneling."""
        base = _base_domain(domain)
        signals = self._domain_signals[base]
        signals.query_count += 1
        subdomain = _subdomain_part(domain, base)
        if subdomain:
            signals.subdomains.add(subdomain)

        labels = domain.split(".")
        signals.max_label_length = max(signals.max_label_length, max((len(label) for label in labels), default=0))
        signals.max_entropy = max(signals.max_entropy, max((_shannon_entropy(label) for label in labels), default=0.0))

    def _tunneling_indicators(self) -> List[DNSTunnelingIndicator]:
        """Costruisce indicatori DNS tunneling ordinati per score."""
        indicators: List[DNSTunnelingIndicator] = []
        for domain, signals in self._domain_signals.items():
            reasons: List[str] = []
            score = 0

            if signals.max_label_length >= 45:
                score += 35
                reasons.append(f"Label molto lunga: {signals.max_label_length} caratteri")
            if len(signals.subdomains) >= 20:
                score += 30
                reasons.append(f"Molti sottodomains unici: {len(signals.subdomains)}")
            if signals.max_entropy >= 4.0:
                score += 25
                reasons.append(f"Entropia approssimata elevata: {signals.max_entropy:.2f}")
            if signals.query_count >= 50:
                score += 20
                reasons.append(f"Volume anomalo verso stesso domainso: {signals.query_count} query")

            if reasons:
                indicators.append(DNSTunnelingIndicator(
                    domain=domain,
                    score=min(score, 100),
                    query_count=signals.query_count,
                    unique_subdomains=len(signals.subdomains),
                    max_label_length=signals.max_label_length,
                    max_entropy=round(signals.max_entropy, 3),
                    reasons=reasons,
                ))

        return sorted(indicators, key=lambda item: item.score, reverse=True)[:50]

    def _flow_correlations(self, flows: List[FlowEntry]) -> List[DNSFlowCorrelation]:
        """Correlates DNS answer IPs with subsequent flows involving them."""
        correlations: Dict[Tuple[str, str], DNSFlowCorrelation] = {}
        for query in self._queries:
            if not query.answer_ips:
                continue
            query_ts = datetime.fromisoformat(query.timestamp).timestamp()
            for answer_ip in query.answer_ips:
                matched = [
                    flow.flow_id for flow in flows
                    if (flow.src_ip == answer_ip or flow.dst_ip == answer_ip)
                    and datetime.fromisoformat(flow.first_seen).timestamp() >= query_ts
                ][:10]
                if not matched:
                    continue
                key = (query.query, answer_ip)
                current = correlations.get(key) or DNSFlowCorrelation(domain=query.query, answer_ip=answer_ip)
                current.flow_ids = sorted(set(current.flow_ids + matched))
                current.dns_packet_numbers = sorted(set(current.dns_packet_numbers + [query.packet_number]))
                correlations[key] = current

        return sorted(correlations.values(), key=lambda item: (item.domain, item.answer_ip))[:100]

    def to_result(self, flows: Optional[List[FlowEntry]] = None) -> DNSAnalysisResult:
        """Produce il modello finale consumato dal frontend."""
        nxdomain_count = self._rcode_counter.get(3, 0)
        txt_query_count = len([query for query in self._queries if query.record_type == "TXT"])
        suspicious_txt_count = len([query for query in self._queries if query.suspicious_txt])
        stats = DNSStats(
            total_queries=len(self._queries),
            total_responses=self._total_responses,
            unique_domains=len(self._domain_counter),
            nxdomain_count=nxdomain_count,
            nxdomain_ratio=round(nxdomain_count / self._total_responses, 4) if self._total_responses else 0.0,
            txt_query_count=txt_query_count,
            suspicious_txt_count=suspicious_txt_count,
        )

        return DNSAnalysisResult(
            stats=stats,
            queries=self._queries[:2000],
            top_domains=[DNSTopEntry(value=value, count=count) for value, count in self._domain_counter.most_common(30)],
            top_clients=[DNSTopEntry(value=value, count=count) for value, count in self._client_counter.most_common(20)],
            top_resolvers=[DNSTopEntry(value=value, count=count) for value, count in self._resolver_counter.most_common(20)],
            tunneling_indicators=self._tunneling_indicators(),
            flow_correlations=self._flow_correlations(flows or []),
        )

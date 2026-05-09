"""
Analysis SSL/TLS basata sui soli metadata osservabili.

This module does not decrypt application traffic and does not require private keys. It reads
solo record TLS presenti nei payload TCP e prova a estrarre ClientHello,
ServerHello e certificato leaf quando l'handshake e presente nel PCAP. Se i
records are fragmented across multiple TCP segments, the entry is marked as partial
and the parser keeps only fields actually observed.
"""

import hashlib
import ssl
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from models import TLSAnalysisResult, TLSEntry, TLSStats, TLSTopEntry


TLS_VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Small but useful map of the most common cipher suites. If a suite is not in
# mappa, il codice esadecimale resta comunque disponibile nel report.
CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
}


@dataclass
class _TLSRecord:
    """Record TLS estratto da un payload TCP."""

    content_type: int
    version: int
    data: bytes
    partial: bool = False


@dataclass
class _ExtensionInfo:
    """Metadata estratti dalle estensioni TLS."""

    extension_ids: List[int] = field(default_factory=list)
    sni: Optional[str] = None
    alpn: List[str] = field(default_factory=list)
    supported_versions: List[int] = field(default_factory=list)
    selected_version: Optional[int] = None
    elliptic_curves: List[int] = field(default_factory=list)
    ec_point_formats: List[int] = field(default_factory=list)


def _format_ts(ts: float) -> str:
    """Converte timestamp Unix in ISO 8601 UTC."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _u16(data: bytes, offset: int) -> int:
    """Legge un intero unsigned a 16 bit big-endian."""
    return int.from_bytes(data[offset:offset + 2], "big")


def _u24(data: bytes, offset: int) -> int:
    """Legge un intero unsigned a 24 bit big-endian."""
    return int.from_bytes(data[offset:offset + 3], "big")


def _version_name(value: Optional[int]) -> Optional[str]:
    """Rende leggibile una versione TLS."""
    if value is None:
        return None
    return TLS_VERSION_NAMES.get(value, f"0x{value:04x}")


def _cipher_name(value: Optional[int]) -> Optional[str]:
    """Rende leggibile una cipher suite TLS."""
    if value is None:
        return None
    return CIPHER_NAMES.get(value, f"0x{value:04x}")


def _is_grease(value: int) -> bool:
    """Riconosce valori GREASE da escludere da JA3/JA3S."""
    return value in {
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    }


def _ja3_list(values: List[int]) -> str:
    """Serializza una lista JA3 rimuovendo i valori GREASE."""
    return "-".join(str(value) for value in values if not _is_grease(value))


def _fingerprint_ja3(parts: List[str]) -> Tuple[str, str]:
    """Calcola stringa JA3/JA3S e hash MD5 come da convenzione."""
    raw = ",".join(parts)
    return raw, hashlib.md5(raw.encode("ascii")).hexdigest()


def _extract_records(payload: bytes) -> List[_TLSRecord]:
    """Extracts complete TLS records from the observed TCP payload."""
    records: List[_TLSRecord] = []
    offset = 0

    while offset + 5 <= len(payload):
        content_type = payload[offset]
        if content_type not in (20, 21, 22, 23):
            break

        version = _u16(payload, offset + 1)
        length = _u16(payload, offset + 3)
        record_start = offset + 5
        record_end = record_start + length
        if record_end > len(payload):
            # The record continues in a segment not available in this payload.
            records.append(_TLSRecord(content_type, version, payload[record_start:], partial=True))
            break

        records.append(_TLSRecord(content_type, version, payload[record_start:record_end]))
        offset = record_end

    return records


def _handshake_messages(record: _TLSRecord) -> List[Tuple[int, bytes, bool]]:
    """Divide un record handshake nei singoli messaggi TLS contenuti."""
    messages: List[Tuple[int, bytes, bool]] = []
    if record.content_type != 22:
        return messages

    offset = 0
    data = record.data
    while offset + 4 <= len(data):
        msg_type = data[offset]
        length = _u24(data, offset + 1)
        start = offset + 4
        end = start + length
        if end > len(data):
            messages.append((msg_type, data[start:], True))
            break
        messages.append((msg_type, data[start:end], record.partial))
        offset = end

    return messages


def _parse_extensions(data: bytes, *, server_hello: bool = False) -> _ExtensionInfo:
    """Parsa le estensioni TLS note e conserva anche gli ID per JA3/JA3S."""
    info = _ExtensionInfo()
    offset = 0
    while offset + 4 <= len(data):
        ext_type = _u16(data, offset)
        ext_len = _u16(data, offset + 2)
        ext_data = data[offset + 4:offset + 4 + ext_len]
        if len(ext_data) < ext_len:
            break

        info.extension_ids.append(ext_type)

        if ext_type == 0 and len(ext_data) >= 5:
            # Server Name Indication: lista di nomi, normalmente uno solo.
            list_len = _u16(ext_data, 0)
            cursor = 2
            while cursor + 3 <= min(len(ext_data), 2 + list_len):
                name_type = ext_data[cursor]
                name_len = _u16(ext_data, cursor + 1)
                name = ext_data[cursor + 3:cursor + 3 + name_len]
                if name_type == 0 and len(name) == name_len:
                    info.sni = name.decode("ascii", errors="ignore").lower()
                    break
                cursor += 3 + name_len

        elif ext_type == 16 and len(ext_data) >= 2:
            # ALPN: lista length-prefixed di protocolli applicativi.
            list_len = _u16(ext_data, 0)
            cursor = 2
            while cursor + 1 <= min(len(ext_data), 2 + list_len):
                proto_len = ext_data[cursor]
                proto = ext_data[cursor + 1:cursor + 1 + proto_len]
                if len(proto) != proto_len:
                    break
                info.alpn.append(proto.decode("ascii", errors="ignore"))
                cursor += 1 + proto_len

        elif ext_type == 43 and ext_data:
            # supported_versions: a list in ClientHello, a single value in ServerHello.
            if server_hello and len(ext_data) >= 2:
                info.selected_version = _u16(ext_data, 0)
            elif len(ext_data) >= 3:
                total = ext_data[0]
                cursor = 1
                while cursor + 2 <= min(len(ext_data), 1 + total):
                    info.supported_versions.append(_u16(ext_data, cursor))
                    cursor += 2

        elif ext_type == 10 and len(ext_data) >= 2:
            # supported_groups / elliptic_curves used in the JA3 string.
            total = _u16(ext_data, 0)
            cursor = 2
            while cursor + 2 <= min(len(ext_data), 2 + total):
                info.elliptic_curves.append(_u16(ext_data, cursor))
                cursor += 2

        elif ext_type == 11 and ext_data:
            # ec_point_formats usato nella stringa JA3.
            total = ext_data[0]
            info.ec_point_formats = list(ext_data[1:1 + total])

        offset += 4 + ext_len

    return info


def _parse_client_hello(body: bytes) -> Optional[Dict]:
    """Estrae metadata dal ClientHello."""
    try:
        if len(body) < 42:
            return None
        legacy_version = _u16(body, 0)
        offset = 34  # version + random
        session_len = body[offset]
        offset += 1 + session_len
        cipher_len = _u16(body, offset)
        offset += 2
        ciphers = [_u16(body, idx) for idx in range(offset, offset + cipher_len, 2) if idx + 2 <= len(body)]
        offset += cipher_len
        comp_len = body[offset]
        offset += 1 + comp_len

        ext_info = _ExtensionInfo()
        if offset + 2 <= len(body):
            ext_len = _u16(body, offset)
            offset += 2
            ext_info = _parse_extensions(body[offset:offset + ext_len])

        best_version = max([value for value in ext_info.supported_versions if not _is_grease(value)], default=legacy_version)
        ja3_string, ja3 = _fingerprint_ja3([
            str(legacy_version),
            _ja3_list(ciphers),
            _ja3_list(ext_info.extension_ids),
            _ja3_list(ext_info.elliptic_curves),
            _ja3_list(ext_info.ec_point_formats),
        ])

        return {
            "sni": ext_info.sni,
            "version": best_version,
            "alpn": ext_info.alpn,
            "ciphers": ciphers,
            "ja3": ja3,
            "ja3_string": ja3_string,
        }
    except Exception:
        return None


def _parse_server_hello(body: bytes) -> Optional[Dict]:
    """Estrae metadata dal ServerHello."""
    try:
        if len(body) < 38:
            return None
        legacy_version = _u16(body, 0)
        offset = 34
        session_len = body[offset]
        offset += 1 + session_len
        cipher = _u16(body, offset)
        offset += 3  # cipher suite + compression method

        ext_info = _ExtensionInfo()
        if offset + 2 <= len(body):
            ext_len = _u16(body, offset)
            offset += 2
            ext_info = _parse_extensions(body[offset:offset + ext_len], server_hello=True)

        selected_version = ext_info.selected_version or legacy_version
        ja3s_string, ja3s = _fingerprint_ja3([
            str(legacy_version),
            str(cipher),
            _ja3_list(ext_info.extension_ids),
        ])

        return {
            "version": selected_version,
            "cipher": cipher,
            "alpn": ext_info.alpn,
            "ja3s": ja3s,
            "ja3s_string": ja3s_string,
        }
    except Exception:
        return None


def _split_name(items) -> Optional[str]:
    """Converte subject/issuer di ssl._test_decode_cert in stringa leggibile."""
    if not items:
        return None
    parts: List[str] = []
    try:
        for group in items:
            for key, value in group:
                parts.append(f"{key}={value}")
    except Exception:
        return None
    return ", ".join(parts) if parts else None


def _parse_cert_time(value: Optional[str]) -> Optional[datetime]:
    """Converte le date testuali dei certificati in datetime UTC."""
    if not value:
        return None
    normalized = " ".join(value.split())
    try:
        return datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _decode_certificate(der: bytes) -> Dict:
    """Estrae metadata X.509 dal certificato DER leaf."""
    result = {
        "sha256": hashlib.sha256(der).hexdigest(),
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "not_before_dt": None,
        "not_after_dt": None,
    }

    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        # The stdlib exposes the X.509 decoder only through a file path. The file
        # temporary file contains the certificate already present in the PCAP and is
        # rimosso subito dopo la lettura.
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as handle:
            handle.write(pem)
            handle.flush()
            decoded = ssl._ssl._test_decode_cert(handle.name)  # type: ignore[attr-defined]

        result["subject"] = _split_name(decoded.get("subject"))
        result["issuer"] = _split_name(decoded.get("issuer"))
        result["not_before"] = decoded.get("notBefore")
        result["not_after"] = decoded.get("notAfter")
        result["not_before_dt"] = _parse_cert_time(decoded.get("notBefore"))
        result["not_after_dt"] = _parse_cert_time(decoded.get("notAfter"))
    except Exception:
        # Anche se il decoding X.509 fallisce, il fingerprint resta utile.
        pass

    return result


def _extract_certificate_chain(body: bytes) -> List[bytes]:
    """Estrae certificati DER da messaggi Certificate TLS 1.2 o TLS 1.3."""
    candidates: List[bytes] = []

    def parse_list(data: bytes) -> List[bytes]:
        certs: List[bytes] = []
        if len(data) < 3:
            return certs
        total = _u24(data, 0)
        cursor = 3
        end = min(len(data), 3 + total)
        while cursor + 3 <= end:
            cert_len = _u24(data, cursor)
            cursor += 3
            cert = data[cursor:cursor + cert_len]
            if len(cert) != cert_len:
                break
            certs.append(cert)
            cursor += cert_len
            # TLS 1.3 aggiunge estensioni per ogni certificate entry.
            if cursor + 2 <= end:
                ext_len = _u16(data, cursor)
                if cursor + 2 + ext_len <= end:
                    cursor += 2 + ext_len
        return certs

    # TLS format 1.2: certificate_list immediately at the beginning of the body.
    candidates = parse_list(body)
    if candidates:
        return candidates

    # TLS format 1.3: context length + context + certificate_list.
    if body:
        context_len = body[0]
        start = 1 + context_len
        if start < len(body):
            return parse_list(body[start:])

    return []


class TLSAnalyzer:
    """Accumulatore streaming per metadata TLS osservabili."""

    def __init__(self) -> None:
        # Entry indicizzate dal flow direzionale client -> server.
        self._connections: Dict[Tuple[str, int, str, int], TLSEntry] = {}
        self._order: List[Tuple[str, int, str, int]] = []
        self._sni_counter: Counter = Counter()
        self._issuer_counter: Counter = Counter()
        self._version_counter: Counter = Counter()
        self._expired = 0
        self._legacy = 0

    def add_packet(
        self,
        *,
        packet_number: int,
        ts: float,
        src_ip: Optional[str],
        src_port: Optional[int],
        dst_ip: Optional[str],
        dst_port: Optional[int],
        payload: Optional[bytes],
    ) -> None:
        """Analyzes TLS records contained in a TCP payload."""
        if not src_ip or not dst_ip or src_port is None or dst_port is None or not payload:
            return

        records = _extract_records(payload)
        if not records:
            return

        for record in records:
            for msg_type, body, msg_partial in _handshake_messages(record):
                partial = record.partial or msg_partial
                if msg_type == 1:
                    parsed = _parse_client_hello(body)
                    if parsed:
                        self._record_client_hello(packet_number, ts, src_ip, src_port, dst_ip, dst_port, parsed, partial)
                elif msg_type == 2:
                    parsed = _parse_server_hello(body)
                    if parsed:
                        self._record_server_hello(src_ip, src_port, dst_ip, dst_port, parsed, partial)
                elif msg_type == 11:
                    self._record_certificate(packet_number, ts, src_ip, src_port, dst_ip, dst_port, body, partial)

    def _entry_for_key(self, key: Tuple[str, int, str, int], packet_number: int, ts: float) -> TLSEntry:
        """Recupera o crea una connessione TLS mantenendo ordine stabile."""
        if key not in self._connections:
            client_ip, client_port, server_ip, server_port = key
            self._connections[key] = TLSEntry(
                packet_number=packet_number,
                timestamp=_format_ts(ts),
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
            )
            self._order.append(key)
        return self._connections[key]

    def _record_client_hello(
        self,
        packet_number: int,
        ts: float,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        parsed: Dict,
        partial: bool,
    ) -> None:
        """Registra SNI, ALPN, versione offerta e JA3 dal ClientHello."""
        key = (client_ip, client_port, server_ip, server_port)
        entry = self._entry_for_key(key, packet_number, ts)
        entry.sni = parsed.get("sni") or entry.sni
        entry.tls_version = _version_name(parsed.get("version")) or entry.tls_version
        entry.alpn = sorted(set(entry.alpn + parsed.get("alpn", [])))
        entry.ja3 = parsed.get("ja3")
        entry.ja3_string = parsed.get("ja3_string")
        entry.partial = entry.partial or partial

    def _record_server_hello(
        self,
        server_ip: str,
        server_port: int,
        client_ip: str,
        client_port: int,
        parsed: Dict,
        partial: bool,
    ) -> None:
        """Aggiorna la connessione con versione/cipher negoziate e JA3S."""
        key = (client_ip, client_port, server_ip, server_port)
        entry = self._connections.get(key)
        if not entry:
            return

        entry.tls_version = _version_name(parsed.get("version")) or entry.tls_version
        entry.cipher_suite = _cipher_name(parsed.get("cipher")) or entry.cipher_suite
        entry.alpn = sorted(set(entry.alpn + parsed.get("alpn", [])))
        entry.ja3s = parsed.get("ja3s")
        entry.ja3s_string = parsed.get("ja3s_string")
        entry.partial = entry.partial or partial

    def _record_certificate(
        self,
        packet_number: int,
        ts: float,
        server_ip: str,
        server_port: int,
        client_ip: str,
        client_port: int,
        body: bytes,
        partial: bool,
    ) -> None:
        """Estrae subject, issuer, validita e fingerprint dal certificato leaf."""
        key = (client_ip, client_port, server_ip, server_port)
        entry = self._connections.get(key)
        if not entry:
            # Se manca il ClientHello nel PCAP, conserva comunque il certificato.
            entry = self._entry_for_key(key, packet_number, ts)

        chain = _extract_certificate_chain(body)
        if not chain:
            entry.partial = True
            return

        cert = _decode_certificate(chain[0])
        entry.cert_sha256 = cert.get("sha256")
        entry.cert_subject = cert.get("subject")
        entry.cert_issuer = cert.get("issuer")
        entry.cert_not_before = cert.get("not_before")
        entry.cert_not_after = cert.get("not_after")
        entry.partial = entry.partial or partial

        capture_time = datetime.fromtimestamp(ts, tz=timezone.utc)
        not_after = cert.get("not_after_dt")
        not_before = cert.get("not_before_dt")
        if not_after and capture_time > not_after:
            entry.anomalies.append("certificato scaduto")
        if not_before and capture_time < not_before:
            entry.anomalies.append("certificato non ancora valido")
        if entry.cert_subject and entry.cert_issuer and entry.cert_subject == entry.cert_issuer:
            entry.anomalies.append("certificato self-signed")

    def _finalize_anomalies(self, dns_hostnames: Optional[Dict[str, set]]) -> None:
        """Adds anomalies inferable after observing the whole capture."""
        for entry in self._connections.values():
            if not entry.sni:
                entry.anomalies.append("SNI mancante")
            if entry.tls_version in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
                entry.anomalies.append("TLS vecchio")

            # Approximate comparison between SNI and DNS names observed for the same IP.
            hostnames = sorted((dns_hostnames or {}).get(entry.server_ip or "", set()))
            if entry.sni and hostnames:
                normalized = entry.sni.lower().rstrip(".")
                matched = any(normalized == host.lower().rstrip(".") or normalized.endswith("." + host.lower().rstrip(".")) for host in hostnames)
                if not matched:
                    entry.anomalies.append("mismatch approssimato DNS/SNI")

            # Removes duplicates while preserving order for a more readable UI.
            entry.anomalies = list(dict.fromkeys(entry.anomalies))

    def to_result(self, dns_hostnames: Optional[Dict[str, set]] = None) -> TLSAnalysisResult:
        """Produce il risultato serializzabile per il frontend."""
        self._finalize_anomalies(dns_hostnames)
        connections = [self._connections[key] for key in self._order]

        self._sni_counter = Counter(entry.sni for entry in connections if entry.sni)
        self._issuer_counter = Counter(entry.cert_issuer for entry in connections if entry.cert_issuer)
        self._version_counter = Counter(entry.tls_version for entry in connections if entry.tls_version)
        self._expired = sum(1 for entry in connections if "certificato scaduto" in entry.anomalies)
        self._legacy = sum(1 for entry in connections if "TLS vecchio" in entry.anomalies)

        stats = TLSStats(
            total_connections=len(connections),
            with_sni=sum(1 for entry in connections if entry.sni),
            with_certificate=sum(1 for entry in connections if entry.cert_sha256),
            anomalous_connections=sum(1 for entry in connections if entry.anomalies),
            expired_certificates=self._expired,
            legacy_tls=self._legacy,
        )

        return TLSAnalysisResult(
            stats=stats,
            connections=connections[:2000],
            top_sni=[TLSTopEntry(value=value, count=count) for value, count in self._sni_counter.most_common(30)],
            top_issuers=[TLSTopEntry(value=value, count=count) for value, count in self._issuer_counter.most_common(30)],
            top_versions=[TLSTopEntry(value=value, count=count) for value, count in self._version_counter.most_common(20)],
            limitations=[
                "Does not decrypt TLS traffic and does not recover application content.",
                "Extracts only metadata present in the handshake observed in the PCAP.",
                "TLS records fragmented across multiple TCP segments may be partial.",
                "Subject e issuer sono disponibili solo se il certificato e presente e decodificabile.",
                "DNS/SNI mismatch is heuristic and uses only DNS responses observed in the capture.",
            ],
        )

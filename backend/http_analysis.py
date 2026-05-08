"""
Analisi HTTP in chiaro.

Il parser lavora solo su payload TCP leggibili che iniziano come richiesta o
risposta HTTP. Non tenta di decifrare TLS e non ricostruisce stream TCP completi:
se gli header sono frammentati o incompleti, registra il metadato disponibile e
marca l'entry come parziale.
"""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from models import HTTPAnalysisResult, HTTPRequestEntry, HTTPStats, HTTPTopEntry


HTTP_METHODS = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
}


@dataclass
class _ParsedHTTP:
    """Risultato interno del parsing di un segmento HTTP."""

    kind: str
    first: str
    headers: Dict[str, str]
    partial: bool
    payload_size: int


def _format_ts(ts: float) -> str:
    """Converte timestamp Unix in ISO 8601 UTC."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _decode_payload(payload: bytes) -> Optional[str]:
    """Decodifica payload HTTP usando ISO-8859-1, standard compatibile con header HTTP."""
    if not payload:
        return None
    if b"\x00" in payload[:32]:
        return None
    try:
        return payload.decode("iso-8859-1", errors="replace")
    except Exception:
        return None


def _header_end(text: str) -> Tuple[int, int]:
    """Trova fine header e lunghezza delimitatore CRLF/LF."""
    crlf = text.find("\r\n\r\n")
    if crlf >= 0:
        return crlf, 4
    lf = text.find("\n\n")
    if lf >= 0:
        return lf, 2
    return -1, 0


def _parse_headers(lines: List[str]) -> Dict[str, str]:
    """Converte righe header in dizionario case-insensitive semplificato."""
    headers: Dict[str, str] = {}
    current_name: Optional[str] = None
    for line in lines:
        if not line:
            continue
        if line[:1] in (" ", "\t") and current_name:
            headers[current_name] = f"{headers[current_name]} {line.strip()}"
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        current_name = name.strip().lower()
        headers[current_name] = value.strip()
    return headers


def _parse_http_payload(payload: bytes) -> Optional[_ParsedHTTP]:
    """Riconosce e parsa una richiesta o risposta HTTP da un singolo segmento TCP."""
    text = _decode_payload(payload)
    if not text:
        return None

    first_line = text.splitlines()[0] if text.splitlines() else ""
    first_parts = first_line.split()
    is_request = len(first_parts) >= 3 and first_parts[0].upper() in HTTP_METHODS and first_parts[2].startswith("HTTP/")
    is_response = first_line.startswith("HTTP/") and len(first_parts) >= 2
    if not is_request and not is_response:
        return None

    header_end, delimiter_len = _header_end(text)
    partial = header_end < 0
    header_text = text[:header_end] if header_end >= 0 else text
    lines = header_text.replace("\r\n", "\n").split("\n")
    headers = _parse_headers(lines[1:])
    payload_size = max(0, len(payload) - (header_end + delimiter_len)) if header_end >= 0 else 0

    return _ParsedHTTP(
        kind="request" if is_request else "response",
        first=first_line,
        headers=headers,
        partial=partial,
        payload_size=payload_size,
    )


def _int_header(value: Optional[str]) -> Optional[int]:
    """Converte un header numerico, restituendo None se non valido."""
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _content_disposition_filename(value: Optional[str]) -> Optional[str]:
    """Estrae filename da Content-Disposition, se presente."""
    if not value:
        return None
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', value, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip()


def _filename_from_uri(uri: str) -> Optional[str]:
    """Deduce un nome file dalla path URI quando ha una forma plausibile."""
    path = urlparse(uri).path if uri else ""
    name = path.rstrip("/").split("/")[-1]
    if "." in name and len(name) <= 160:
        return name
    return None


class HTTPAnalyzer:
    """Accumulatore streaming per metadati HTTP in chiaro."""

    def __init__(self) -> None:
        # Richieste pendenti indicizzate per flow direzionale client -> server.
        self._pending: Dict[Tuple[str, int, str, int], List[HTTPRequestEntry]] = defaultdict(list)
        self._requests: List[HTTPRequestEntry] = []
        self._host_counter: Counter = Counter()
        self._ua_counter: Counter = Counter()
        self._total_responses = 0
        self._partial_responses = 0

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
        """Analizza un payload TCP e aggiorna richieste/risposte HTTP."""
        if not src_ip or not dst_ip or src_port is None or dst_port is None or not payload:
            return

        parsed = _parse_http_payload(payload)
        if not parsed:
            return

        if parsed.kind == "request":
            self._record_request(packet_number, ts, src_ip, src_port, dst_ip, dst_port, parsed)
        else:
            self._record_response(packet_number, src_ip, src_port, dst_ip, dst_port, parsed)

    def _record_request(
        self,
        packet_number: int,
        ts: float,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        parsed: _ParsedHTTP,
    ) -> None:
        """Registra una richiesta HTTP e la mette in attesa della risposta."""
        parts = parsed.first.split()
        method = parts[0].upper()
        uri = parts[1] if len(parts) > 1 else ""
        host = parsed.headers.get("host")
        content_length = _int_header(parsed.headers.get("content-length"))
        payload_size = content_length if content_length is not None else parsed.payload_size

        entry = HTTPRequestEntry(
            packet_number=packet_number,
            timestamp=_format_ts(ts),
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            method=method,
            host=host,
            uri=uri,
            user_agent=parsed.headers.get("user-agent"),
            referer=parsed.headers.get("referer") or parsed.headers.get("referrer"),
            content_type=parsed.headers.get("content-type"),
            payload_size=payload_size,
            partial=parsed.partial,
        )

        self._requests.append(entry)
        self._pending[(client_ip, client_port, server_ip, server_port)].append(entry)
        if host:
            self._host_counter[host] += 1
        if entry.user_agent:
            self._ua_counter[entry.user_agent] += 1

    def _record_response(
        self,
        packet_number: int,
        server_ip: str,
        server_port: int,
        client_ip: str,
        client_port: int,
        parsed: _ParsedHTTP,
    ) -> None:
        """Correla una risposta HTTP alla prima richiesta pendente sul verso opposto."""
        self._total_responses += 1
        if parsed.partial:
            self._partial_responses += 1

        parts = parsed.first.split(maxsplit=2)
        status_code = _int_header(parts[1] if len(parts) > 1 else None)
        reason = parts[2] if len(parts) > 2 else None
        content_length = _int_header(parsed.headers.get("content-length"))
        key = (client_ip, client_port, server_ip, server_port)
        pending = self._pending.get(key, [])
        request = pending.pop(0) if pending else None
        if not request:
            return

        request.response_packet_number = packet_number
        request.response_status_code = status_code
        request.response_reason = reason
        request.response_server = parsed.headers.get("server")
        request.response_content_type = parsed.headers.get("content-type")
        request.response_content_length = content_length
        request.response_partial = parsed.partial
        request.response_file_name = (
            _content_disposition_filename(parsed.headers.get("content-disposition"))
            or _filename_from_uri(request.uri)
        )

    def to_result(self) -> HTTPAnalysisResult:
        """Produce il risultato serializzabile per il frontend."""
        correlated = len([request for request in self._requests if request.response_packet_number is not None])
        partial_requests = len([request for request in self._requests if request.partial])
        stats = HTTPStats(
            total_requests=len(self._requests),
            total_responses=self._total_responses,
            correlated_responses=correlated,
            partial_requests=partial_requests,
            partial_responses=self._partial_responses,
            unique_hosts=len(self._host_counter),
        )

        return HTTPAnalysisResult(
            stats=stats,
            requests=self._requests[:2000],
            top_hosts=[HTTPTopEntry(value=value, count=count) for value, count in self._host_counter.most_common(30)],
            top_user_agents=[HTTPTopEntry(value=value, count=count) for value, count in self._ua_counter.most_common(30)],
            limitations=[
                "Analizza solo traffico HTTP in chiaro su TCP.",
                "Non decifra HTTPS/TLS.",
                "Non ricostruisce stream TCP completi: header o body frammentati possono risultare parziali.",
                "La dimensione payload e stimata da Content-Length o dai byte presenti nel segmento osservato.",
            ],
        )

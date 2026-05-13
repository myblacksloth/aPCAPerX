"""
Follow-stream reconstruction for TCP and UDP payloads.

The analyzer keeps bounded payload evidence while the PCAP is read in streaming
mode. It does not try to decrypt TLS and it does not store unlimited payloads;
the output is meant for Wireshark-style triage inside the web report.
"""

import hashlib
import string
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from config import FOLLOW_STREAM_MAX_BYTES_PER_STREAM, FOLLOW_STREAM_MAX_SEGMENT_BYTES, FOLLOW_STREAM_MAX_STREAMS


EndpointTuple = Tuple[str, Optional[int], str, Optional[int], str]
BidirectionalKey = Tuple[Tuple[str, Optional[int]], Tuple[str, Optional[int]], str]


@dataclass
class _PayloadSegment:
    """One application-payload fragment observed in a packet."""

    packet_number: int
    timestamp: str
    direction: str
    sequence: Optional[int]
    payload: bytes


@dataclass
class _StreamState:
    """Internal bounded state for one bidirectional stream."""

    stream_id: str
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    transport_protocol: str
    segments: List[_PayloadSegment] = field(default_factory=list)
    bytes_total: int = 0
    truncated: bool = False


def _stable_stream_id(src_ip: str, src_port: Optional[int], dst_ip: str, dst_port: Optional[int], protocol: str) -> str:
    """Create the same stable id shape used by flow analysis."""
    raw = f"{src_ip}|{src_port or 0}|{dst_ip}|{dst_port or 0}|{protocol.upper()}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _bidirectional_key(src_ip: str, src_port: Optional[int], dst_ip: str, dst_port: Optional[int], protocol: str) -> BidirectionalKey:
    """Build a direction-independent key so both directions share one stream."""
    left = (src_ip, src_port)
    right = (dst_ip, dst_port)
    return (left, right, protocol) if left <= right else (right, left, protocol)


def _is_client_to_server(stream: _StreamState, src_ip: str, src_port: Optional[int], dst_ip: str, dst_port: Optional[int]) -> bool:
    """Return whether the packet follows the stream's first observed direction."""
    return (
        src_ip == stream.src_ip
        and src_port == stream.src_port
        and dst_ip == stream.dst_ip
        and dst_port == stream.dst_port
    )


def _decode_payload(payload: bytes) -> str:
    """Decode bytes into readable text while preserving non-printable evidence."""
    text = payload.decode("utf-8", errors="replace")
    printable = set(string.printable)
    return "".join(char if char in printable or char in "\r\n\t" else "." for char in text)


def _application_protocol(src_port: Optional[int], dst_port: Optional[int], payloads: List[bytes]) -> Optional[str]:
    """Infer the visible application protocol from ports and plaintext prefixes."""
    ports = {src_port, dst_port}
    first_bytes = b"".join(payloads[:3]).lstrip()[:32].upper()
    if ports & {80, 8080, 8000, 8888} or first_bytes.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"HTTP/")):
        return "HTTP"
    if ports & {53}:
        return "DNS"
    if ports & {25, 465, 587}:
        return "SMTP"
    if ports & {110, 995}:
        return "POP3"
    if ports & {143, 993}:
        return "IMAP"
    return None


def _ordered_segments(stream: _StreamState) -> List[_PayloadSegment]:
    """Order TCP by direction and sequence number; UDP remains capture-order."""
    if stream.transport_protocol != "TCP":
        return sorted(stream.segments, key=lambda item: item.packet_number)
    return sorted(
        stream.segments,
        key=lambda item: (
            0 if item.direction == "client_to_server" else 1,
            item.sequence if item.sequence is not None else item.packet_number,
            item.packet_number,
        ),
    )


class FollowStreamAnalyzer:
    """Accumulates bounded TCP/UDP payloads and converts them to report entries."""

    def __init__(self) -> None:
        self._streams: Dict[BidirectionalKey, _StreamState] = {}

    def add_packet(
        self,
        *,
        packet_number: int,
        timestamp: str,
        src_ip: Optional[str],
        src_port: Optional[int],
        dst_ip: Optional[str],
        dst_port: Optional[int],
        protocol: str,
        payload: Optional[bytes],
        sequence: Optional[int] = None,
    ) -> None:
        """Attach one packet payload to its bidirectional stream."""
        if not payload or not src_ip or not dst_ip or src_port is None or dst_port is None:
            return
        if protocol not in {"TCP", "UDP"}:
            return

        key = _bidirectional_key(src_ip, src_port, dst_ip, dst_port, protocol)
        stream = self._streams.get(key)
        if stream is None:
            if len(self._streams) >= FOLLOW_STREAM_MAX_STREAMS:
                return
            stream = _StreamState(
                stream_id=_stable_stream_id(src_ip, src_port, dst_ip, dst_port, protocol),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                transport_protocol=protocol,
            )
            self._streams[key] = stream

        remaining = FOLLOW_STREAM_MAX_BYTES_PER_STREAM - stream.bytes_total
        if remaining <= 0:
            stream.truncated = True
            return

        stored_payload = payload[:remaining]
        stream.truncated = stream.truncated or len(stored_payload) < len(payload)
        stream.bytes_total += len(stored_payload)
        direction = "client_to_server" if _is_client_to_server(stream, src_ip, src_port, dst_ip, dst_port) else "server_to_client"
        stream.segments.append(_PayloadSegment(
            packet_number=packet_number,
            timestamp=timestamp,
            direction=direction,
            sequence=sequence,
            payload=stored_payload,
        ))

    def to_entries(self):
        """Convert internal stream state into serializable Pydantic models."""
        from models import FollowStreamEntry, FollowStreamSegment

        entries: List[FollowStreamEntry] = []
        for stream in self._streams.values():
            ordered = _ordered_segments(stream)
            payloads = [segment.payload for segment in ordered]
            client_payload = b"".join(segment.payload for segment in ordered if segment.direction == "client_to_server")
            server_payload = b"".join(segment.payload for segment in ordered if segment.direction == "server_to_client")
            combined_lines = []
            for segment in sorted(stream.segments, key=lambda item: item.packet_number):
                label = "C -> S" if segment.direction == "client_to_server" else "S -> C"
                combined_lines.append(f"--- packet {segment.packet_number} {label} ({len(segment.payload)} bytes) ---")
                combined_lines.append(_decode_payload(segment.payload[:FOLLOW_STREAM_MAX_SEGMENT_BYTES]))

            entries.append(FollowStreamEntry(
                stream_id=stream.stream_id,
                src_ip=stream.src_ip,
                src_port=stream.src_port,
                dst_ip=stream.dst_ip,
                dst_port=stream.dst_port,
                transport_protocol=stream.transport_protocol,
                application_protocol=_application_protocol(stream.src_port, stream.dst_port, payloads),
                packets=len(stream.segments),
                bytes=stream.bytes_total,
                truncated=stream.truncated,
                client_text=_decode_payload(client_payload),
                server_text=_decode_payload(server_payload),
                combined_text="\n".join(combined_lines),
                segments=[
                    FollowStreamSegment(
                        packet_number=segment.packet_number,
                        timestamp=segment.timestamp,
                        direction=segment.direction,
                        sequence=segment.sequence,
                        length=len(segment.payload),
                        text=_decode_payload(segment.payload[:FOLLOW_STREAM_MAX_SEGMENT_BYTES]),
                        hex_preview=segment.payload[:FOLLOW_STREAM_MAX_SEGMENT_BYTES].hex(),
                        truncated=len(segment.payload) > FOLLOW_STREAM_MAX_SEGMENT_BYTES,
                    )
                    for segment in sorted(stream.segments, key=lambda item: item.packet_number)
                ],
            ))

        return sorted(entries, key=lambda item: item.bytes, reverse=True)

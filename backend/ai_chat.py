"""
Lightweight AI chat integration for PCAPCaper.

The backend acts as a privacy and resource gatekeeper: it receives the user's
question and the packet list already available in the browser, selects only the
small subset that is relevant to the question, and sends a compact JSON context
to the model service.
"""

import json
import re
import socket
import urllib.error
import urllib.request
from typing import Iterable, List, Sequence, Set, Tuple

from config import (
    AI_BASE_URL,
    AI_MAX_HISTORY_MESSAGES,
    AI_MAX_PACKETS,
    AI_MODEL,
    AI_NUM_CTX,
    AI_NUM_PREDICT,
    AI_TIMEOUT_SECONDS,
)
from models import AIChatMessage, AIChatRequest, AIChatResponse, AISelectedPacket, PacketEntry


_STOPWORDS = {
    "about", "after", "again", "also", "and", "any", "are", "can", "che", "con",
    "cosa", "del", "della", "delle", "degli", "dei", "for", "from", "hai",
    "have", "how", "nel", "nella", "per", "show", "the", "this", "tra", "una",
    "uno", "verso", "what", "when", "where", "which", "with",
}
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PORT_RE = re.compile(r"(?:port|porta|tcp|udp|:)\s*(\d{1,5})\b", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-zA-Z0-9_.:-]{3,}")
_GENERIC_TERMS = {"summary", "summarize", "overview", "capture", "traffic", "analisi", "riepilogo", "traffico"}
_KNOWN_PROTOCOLS = {"arp", "icmp", "dns", "http", "https", "tls", "tcp", "udp", "dhcp", "ntp", "smtp", "ftp", "ssh"}


class AIModelError(RuntimeError):
    """Raised when the model server responds but cannot run the request."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def _tokens(question: str) -> Set[str]:
    """Extract searchable terms while dropping very common words."""
    return {
        token.lower()
        for token in _WORD_RE.findall(question)
        if token.lower() not in _STOPWORDS and not token.isdigit()
    }


def _ports(question: str) -> Set[int]:
    """Extract explicit port references from the question."""
    ports = set()
    for raw in _PORT_RE.findall(question):
        try:
            value = int(raw)
        except ValueError:
            continue
        if 0 < value <= 65535:
            ports.add(value)
    return ports


def _packet_text(packet: PacketEntry) -> str:
    """Build a compact searchable string for a packet without raw bytes."""
    parts = [
        str(packet.number),
        packet.timestamp,
        packet.src_ip or "",
        packet.dst_ip or "",
        str(packet.src_port or ""),
        str(packet.dst_port or ""),
        packet.protocol,
        packet.info,
    ]
    for layer in packet.layers[:4]:
        parts.append(layer.name)
        for field in layer.fields[:8]:
            parts.append(field.name)
            parts.append(field.value)
    return " ".join(parts).lower()


def _score_packet(packet: PacketEntry, terms: Set[str], ips: Set[str], ports: Set[int], protocols: Set[str]) -> int:
    """Assign a deterministic relevance score to a packet for the user question."""
    score = 0
    text = _packet_text(packet)

    if packet.src_ip in ips or packet.dst_ip in ips:
        score += 20
    if packet.src_port in ports or packet.dst_port in ports:
        score += 14
    if packet.protocol.lower() in protocols:
        score += 10

    for term in terms:
        if term in text:
            score += 3

    # DNS/HTTP/TLS fields often carry the semantic answer, but they should only
    # boost packets that already matched the user's question.
    if score > 0 and any(term in text for term in ("query", "host", "sni", "user-agent", "status", "rcode")):
        score += 1
    return score


def _compact_packet(packet: PacketEntry, score: int) -> AISelectedPacket:
    """Convert a packet to the minimal structure allowed to reach the model."""
    src = packet.src_ip or ""
    dst = packet.dst_ip or ""
    if packet.src_port is not None:
        src = f"{src}:{packet.src_port}" if src else str(packet.src_port)
    if packet.dst_port is not None:
        dst = f"{dst}:{packet.dst_port}" if dst else str(packet.dst_port)
    return AISelectedPacket(
        number=packet.number,
        timestamp=packet.timestamp,
        src=src or None,
        dst=dst or None,
        protocol=packet.protocol,
        length=packet.length,
        info=packet.info[:280],
        score=score,
    )


def select_relevant_packets(question: str, packets: Sequence[PacketEntry]) -> List[AISelectedPacket]:
    """Select only packets that are relevant enough to send to the AI model."""
    terms = _tokens(question)
    ips = set(_IP_RE.findall(question))
    ports = _ports(question)
    protocols = {term for term in terms if term in _KNOWN_PROTOCOLS}
    generic_question = bool(terms & _GENERIC_TERMS) and not ips and not ports and not protocols

    scored: List[Tuple[int, PacketEntry]] = []
    for packet in packets:
        score = _score_packet(packet, terms, ips, ports, protocols)
        if score > 0:
            scored.append((score, packet))

    if not scored and generic_question:
        # For broad questions, sample the capture evenly instead of sending it all.
        step = max(1, len(packets) // AI_MAX_PACKETS)
        sampled = [(1, packet) for packet in packets[::step][:AI_MAX_PACKETS]]
        return [_compact_packet(packet, score) for score, packet in sampled]

    scored.sort(key=lambda item: (-item[0], item[1].number))
    return [_compact_packet(packet, score) for score, packet in scored[:AI_MAX_PACKETS]]


def _history_lines(history: Iterable[AIChatMessage]) -> str:
    """Keep only a short text history so the model preserves chat continuity."""
    messages = list(history)[-AI_MAX_HISTORY_MESSAGES:]
    lines = []
    for message in messages:
        role = "User" if message.role == "user" else "Assistant"
        lines.append(f"{role}: {message.content[:500]}")
    return "\n".join(lines)


def _build_prompt(payload: AIChatRequest, selected: Sequence[AISelectedPacket]) -> str:
    """Create the final prompt with only selected packet context."""
    packet_json = json.dumps([packet.dict() for packet in selected], ensure_ascii=True, separators=(",", ":"))
    return (
        "You are PCAPCaper's lightweight network-analysis assistant.\n"
        "Answer using only the selected packet context below. If the context is insufficient, say so clearly.\n"
        "Be concise, technical, and practical. Do not invent packets, hosts, ports, or payloads.\n\n"
        f"Recent chat:\n{_history_lines(payload.history) or '(none)'}\n\n"
        f"User question:\n{payload.question}\n\n"
        f"Selected packets ({len(selected)} max {AI_MAX_PACKETS}):\n{packet_json}\n"
    )


def ask_ai(payload: AIChatRequest) -> AIChatResponse:
    """Query the configured model service with a bounded packet context."""
    selected = select_relevant_packets(payload.question, payload.packets)
    prompt = _build_prompt(payload, selected)
    request_body = json.dumps({
        "model": AI_MODEL,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "1m",
        "options": {
            "temperature": 0.2,
            "num_ctx": AI_NUM_CTX,
            "num_predict": AI_NUM_PREDICT,
        },
    }).encode("utf-8")

    request = urllib.request.Request(
        f"{AI_BASE_URL}/api/generate",
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=AI_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (TimeoutError, socket.timeout) as exc:
        raise TimeoutError("AI model response timed out.") from exc
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        if exc.code == 404 and "model" in detail.lower():
            raise AIModelError(
                f"AI model '{AI_MODEL}' is not installed. Run: docker compose exec ai ollama pull {AI_MODEL}",
                status_code=503,
            ) from exc
        raise AIModelError(f"AI model service returned HTTP {exc.code}: {detail}", status_code=502) from exc
    except urllib.error.URLError as exc:
        raise AIModelError("AI model service is unavailable. Check that the 'ai' container is running.", status_code=503) from exc

    answer = str(data.get("response") or "").strip()
    if not answer:
        answer = "The model returned an empty response. Try a more specific question."

    return AIChatResponse(
        answer=answer,
        model=AI_MODEL,
        selected_packets=selected,
        selected_packet_count=len(selected),
        timed_out=False,
    )

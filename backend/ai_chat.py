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
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

from config import (
    AI_BASE_URL,
    AI_MAX_HISTORY_MESSAGES,
    AI_MAX_PACKETS,
    AI_MODEL,
    AI_NUM_CTX,
    AI_NUM_PREDICT,
    AI_PROMPT_MAX_CHARS,
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
_TECHNICAL_TERMS = {
    "ack", "asn", "certificate", "cipher", "dns", "domain", "flow", "flows",
    "host", "http", "ip", "ja3", "nxdomain", "packet", "packets", "port",
    "rcode", "security", "sni", "tcp", "tls", "ttl", "udp", "uri",
}
_PRUNABLE_CONTEXT_PATHS = [
    ("dns", "queries"),
    ("http", "requests"),
    ("http", "responses"),
    ("tls", "connections"),
    ("hosts", "items"),
    ("flows",),
    ("conversations",),
    ("selected_packets",),
    ("dns", "correlations"),
    ("dns", "tunneling_indicators"),
    ("tls", "anomalies"),
    ("dns", "top_domains"),
    ("http", "top_hosts"),
    ("http", "top_user_agents"),
    ("tls", "top_sni"),
    ("top_src_ips",),
    ("top_dst_ips",),
    ("top_src_ports",),
    ("top_dst_ports",),
]


class AIModelError(RuntimeError):
    """Raised when the model server responds but cannot run the request."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def _model_pull_hint() -> str:
    """Return the safest pull command for the currently configured Ollama endpoint."""
    if AI_BASE_URL.startswith("http://ai:"):
        return f"docker compose exec ai ollama pull {AI_MODEL}"
    return f"ollama pull {AI_MODEL}"


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


def _safe_list(value: Any) -> List[Any]:
    """Return a list for JSON fields that may be absent or malformed."""
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> Dict[str, Any]:
    """Return a dict for JSON fields that may be absent or malformed."""
    return value if isinstance(value, dict) else {}


def _matches_text(item: Any, terms: Set[str], ips: Set[str], ports: Set[int], protocols: Set[str]) -> bool:
    """Check if a report item is relevant to the user question."""
    text = json.dumps(item, ensure_ascii=True, default=str).lower()
    if any(ip in text for ip in ips):
        return True
    if any(str(port) in text for port in ports):
        return True
    if any(protocol in text for protocol in protocols):
        return True
    return any(term in text for term in terms if term not in _GENERIC_TERMS)


def _take_relevant(items: Sequence[Any], terms: Set[str], ips: Set[str], ports: Set[int], protocols: Set[str], limit: int) -> List[Any]:
    """Take relevant report rows, falling back to the first rows for broad questions."""
    relevant = [item for item in items if _matches_text(item, terms, ips, ports, protocols)]
    if not relevant and (terms & _GENERIC_TERMS):
        relevant = list(items)
    return relevant[:limit]


def _truncate_text_values(value: Any, max_length: int = 180) -> Any:
    """Recursively shorten long strings before sending report evidence to the LLM."""
    if isinstance(value, str):
        return value if len(value) <= max_length else f"{value[:max_length]}..."
    if isinstance(value, list):
        return [_truncate_text_values(item, max_length) for item in value]
    if isinstance(value, dict):
        return {key: _truncate_text_values(item, max_length) for key, item in value.items()}
    return value


def _context_json(context: Dict[str, Any]) -> str:
    """Serialize technical evidence in the most compact stable form."""
    return json.dumps(context, ensure_ascii=True, separators=(",", ":"), default=str)


def _list_at_path(context: Dict[str, Any], path: Tuple[str, ...]) -> List[Any]:
    """Return a mutable list at a nested context path, or an empty list."""
    current: Any = context
    for key in path:
        if not isinstance(current, dict):
            return []
        current = current.get(key)
    return current if isinstance(current, list) else []


def _shrink_context_once(context: Dict[str, Any]) -> bool:
    """Remove one slice of the least critical evidence and report if it changed."""
    for path in _PRUNABLE_CONTEXT_PATHS:
        items = _list_at_path(context, path)
        if len(items) > 1:
            del items[max(1, len(items) // 2):]
            return True
        if len(items) == 1:
            items.clear()
            return True
    return False


def _prune_context_to_budget(context: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce context lists until the prompt fits the configured budget."""
    context = _truncate_text_values(context)
    context["context_budget"] = {
        "max_chars": AI_PROMPT_MAX_CHARS,
        "pruned": False,
        "note": "Context is pre-pruned by the backend to avoid Ollama prompt truncation.",
    }

    while len(_context_json(context)) > AI_PROMPT_MAX_CHARS:
        changed = _shrink_context_once(context)
        context["context_budget"]["pruned"] = True
        context["context_budget"]["chars_after_last_prune"] = len(_context_json(context))
        if not changed:
            context["context_budget"]["warning"] = "Prompt budget is too small for even the minimal report summary."
            break

    context["context_budget"]["final_chars"] = len(_context_json(context))
    return context


def build_technical_context(question: str, analysis: Dict[str, Any], selected: Sequence[AISelectedPacket]) -> Dict[str, Any]:
    """Build a technical evidence pack from the sanitized full analysis report."""
    terms = _tokens(question)
    ips = set(_IP_RE.findall(question))
    ports = _ports(question)
    protocols = {term for term in terms if term in _KNOWN_PROTOCOLS}
    technical_mode = bool((terms & _TECHNICAL_TERMS) or ips or ports or protocols)

    dns = _safe_dict(analysis.get("dns"))
    http = _safe_dict(analysis.get("http"))
    tls = _safe_dict(analysis.get("tls"))
    hosts = _safe_dict(analysis.get("hosts"))

    context: Dict[str, Any] = {
        "mode": "technical" if technical_mode else "general",
        "summary": analysis.get("summary"),
        "protocols": _safe_list(analysis.get("protocols"))[:12],
        "top_src_ips": _safe_list(analysis.get("top_src_ips"))[:12],
        "top_dst_ips": _safe_list(analysis.get("top_dst_ips"))[:12],
        "top_src_ports": _safe_list(analysis.get("top_src_ports"))[:10],
        "top_dst_ports": _safe_list(analysis.get("top_dst_ports"))[:10],
        "conversations": _take_relevant(_safe_list(analysis.get("conversations")), terms, ips, ports, protocols, 12),
        "flows": _take_relevant(_safe_list(analysis.get("flows")), terms, ips, ports, protocols, 18),
        "selected_packets": [packet.model_dump() for packet in selected],
    }

    if dns:
        context["dns"] = {
            "stats": dns.get("stats"),
            "top_domains": _safe_list(dns.get("top_domains"))[:15],
            "tunneling_indicators": _take_relevant(_safe_list(dns.get("tunneling_indicators")), terms, ips, ports, protocols, 15),
            "queries": _take_relevant(_safe_list(dns.get("queries")), terms, ips, ports, protocols, 30),
            "correlations": _take_relevant(_safe_list(dns.get("correlations")), terms, ips, ports, protocols, 15),
        }
    if http:
        context["http"] = {
            "stats": http.get("stats"),
            "top_hosts": _safe_list(http.get("top_hosts"))[:15],
            "top_user_agents": _safe_list(http.get("top_user_agents"))[:10],
            "requests": _take_relevant(_safe_list(http.get("requests")), terms, ips, ports, protocols, 20),
            "responses": _take_relevant(_safe_list(http.get("responses")), terms, ips, ports, protocols, 20),
        }
    if tls:
        context["tls"] = {
            "stats": tls.get("stats"),
            "top_sni": _safe_list(tls.get("top_sni"))[:15],
            "versions": tls.get("versions"),
            "connections": _take_relevant(_safe_list(tls.get("connections")), terms, ips, ports, protocols, 20),
            "anomalies": _take_relevant(_safe_list(tls.get("anomalies")), terms, ips, ports, protocols, 20),
        }
    if hosts:
        context["hosts"] = {
            "total_hosts": hosts.get("total_hosts"),
            "items": _take_relevant(_safe_list(hosts.get("hosts")), terms, ips, ports, protocols, 20),
        }

    return _prune_context_to_budget(context)


def _history_lines(history: Iterable[AIChatMessage]) -> str:
    """Keep only a short text history so the model preserves chat continuity."""
    messages = list(history)[-AI_MAX_HISTORY_MESSAGES:]
    lines = []
    for message in messages:
        role = "User" if message.role == "user" else "Assistant"
        lines.append(f"{role}: {message.content[:500]}")
    return "\n".join(lines)


def _build_prompt(payload: AIChatRequest, technical_context: Dict[str, Any]) -> str:
    """Create the final prompt from bounded technical evidence."""
    context_json = _context_json(technical_context)
    return (
        "You are PCAPCaper's technical network-analysis assistant.\n"
        "Use the structured evidence below to produce a precise technical answer.\n"
        "Prioritize flows, DNS, HTTP, TLS, host profiles, and packet numbers when available.\n"
        "Mention concrete IPs, ports, protocols, domains, SNI, rcodes, status codes, flow IDs, and packet numbers.\n"
        "If evidence is insufficient, state what is missing. Do not invent packets, payloads, hosts, or threat intel.\n\n"
        f"Recent chat:\n{_history_lines(payload.history) or '(none)'}\n\n"
        f"User question:\n{payload.question}\n\n"
        f"Technical evidence JSON:\n{context_json}\n"
    )


def _build_budgeted_prompt(payload: AIChatRequest, technical_context: Dict[str, Any]) -> str:
    """Build the final prompt and keep pruning until the whole prompt fits."""
    prompt = _build_prompt(payload, technical_context)
    while len(prompt) > AI_PROMPT_MAX_CHARS:
        changed = _shrink_context_once(technical_context)
        budget = _safe_dict(technical_context.get("context_budget"))
        budget["pruned"] = True
        budget["final_prompt_chars"] = len(prompt)
        technical_context["context_budget"] = budget
        if not changed:
            budget["warning"] = "Prompt budget is too small for the minimal prompt."
            break
        prompt = _build_prompt(payload, technical_context)
    technical_context["context_budget"]["final_prompt_chars"] = len(prompt)
    return prompt


def ask_ai(payload: AIChatRequest) -> AIChatResponse:
    """Query the configured model service with a bounded packet context."""
    selected = select_relevant_packets(payload.question, payload.packets)
    technical_context = build_technical_context(payload.question, payload.analysis, selected)
    prompt = _build_budgeted_prompt(payload, technical_context)
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
                f"AI model '{AI_MODEL}' is not installed. Run: {_model_pull_hint()}",
                status_code=503,
            ) from exc
        raise AIModelError(f"AI model service returned HTTP {exc.code}: {detail}", status_code=502) from exc
    except urllib.error.URLError as exc:
        raise AIModelError(
            f"AI model service is unavailable at {AI_BASE_URL}. Check the configured Ollama host and port.",
            status_code=503,
        ) from exc

    answer = str(data.get("response") or "").strip()
    if not answer:
        answer = "The model returned an empty response. Try a more specific question."

    return AIChatResponse(
        answer=answer,
        model=AI_MODEL,
        selected_packets=selected,
        selected_packet_count=len(selected),
        technical_context=technical_context,
        timed_out=False,
    )

"""
Configurazione runtime di PCAPCaper.

Le variabili vengono lette dall'ambiente per evitare limiti hardcoded e per
permettere tuning in Docker/produzione senza modificare il codice.
"""

import os
import tempfile
from pathlib import Path
from typing import Optional


def _load_dotenv() -> None:
    """Carica un file .env semplice senza introdurre dipendenze runtime."""
    candidates = [
        Path.cwd() / ".env",
        Path.cwd().parent / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    for path in candidates:
        if not path.exists():
            continue
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
        break


_load_dotenv()


def _int_env(name: str, default: int, minimum: Optional[int] = None) -> int:
    """Legge un intero da env applicando fallback e minimo opzionale."""
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def _float_env(name: str, default: float, minimum: Optional[float] = None) -> float:
    """Legge un float da env applicando fallback e minimo opzionale."""
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def _ai_base_url() -> str:
    """Resolve the Ollama API URL from explicit or mode-based configuration."""
    explicit_base_url = os.getenv("PCAPCAPER_AI_BASE_URL", "").strip()
    if explicit_base_url:
        return explicit_base_url.rstrip("/")

    mode = os.getenv("PCAPCAPER_AI_OLLAMA_MODE", "container").strip().lower()
    if mode == "host":
        host = os.getenv("PCAPCAPER_AI_OLLAMA_HOST", "host.docker.internal").strip()
        port = os.getenv("PCAPCAPER_AI_OLLAMA_PORT", "11434").strip()
        return f"http://{host}:{port}".rstrip("/")

    return "http://ai:11434"


# 0 significa nessun limite applicativo; eventuali limiti restano a carico di
# reverse proxy, filesystem o quote del container.
UPLOAD_MAX_MB = _int_env("PCAPCAPER_UPLOAD_MAX_MB", 0, 0)
UPLOAD_CHUNK_SIZE = _int_env("PCAPCAPER_UPLOAD_CHUNK_SIZE", 1024 * 1024, 64 * 1024)
TEMP_DIR = os.getenv("PCAPCAPER_TEMP_DIR", tempfile.gettempdir())

# Limiti di output per evitare JSON enormi e consumo eccessivo di memoria lato
# browser. Il backend continua ad analizzare tutto il PCAP in streaming.
MAX_PACKET_LIST = _int_env("PCAPCAPER_MAX_PACKET_LIST", 1000, 0)
MAX_FLOW_PACKET_NUMBERS = _int_env("PCAPCAPER_MAX_FLOW_PACKET_NUMBERS", 200, 0)

# Concorrenza prudente per servizi esterni gratuiti: parallelizza senza aprire
# decine di connessioni simultanee.
EXTERNAL_MAX_WORKERS = _int_env("PCAPCAPER_EXTERNAL_MAX_WORKERS", 6, 1)
MAX_ENRICHMENT_IPS = _int_env("PCAPCAPER_MAX_ENRICHMENT_IPS", 80, 1)
HTTP_TIMEOUT_SECONDS = _float_env("PCAPCAPER_HTTP_TIMEOUT_SECONDS", 6.0, 1.0)
SOCKET_TIMEOUT_SECONDS = _float_env("PCAPCAPER_SOCKET_TIMEOUT_SECONDS", 5.0, 1.0)

# Lightweight AI assistant settings. The backend sends only compact technical
# evidence to the model service, never raw packet bytes or full layer dumps.
AI_ENABLED = os.getenv("PCAPCAPER_AI_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
AI_BASE_URL = _ai_base_url()
AI_MODEL = os.getenv("PCAPCAPER_AI_MODEL", "qwen2.5:0.5b")
AI_TIMEOUT_SECONDS = _float_env("PCAPCAPER_AI_TIMEOUT_SECONDS", 360.0, 2.0)
AI_MAX_PACKETS = _int_env("PCAPCAPER_AI_MAX_PACKETS", 40, 1)
AI_MAX_HISTORY_MESSAGES = _int_env("PCAPCAPER_AI_MAX_HISTORY_MESSAGES", 8, 0)
AI_NUM_PREDICT = _int_env("PCAPCAPER_AI_NUM_PREDICT", 384, 64)
AI_NUM_CTX = _int_env("PCAPCAPER_AI_NUM_CTX", 2048, 512)

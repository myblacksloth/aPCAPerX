# Lightweight AI Assistant

## Overview

PCAPCaper includes an optional floating chat in the bottom-right corner of the dashboard. The chat talks to `/api/ai-chat`, and the backend forwards the request to a separate Ollama container.

The assistant is designed for low-power hardware:

- default model: `qwen2.5:0.5b`;
- Docker limits the AI container to `1` CPU and `3 GB` RAM by default;
- Ollama is configured for one parallel request and one loaded model;
- the backend sends at most `PCAPCAPER_AI_MAX_PACKETS` compact packet summaries to the model;
- raw packet bytes and the full analysis object are not sent to the model;
- if the model exceeds `PCAPCAPER_AI_TIMEOUT_SECONDS`, the backend returns `504` and the UI shows an error.

## Technical Context

The AI chat is split into two layers:

- the chat widget keeps the conversation and forwards the user question;
- the backend technical context builder inspects the sanitized full report: summary, protocols, top IPs, ports, conversations, 5-tuple flows, DNS, HTTP, TLS, hosts, enrichment data, and selected packet metadata.

The model does **not** receive raw packet bytes or full Scapy layer trees. It receives a bounded technical evidence JSON built from the whole analysis, plus a small list of packet numbers relevant to the question. This keeps the assistant technical without trying to push an entire PCAP into a small local model.

The `/api/ai-chat` endpoint returns the model answer, selected packet metadata, and the technical context metadata used for the answer. If the model exceeds `PCAPCAPER_AI_TIMEOUT_SECONDS`, the backend returns `504` and the chat keeps its history.

## Docker Setup

Docker Compose includes the `ai-model-pull` one-shot service, so `docker compose up --build` starts an automatic model download through Ollama's HTTP API. The backend can start while the model is downloading; the chat will work as soon as the pull completes.

If you start only the AI service manually or need to refresh the model, run:

```bash
docker compose up -d ai
docker compose exec ai ollama pull qwen2.5:0.5b
```

To move to stronger hardware, change `PCAPCAPER_AI_MODEL`, `PCAPCAPER_AI_NUM_CTX`, `PCAPCAPER_AI_NUM_PREDICT`, and the `cpus` / `mem_limit` values in `docker-compose.yml`.

## External Ollama Service

You can disable the bundled AI container and point the backend to an Ollama service running on another host, including a macOS machine on the same LAN.

### Configuration

Configure `.env`:

```dotenv
PCAPCAPER_AI_ENABLED=1
PCAPCAPER_AI_OLLAMA_MODE=host
PCAPCAPER_AI_OLLAMA_HOST=192.168.1.20
PCAPCAPER_AI_OLLAMA_PORT=11434
PCAPCAPER_AI_MODEL=qwen3:8b
PCAPCAPER_AI_NUM_CTX=8192
PCAPCAPER_AI_NUM_PREDICT=768
```

### macOS host integration

If the backend container must reach Ollama running on the same macOS host as Docker Desktop, use:

```dotenv
PCAPCAPER_AI_OLLAMA_HOST=host.docker.internal
```

If you prefer a single explicit URL:

```dotenv
PCAPCAPER_AI_BASE_URL=http://192.168.1.20:11434
```

### Disable bundled AI

To avoid starting `ai` and `ai-model-pull`, create a local Compose override file, for example `docker-compose.external-ai.yml`:

```yaml
services:
  ai:
    profiles: ["internal-ai"]
  ai-model-pull:
    profiles: ["internal-ai"]
  backend:
    depends_on: !reset []
```

`!reset` requires Docker Compose v2. If your Compose version does not support it, update Docker Compose or use a local copy of the Compose file with the backend `depends_on` entry for `ai` removed.

Then start only the application services:

```bash
docker compose -f docker-compose.yml -f docker-compose.external-ai.yml up --build backend frontend
```

The external Ollama server must already be running and must have the configured model installed:

```bash
ollama pull qwen3:8b
curl http://192.168.1.20:11434/api/tags
```

## Chat History

The chat history is preserved while the dashboard is open: closing the popup hides it but does not clear the conversation.

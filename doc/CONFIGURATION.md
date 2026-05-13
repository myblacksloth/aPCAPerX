# Configuration & Performance

## Overview

PCAP analysis is optimized to reduce memory usage and avoid blocking the server:

- uploads are written to temporary storage in chunks;
- PCAP analysis runs in a separate thread from the FastAPI event loop;
- packet details and per-flow packet numbers are limited through configuration to avoid huge JSON responses;
- external IP enrichment is parallelized with a bounded number of workers;
- external DNS lists are downloaded and indexed with process-level caching;
- the UI has separate states for upload, processing, analysis, and external calls.

## Environment Variables (`.env`)

The repository includes `.env.example`. Local `.env` files are ignored by git and can be used to customize the environment.

### Upload & Storage

| Variable | Default | Description |
| --- | --- | --- |
| `PCAPCAPER_UPLOAD_MAX_MB` | `0` | Upload limit in MB. `0` means no application-level limit. |
| `PCAPCAPER_TEMP_DIR` | `/tmp/pcapcaper` | Temporary PCAP file directory. |
| `PCAPCAPER_UPLOAD_CHUNK_SIZE` | `1048576` | Upload chunk size in bytes. |
| `PCAPCAPER_ANALYSIS_STORAGE_ENABLED` | `1` | Persists completed analysis JSON reports on the backend. |
| `PCAPCAPER_ANALYSIS_STORAGE_DIR` | `/data/pcapcaper/analyses` | Directory used for persisted analysis reports. Docker Compose mounts this path on a named volume. |
| `PCAPCAPER_ANALYSIS_STORAGE_MAX_ITEMS` | `50` | Maximum saved reports kept by the filesystem storage backend. Older reports are pruned. |

### JSON Limits

| Variable | Default | Description |
| --- | --- | --- |
| `PCAPCAPER_MAX_PACKET_LIST` | `1000` | Maximum detailed packet rows included in the JSON response. `0` means unlimited. |
| `PCAPCAPER_MAX_FLOW_PACKET_NUMBERS` | `200` | Maximum packet numbers stored per flow. `0` means unlimited. |
| `PCAPCAPER_FOLLOW_STREAM_MAX_STREAMS` | `100` | Maximum payload-bearing TCP/UDP streams stored for Follow stream. |
| `PCAPCAPER_FOLLOW_STREAM_MAX_BYTES_PER_STREAM` | `65536` | Maximum reconstructed payload bytes stored for each stream. |
| `PCAPCAPER_FOLLOW_STREAM_MAX_SEGMENT_BYTES` | `4096` | Maximum bytes shown per individual payload segment preview. |

### External Services & Timeouts

| Variable | Default | Description |
| --- | --- | --- |
| `PCAPCAPER_EXTERNAL_MAX_WORKERS` | `6` | Maximum parallel workers for external enrichment. |
| `PCAPCAPER_MAX_ENRICHMENT_IPS` | `80` | Maximum public IPs enriched per request. |
| `PCAPCAPER_HTTP_TIMEOUT_SECONDS` | `6` | HTTP timeout for external services. |
| `PCAPCAPER_SOCKET_TIMEOUT_SECONDS` | `5` | Socket timeout for WHOIS and reverse lookup operations. |
| `URLHAUS_AUTH_KEY` | empty | Optional URLhaus Auth-Key. |

### Authentication

| Variable | Default | Description |
| --- | --- | --- |
| `PCAPCAPER_AUTH_ENABLED` | `1` | Enables login, sessions, user-owned reports, TOTP, recovery codes, and passkeys. |
| `PCAPCAPER_DATABASE_URL` | `postgresql://pcapcaper:pcapcaper@db:5432/pcapcaper` | PostgreSQL connection URL used by the backend. |
| `PCAPCAPER_POSTGRES_DB` | `pcapcaper` | Database created by the Compose PostgreSQL service. |
| `PCAPCAPER_POSTGRES_USER` | `pcapcaper` | PostgreSQL application user. |
| `PCAPCAPER_POSTGRES_PASSWORD` | `pcapcaper` | PostgreSQL application password. Change it outside local demos. |
| `PCAPCAPER_SESSION_SECRET` | `change-me-in-production` | HMAC secret for session-token hashes. Must be stable and random in production. |
| `PCAPCAPER_WEBAUTHN_RP_ID` | `localhost` | WebAuthn relying-party id for passkeys. Must match the browser hostname. |
| `PCAPCAPER_WEBAUTHN_ORIGIN` | `http://localhost:3000` | Expected WebAuthn browser origin. |

### AI Assistant

| Variable | Default | Description |
| --- | --- | --- |
| `PCAPCAPER_AI_ENABLED` | `1` | Enables the local technical AI assistant. |
| `PCAPCAPER_AI_OLLAMA_MODE` | `container` | Ollama endpoint mode. Use `container` for the Compose service or `host` for an external/local Ollama server. |
| `PCAPCAPER_AI_OLLAMA_HOST` | `host.docker.internal` | Ollama host used when `PCAPCAPER_AI_OLLAMA_MODE=host`. Use an IP or DNS name for a remote host. |
| `PCAPCAPER_AI_OLLAMA_PORT` | `11434` | Ollama API port used when `PCAPCAPER_AI_OLLAMA_MODE=host`. |
| `PCAPCAPER_AI_BASE_URL` | empty | Full Ollama API URL override. When set, it bypasses `PCAPCAPER_AI_OLLAMA_MODE`, host, and port. |
| `PCAPCAPER_AI_MODEL` | `qwen2.5:0.5b` | Default lightweight model. |
| `PCAPCAPER_AI_TIMEOUT_SECONDS` | `360` | Maximum time allowed for one model response. |
| `PCAPCAPER_AI_MAX_PACKETS` | `40` | Maximum selected packets included in AI technical evidence. |
| `PCAPCAPER_AI_NUM_CTX` | `2048` | Ollama context size used by the assistant. |
| `PCAPCAPER_AI_NUM_PREDICT` | `384` | Maximum generated tokens per response. |
| `PCAPCAPER_AI_PROMPT_MAX_CHARS` | `3072` | Approximate backend prompt budget before pruning AI technical evidence. |
| `OLLAMA_NUM_PARALLEL` | `1` | Ollama parallel request limit for low-power hardware. |
| `OLLAMA_MAX_LOADED_MODELS` | `1` | Prevents multiple loaded models from consuming RAM. |

## Technical Details

### Temporary Storage

During `/api/analyze`, the backend stores the uploaded PCAP in `PCAPCAPER_TEMP_DIR` using `tempfile.NamedTemporaryFile(delete=False)`.

The file is removed in the endpoint `finally` block, including error cases. In Docker, `/tmp/pcapcaper` is mounted as `tmpfs`, so files are also removed when the container stops.

### Saved Analysis Reports

Completed analysis reports are persisted server-side as JSON files when `PCAPCAPER_ANALYSIS_STORAGE_ENABLED=1`. The frontend homepage calls `GET /api/analyses` and, when saved reports exist, shows a reload list. Selecting a report calls `GET /api/analyses/{analysis_id}` and restores the dashboard without re-uploading the PCAP.

The uploaded PCAP file is still deleted after analysis. Only the derived JSON report is stored. Docker Compose mounts `/data/pcapcaper/analyses` on the `analysis_reports` named volume so reports survive container restarts and rebuilds.

Reports are now tagged with `owner_user_id`, and the list/load/update endpoints only return reports owned by the authenticated user.

### Pagination and JSON Limits

The packet list in the frontend is paginated with 50 rows per page.

By default, the backend sends the first `PCAPCAPER_MAX_PACKET_LIST=1000` detailed packets. Summaries, flows, DNS, HTTP, TLS, and hosts are still computed over the full PCAP.

Increasing this value for very large PCAP files makes the JSON heavier and may slow down the browser.

### Redis Evaluation

Redis was evaluated but is not required for the current synchronous request model or filesystem report storage. It remains a natural candidate for future asynchronous jobs, resumable analysis, shared progress state, and distributed caches.

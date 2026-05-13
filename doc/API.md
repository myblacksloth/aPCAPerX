# API Reference

## Health Check

### `GET /api/health`

Checks whether the backend is running.

**Response:**

```json
{
  "status": "ok",
  "service": "pcap-analyzer"
}
```

---

## PCAP Analysis

### `POST /api/analyze`

Analyzes a PCAP file and returns the report.

**Request:** `Content-Type: multipart/form-data`

| Field | Type | Description |
| --- | --- | --- |
| `file` | File | `.pcap`, `.pcapng`, or `.cap` file. Application-level size limit is configurable through `PCAPCAPER_UPLOAD_MAX_MB`. |

**Response sections include:**

- `filename`;
- `summary`;
- `protocols`;
- `top_src_ips`;
- `top_dst_ips`;
- `top_src_ports`;
- `top_dst_ports`;
- `conversations`;
- `flows`;
- `dns`;
- `http`;
- `tls`;
- `hosts`;
- `timeline`;
- `packets`;
- `external_ip_info`.

When report storage is enabled, the response also includes `analysis_id`, `analyzed_at`, and `original_size_bytes`.

**Error responses:**

| Status code | Cause |
| --- | --- |
| `400` | Unsupported file extension or empty file. |
| `413` | File exceeds `PCAPCAPER_UPLOAD_MAX_MB`, when configured. |
| `422` | Corrupted PCAP file or no valid packets found. |
| `500` | Internal server error. |

---

## Saved Reports

### `GET /api/analyses`

Lists saved analysis reports. The response contains lightweight metadata only; full packet rows are loaded through `GET /api/analyses/{analysis_id}`.

### `GET /api/analyses/{analysis_id}`

Loads one saved analysis report and returns the same JSON shape as `POST /api/analyze`.

### `PUT /api/analyses/{analysis_id}`

Updates one saved report. The frontend uses this after manual enrichment so reloaded reports keep external IP data.

---

## Authentication

### `POST /api/auth/login`

Username/password login. When TOTP is enabled, the second request includes the OTP code.

### `POST /api/auth/register`

Creates a new user, recovery codes, and an authenticated session.

### `POST /api/auth/recover`

Logs in with username and one unused recovery code.

### `POST /api/auth/logout`

Clears the HTTP-only session cookie.

### `GET /api/auth/me`

Returns the current user profile.

### `POST /api/auth/totp/setup`, `/totp/enable`, `/totp/disable`

Configure TOTP MFA.

### `POST /api/auth/passkeys/register/options` and `/register/verify`

Register a passkey.

### `POST /api/auth/passkeys/login/options` and `/login/verify`

Login with a passkey.

---

## AI Chat

### `POST /api/ai-chat`

Sends a chat question to the local AI assistant. The frontend includes compact packet metadata and the sanitized analysis report; the backend extracts a bounded technical context before calling Ollama.

**Request:** `Content-Type: application/json`

```json
{
  "question": "Summarize suspicious DNS activity",
  "packets": [{ "number": 1, "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "protocol": "DNS" }],
  "analysis": { "summary": {}, "flows": [], "dns": {}, "http": {}, "tls": {}, "hosts": {} },
  "history": [{ "role": "user", "content": "What happened?" }]
}
```

**Privacy note:** raw packet bytes and decoded layer trees are not sent to the model. The backend forwards only limited technical evidence such as flows, DNS/HTTP/TLS metadata, host summaries, and selected packet references.

**Timeout behavior:** if the model exceeds `PCAPCAPER_AI_TIMEOUT_SECONDS`, the backend returns `504` and interrupts the request.

---

## External Enrichment

### `POST /api/enrich-ips`

Enriches a list of public IPs using external tools. This endpoint is used by the **Analyze with external tools** button.

**Request:**

```json
{
  "ips": ["8.8.8.8", "1.1.1.1", "192.168.1.10"]
}
```

**Response (200 OK):**

```json
{
  "results": {
    "8.8.8.8": {
      "ip": "8.8.8.8",
      "status": "enriched",
      "sources": ["Reverse DNS", "Team Cymru", "RDAP/IANA", "ip-api"],
      "reverse_dns": "dns.google",
      "asn": "15169",
      "as_name": "GOOGLE",
      "bgp_prefix": "8.8.8.0/24",
      "registry": "arin",
      "country": "United States",
      "country_code": "US",
      "isp": "Google LLC",
      "org": "Google Public DNS",
      "proxy": false,
      "hosting": true,
      "errors": []
    },
    "192.168.1.10": {
      "ip": "192.168.1.10",
      "status": "skipped",
      "reason": "Private, local, reserved, or invalid address: not sent to external services."
    }
  }
}
```

**Privacy note:** non-global IPs are discarded before any external call.

---

## Advanced Security Analysis

### `POST /api/security-analysis`

Runs advanced traffic security analysis. The endpoint is called by the **Advanced security** tab only after explicit user confirmation.

External sources include Shodan InternetDB, Feodo Tracker, and optional URLhaus with `URLHAUS_AUTH_KEY`.

**Request:** `Content-Type: application/json`

```json
{
  "packets": [
    {
      "number": 1,
      "timestamp": "10:23:01.123",
      "src_ip": "192.168.1.10",
      "dst_ip": "8.8.8.8",
      "protocol": "DNS",
      "length": 74,
      "src_port": 52341,
      "dst_port": 53,
      "info": "DNS Query"
    }
  ],
  "external_ip_info": {
    "8.8.8.8": {
      "ip": "8.8.8.8",
      "status": "enriched",
      "sources": ["Reverse DNS", "Team Cymru", "RDAP/IANA", "ip-api"]
    }
  },
  "max_ips": 80
}
```

**Response (200 OK):**

```json
{
  "summary": {
    "total_ips": 12,
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 2,
    "low_count": 3
  },
  "findings": [
    {
      "ip": "192.168.1.10",
      "severity": "high",
      "score": 75,
      "confidence": 0.9,
      "evidence": ["VPN detected", "Suspicious DNS activity"],
      "recommendations": ["Investigate further", "Block if not authorized"],
      "mitre_references": ["T1020", "T1518"],
      "sources_used": ["Shodan", "Local analysis"]
    }
  ]
}
```

---

## DNS Reputation

### `POST /api/dns-reputation`

Checks observed DNS domains against open external lists. The endpoint is called by the **DNS** tab only after explicit user confirmation.

External sources include AdGuard DNS filter, StevenBlack hosts, and optional URLhaus with `URLHAUS_AUTH_KEY`.

# Features & Analysis Capabilities

## Wireshark-style Packet Filters

The dashboard includes a **Packet filters** tab applied to the packet list and trace views. Main statistical summaries remain computed over the full PCAP, while packet-oriented views show only matching items.

You can use both the text input and GUI controls to build filters.

### Logical operators

| Operator | Description | Example |
| --- | --- | --- |
| `and` / `&&` | Both conditions must be true. | `dns and ip.dst == 8.8.8.8` |
| `or` / `\|\|` | At least one condition must be true. | `http or https` |
| `not` / `!` | Negates a condition. | `not arp` |
| `( ... )` | Groups conditions. | `(dns or http) and frame.len > 100` |

### Comparison operators

| Operator | Description | Example |
| --- | --- | --- |
| `==` | Equal to. | `tcp.port == 443` |
| `!=` | Different from. | `ip.src != 192.168.1.10` |
| `contains` | Text field contains a string. | `info contains "Query"` |
| `>` | Greater than. | `frame.len > 1000` |
| `>=` | Greater than or equal to. | `frame.number >= 500` |
| `<` | Less than. | `frame.len < 128` |
| `<=` | Less than or equal to. | `frame.number <= 100` |

### Supported fields

| Field | Aliases | Description |
| --- | --- | --- |
| `ip.addr` | `ip` | Source or destination IP. |
| `ip.src` | `src`, `src.ip` | Source IP. |
| `ip.dst` | `dst`, `dst.ip` | Destination IP. |
| `tcp.port` | `port` | Source or destination TCP port. |
| `udp.port` | `port` | Source or destination UDP port. |
| `tcp.srcport` | `udp.srcport`, `src.port` | Source port. |
| `tcp.dstport` | `udp.dstport`, `dst.port` | Destination port. |
| `frame.len` | `len`, `length` | Packet length in bytes. |
| `frame.number` | `number`, `no` | Packet number. |
| `frame.time` | `time` | Timestamp shown in the packet table. |
| `protocol` | `proto` | Detected protocol. |
| `info` | — | Packet information field. |

### Quick protocol filters

| Filter | Meaning |
| --- | --- |
| `ip` | IP, IPv4, or IPv6 packets. |
| `tcp` | TCP packets. |
| `udp` | UDP packets. |
| `dns` | DNS or mDNS packets. |
| `http` | HTTP or HTTP-Alt traffic. |
| `https` | HTTPS or HTTPS-Alt traffic. |
| `tls` | Traffic classified as HTTPS/TLS. |
| `arp` | ARP packets. |
| `icmp` | ICMP packets. |
| `ssh` | SSH traffic. |

### Useful examples

```text
ip.addr == 8.8.8.8
ip.src == 192.168.1.10 and dns
tcp.port == 443
udp.dstport == 53
frame.len > 1000
info contains "Query"
(http or https) and not ip.dst == 192.168.1.1
```

---

## Host Aliases

The dashboard includes a **Hostname** button that opens a modal for per-report IP overrides. The modal only allows choosing IPs already observed in the PCAP; users cannot type arbitrary IPs. After saving an alias such as `192.168.8.1 -> my_router`, the dashboard builds a display copy of the report and replaces that IP with `my_router` across the UI.

Aliases are stored in the analysis JSON as `host_aliases`, so they are preserved when a saved analysis is reloaded. The original report data remains IP-based internally, while the web UI receives the aliased display version.

---

## External IP Enrichment

The **Analyze with external tools** button first shows a consent popup, then sends observed public IPs to the backend and collects additional information from multiple sources.

| Source | Data retrieved |
| --- | --- |
| RDAP/IANA | Registry, IP range, handle, resource name, entities, and RDAP notes. |
| Team Cymru | ASN, BGP prefix, registry, country code, and AS name. |
| Reverse DNS | PTR name associated with the IP address. |
| ip-api | Country, region, city, ISP, organization, timezone, proxy/VPN, mobile, and hosting flags. |

Private, local, multicast, reserved, and otherwise non-global addresses are discarded and are **not sent to external services**.

Enrichment is opt-in and only runs after the user confirms the dedicated popup.

### Results usage

Results are used to:

- enrich the **Top IPs** popup;
- color the **IP traffic map** and show related flows by country;
- feed the **Security** panel;
- provide context to the **Advanced security** tab;
- include external information in the JSON export.

---

## 5-Tuple Flows & Advanced Traces

The backend reconstructs true 5-tuple TCP/UDP flows while streaming the PCAP.

Each flow is identified by the first observed direction:

```text
src_ip, src_port, dst_ip, dst_port, L4 protocol
```

For each item in `flows`, PCAPCaper computes:

- `flow_id`;
- source IP and port;
- destination IP and port;
- L4 protocol;
- first and last timestamp;
- duration;
- total packets and bytes;
- client-to-server and server-to-client packets/bytes;
- aggregated TCP flags;
- approximate state: `opening`, `established`, `closing`, `closed`, `reset`, `request_response`, or `one_way`;
- packet numbers that belong to the flow.

The **Advanced traces** tab uses these data to show the flow ID, backend-computed state, and directional counters at the roots of the trace tree. Visual packet-response-ACK correlation remains available as a navigable tree.

---

## Security Analysis

### Basic Security Panel

The **Security** panel reports potentially risky connections using locally collected data and optional external enrichment.

Findings are heuristic and do not replace dedicated threat intelligence feeds or blacklists.

Current rules consider:

- IPs reported as proxy/VPN;
- IPs associated with hosting or datacenters;
- traffic to cleartext services such as HTTP, FTP, Telnet, SMTP, POP3, and IMAP;
- remote administration services such as SSH, RDP, VNC, SMB, and Telnet;
- database services such as MySQL, PostgreSQL, Redis, MongoDB, MSSQL, and Oracle;
- sensitive ports;
- high traffic volume compared with other destinations;
- destinations geolocated outside the local context.

Each finding shows IP, severity, score, ASN/country when available, traffic volume, packets, and concrete reasons.

### Advanced Security

The **Advanced security** tab runs a deeper triage-oriented analysis. To reduce CPU usage and avoid unwanted external requests, the workflow is explicit:

1. upload and analyze the PCAP;
2. click **Analyze with external tools** to enrich IPs;
3. open **Advanced security**;
4. click **Security analysis**;
5. confirm the popup explaining which external services may be used.

#### Sources and data used

| Source | Requirements | Data used |
| --- | --- | --- |
| Shodan InternetDB | No API key | Exposed ports, CPEs, tags, hostnames, and CVEs associated with the IP. |
| Feodo Tracker | No API key | Botnet C2 indicators from the public JSON feed. |
| URLhaus | Backend variable `URLHAUS_AUTH_KEY` | Hosts associated with malware distribution URLs. |
| Local PCAPCaper engine | None | Peers, ports, protocols, volumes, fan-out, and packet samples. |

#### Tab output

The tab shows:

- severity counters: critical, high, medium, low;
- findings sorted by risk;
- 0-100 score and confidence;
- concrete evidence from packets and external sources;
- operational recommendations for triage, containment, or verification;
- MITRE ATT&CK references when relevant;
- status of used sources and non-blocking errors;
- ranking of the riskiest IPs.

#### Privacy and control

The `/api/security-analysis` call is opt-in. The popup informs the user before sending data to third-party services.

The backend only uses public IP addresses for external lookups. Private, local, and reserved IPs are not used for threat intelligence queries.

---

## DNS Analysis

The **DNS** tab is dedicated to DNS requests observed in the PCAP. The view is AdGuard-inspired and provides immediate summaries, top domains, most active clients, resolvers, and tracking, advertising, or risk indicators.

### Local analysis

Without sending data outside, the backend produces a `dns` section in the analysis JSON.

The tab:

- extracts DNS queries, record types, and transaction IDs;
- correlates responses with queries when possible;
- shows response codes such as `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`;
- shows answers and TTLs when available;
- identifies requesting clients and queried resolvers;
- aggregates top domains, top clients, and top resolvers;
- calculates the NXDOMAIN ratio;
- flags suspicious TXT queries;
- highlights possible DNS tunneling indicators: very long labels, many unique subdomains, high approximate entropy, and abnormal volume toward the same domain;
- correlates domain → answer IP → later flows when the returned IP appears in the 5-tuple flows.

The view includes filters by domain, client, record type, and rcode.

### External list checks

The **Check external lists** button shows a consent popup before any external request.

After confirmation, the backend checks domains against:

| Source | Requirements | Data used |
| --- | --- | --- |
| AdGuard DNS filter | No API key | DNS-level rules for ads, tracking, cryptomining, and malicious domains. |
| StevenBlack hosts | No API key | Aggregated hosts list for ads, tracking, and malware. |
| URLhaus | Backend variable `URLHAUS_AUTH_KEY` | Hosts associated with malware distribution URLs. |

The response shows used sources, download status, non-blocking errors, categories, and rules that produced matches.

### Privacy

Local DNS analysis is privacy-by-default: it only uses the uploaded PCAP and does not send domains to external services.

External DNS reputation is opt-in. No domain is sent to external services during PCAP upload or standard analysis. Sending happens only from the **DNS** tab, after explicit user confirmation.

---

## HTTP Analysis

The **HTTP analysis** tab shows HTTP metadata extracted only from cleartext traffic. It does not decrypt HTTPS/TLS and does not send data to external services.

### Extracted data

For HTTP requests:

- timestamp;
- client IP and port;
- server IP and port;
- method;
- host;
- URI/path;
- user-agent;
- referer;
- content-type;
- approximate payload size.

For HTTP responses:

- status code;
- reason phrase;
- `Server` header;
- content-type;
- content-length;
- file name inferred from `Content-Disposition` or the request URI.

### Tab features

- request table with correlated responses when possible;
- most contacted hosts;
- most frequent user agents;
- filters by host, method, status, and user-agent.

### Limitations

The parser is conservative:

- it only analyzes TCP payloads that start as textual HTTP;
- full payload reconstruction is available in the separate **Follow stream** tab, but HTTP metadata extraction remains conservative;
- fragmented headers or bodies may be marked as partial;
- payload size is estimated from `Content-Length` or from bytes present in the observed segment;
- encrypted HTTPS/TLS traffic is not interpreted.

---

## Follow Stream

The **Follow stream** tab reconstructs bounded TCP/UDP application payloads during backend analysis. It groups packets by the same bidirectional 5-tuple used by the flow engine and shows:

- stream list with endpoints, protocol, bytes, packet count, and truncation state;
- combined capture-order transcript with `C -> S` and `S -> C` markers;
- client-only and server-only reconstructed text views;
- per-packet segment previews with text and hex.

TCP payloads are ordered per direction by sequence number for the directional views. UDP payloads remain in capture order. TLS is not decrypted, so encrypted streams remain binary/encrypted evidence. The stored payload size is controlled by configuration variables in `.env`.

The implementation is intentionally bounded: it does not attempt full file extraction, TLS decryption, or advanced duplicate/retransmission repair. It is designed for fast triage and readable payload inspection from the web UI.

---

## TLS Analysis

The **TLS analysis** tab analyzes SSL/TLS using only observable metadata from handshake records present in the PCAP.

It does not decrypt traffic, does not require private keys, and does not show encrypted application content.

### Extracted data

When available, it extracts:

- SNI from `ClientHello`;
- offered or negotiated TLS version;
- cipher suite negotiated in `ServerHello`;
- advertised or negotiated ALPN;
- subject and issuer of the leaf certificate;
- certificate validity period;
- SHA256 fingerprint of the DER certificate;
- JA3 and JA3S fingerprints when the required messages are complete;
- partial state when records or handshakes are fragmented.

### Tab features

- TLS connections table with client, server, SNI, version, cipher, certificate, and fingerprint;
- filters by SNI, server IP, version, and anomaly presence;
- summaries of most frequent SNI values, TLS versions, and certificate issuers;
- parser limitation panel to clearly separate what is observable from what is not.

### Anomalies (heuristic)

- certificate expired at the capture timestamp;
- certificate not yet valid;
- self-signed certificate;
- missing SNI;
- legacy TLS: `SSL 3.0`, `TLS 1.0`, or `TLS 1.1`;
- approximate mismatch between DNS observed in the PCAP and SNI.

### Limitations

- does not decrypt TLS payloads;
- does not fully reconstruct TCP streams;
- TLS records fragmented across multiple segments may be marked as partial;
- subject and issuer are available only if the certificate is present in the PCAP and can be decoded by the Python standard library;
- DNS/SNI mismatch uses only DNS responses seen in the capture, so false positives may occur if DNS is absent, cached, or resolved outside the capture.

---

## Hosts

The **Hosts** tab shows a detail view for each IP observed in the PCAP. Sections are collapsible and closed by default. IPs in the packet list are clickable and open the **Hosts** tab filtered on that address.

For each host, PCAPCaper shows:

- estimated role: `client`, `server`, `mixed`, or `unknown`;
- private/public classification;
- hostnames inferred from DNS observed in the PCAP and reverse DNS from external tools when available;
- ASN, organization, and geolocation if IP enrichment was enabled by the user;
- used protocols;
- contacted remote ports;
- exposed or observed server-side ports;
- sent and received bytes and packets;
- related flows;
- generated DNS queries;
- observed TLS SNI values and HTTP hosts;
- associated findings such as cleartext HTTP or TLS anomalies;
- activity timeline with sent and received bytes per time bucket.

The `hosts` section is computed by the backend during standard analysis and does not send data to external services.

ASN/geo data are only displayed when already present in `external_ip_info`, after user consent through **Analyze with external tools**.

---

## Network Graph

The **Graph** tab shows a host-to-host representation built from backend-computed 5-tuple flows.

### Characteristics

- each node represents an IP/host;
- each edge aggregates one or more flows between two hosts;
- edge thickness can be based on bytes or packets;
- node color highlights internal/external hosts and finding presence;
- for very large captures, the graph is limited to the heaviest flows to keep the UI responsive.

### Filters

- flow protocol;
- internal, external, or internal ↔ external communications;
- finding severity inferred from available evidence;
- weight metric: bytes or packets.

### Interactions

- click on a node to show host summary, traffic, protocols, related flows, and findings;
- click on an edge to show underlying flows, endpoints, traffic, packets, and flow state.

The view is implemented in SVG without adding new frontend dependencies.

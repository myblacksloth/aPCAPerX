"""
Analisi di sicurezza avanzata del traffico PCAP.

Il modulo combina osservazioni locali sui pacchetti con arricchimento esterno
gia raccolto dall'utente e, solo quando l'endpoint viene invocato, interroga
fonti di threat intelligence aperte. L'obiettivo e fornire una vista simile a
un triage SOC: priorita, evidenze, confidenza e raccomandazioni operative.
"""

import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from models import (
    IPExternalInfo,
    SecurityAnalysisRequest,
    SecurityAnalysisResponse,
    SecurityAnalysisSummary,
    SecurityFindingModel,
    SecurityIPAssessmentModel,
    SecuritySourceStatus,
)
from config import HTTP_TIMEOUT_SECONDS


# Porte note che meritano attenzione quando compaiono verso/da Internet.
REMOTE_ADMIN_PORTS = {22, 23, 3389, 5900, 5901, 5985, 5986}
DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 27017}
CLEAR_TEXT_PORTS = {21, 23, 25, 80, 110, 143, 8080}
BOTNET_COMMON_PORTS = {4444, 5555, 6666, 6667, 1337, 31337}


@dataclass
class IPObservation:
    """Aggregato locale di traffico per un singolo IP."""

    ip: str
    packets: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    ports: Set[int] = field(default_factory=set)
    protocols: Set[str] = field(default_factory=set)
    peers: Set[str] = field(default_factory=set)
    samples: List[str] = field(default_factory=list)


def _severity_from_score(score: int) -> str:
    """Converte uno score numerico in severita operativa."""
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def _public_ip(ip: str) -> bool:
    """Ritorna True solo per IP globali che possono essere inviati a fonti esterne."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _unique_sorted_ports(ports: Iterable[int]) -> List[int]:
    """Normalizza le porte mantenendo output stabile e compatto."""
    return sorted({port for port in ports if isinstance(port, int) and 0 < port <= 65535})


def _fetch_json(url: str) -> Dict:
    """Scarica JSON via GET usando solo libreria standard."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "PCAPCaper/1.0 security-analysis",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _post_form_json(url: str, data: Dict[str, str], headers: Optional[Dict[str, str]] = None) -> Dict:
    """Invia una POST form-urlencoded e decodifica la risposta JSON."""
    body = urllib.parse.urlencode(data).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "User-Agent": "PCAPCaper/1.0 security-analysis",
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _build_observations(payload: SecurityAnalysisRequest) -> Dict[str, IPObservation]:
    """Aggrega pacchetti per IP calcolando direzione, peer, porte e campioni."""
    observations: Dict[str, IPObservation] = {}

    def get(ip: str) -> IPObservation:
        if ip not in observations:
            observations[ip] = IPObservation(ip=ip)
        return observations[ip]

    for packet in payload.packets:
        src = packet.src_ip
        dst = packet.dst_ip
        if not src and not dst:
            continue

        for ip in (src, dst):
            if not ip:
                continue
            item = get(ip)
            item.packets += 1
            item.protocols.add(packet.protocol)
            if packet.src_port:
                item.ports.add(packet.src_port)
            if packet.dst_port:
                item.ports.add(packet.dst_port)
            if len(item.samples) < 4:
                item.samples.append(
                    f"#{packet.number} {packet.timestamp} {src or '?'}:{packet.src_port or '-'} -> "
                    f"{dst or '?'}:{packet.dst_port or '-'} {packet.protocol} {packet.length}B"
                )

        if src and dst:
            get(src).peers.add(dst)
            get(dst).peers.add(src)
            get(src).bytes_out += packet.length
            get(dst).bytes_in += packet.length

    return observations


def _query_shodan_internetdb(ip: str, errors: List[str]) -> Optional[Dict]:
    """Interroga Shodan InternetDB, che non richiede API key."""
    try:
        return _fetch_json(f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        errors.append(f"Shodan InternetDB {ip}: HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        errors.append(f"Shodan InternetDB {ip}: {exc}")
    return None


def _load_feodo_blocklist(errors: List[str]) -> Dict[str, Dict]:
    """Scarica il feed JSON Feodo Tracker e lo indicizza per IP."""
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    try:
        data = _fetch_json(url)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        errors.append(f"Feodo Tracker: {exc}")
        return {}

    if not isinstance(data, list):
        errors.append("Feodo Tracker: formato JSON inatteso")
        return {}

    indexed: Dict[str, Dict] = {}
    for row in data:
        if isinstance(row, dict) and isinstance(row.get("ip_address"), str):
            indexed[row["ip_address"]] = row
    return indexed


def _query_urlhaus_host(ip: str, external: Optional[IPExternalInfo], errors: List[str]) -> Optional[Dict]:
    """Interroga URLhaus solo se l'utente ha configurato un Auth-Key server-side."""
    auth_key = os.getenv("URLHAUS_AUTH_KEY")
    if not auth_key:
        return None

    hosts = [ip]
    if external and external.reverse_dns:
        hosts.append(external.reverse_dns)

    for host in dict.fromkeys(hosts):
        try:
            data = _post_form_json(
                "https://urlhaus-api.abuse.ch/v1/host/",
                {"host": host},
                {"Auth-Key": auth_key},
            )
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            errors.append(f"URLhaus {host}: {exc}")
            continue

        if data.get("query_status") == "ok":
            return data
    return None


def _finding(
    *,
    finding_id: str,
    severity_score: int,
    category: str,
    title: str,
    description: str,
    ip: str,
    evidence: List[str],
    recommendation: str,
    sources: List[str],
    confidence: int,
    mitre: Optional[List[str]] = None,
) -> SecurityFindingModel:
    """Crea un finding normalizzando severita, score e campi comuni."""
    return SecurityFindingModel(
        id=finding_id,
        severity=_severity_from_score(severity_score),
        category=category,
        title=title,
        description=description,
        ip=ip,
        evidence=evidence,
        recommendation=recommendation,
        sources=sources,
        confidence=max(0, min(confidence, 100)),
        score=max(0, min(severity_score, 100)),
        mitre=mitre or [],
    )


def analyze_security(payload: SecurityAnalysisRequest) -> SecurityAnalysisResponse:
    """Esegue l'analisi avanzata e restituisce finding ordinati per priorita."""
    errors: List[str] = []
    sources: List[SecuritySourceStatus] = []
    observations = _build_observations(payload)
    public_ips = [ip for ip in observations if _public_ip(ip)]
    selected_ips = public_ips[: max(1, min(payload.max_ips, 150))]

    findings: List[SecurityFindingModel] = []
    assessments: Dict[str, SecurityIPAssessmentModel] = {}

    # Il feed Feodo viene scaricato una sola volta per richiesta e poi usato come set IOC.
    feodo_index = _load_feodo_blocklist(errors)
    sources.append(SecuritySourceStatus(
        source="Feodo Tracker",
        status="ok" if feodo_index else "partial",
        detail=f"{len(feodo_index)} indicatori C2 caricati dal feed pubblico",
    ))

    urlhaus_enabled = bool(os.getenv("URLHAUS_AUTH_KEY"))
    sources.append(SecuritySourceStatus(
        source="URLhaus",
        status="ok" if urlhaus_enabled else "skipped",
        detail="Host API attiva tramite URLHAUS_AUTH_KEY" if urlhaus_enabled else "Auth-Key non configurata: fonte saltata",
    ))

    shodan_ok = 0

    for ip in selected_ips:
        observation = observations[ip]
        external = payload.external_ip_info.get(ip)
        ports = _unique_sorted_ports(observation.ports)
        shodan = _query_shodan_internetdb(ip, errors)
        urlhaus = _query_urlhaus_host(ip, external, errors)

        shodan_ports = _unique_sorted_ports(shodan.get("ports", [])) if isinstance(shodan, dict) else []
        shodan_vulns = sorted(shodan.get("vulns", [])) if isinstance(shodan, dict) and isinstance(shodan.get("vulns"), list) else []
        shodan_tags = sorted(shodan.get("tags", [])) if isinstance(shodan, dict) and isinstance(shodan.get("tags"), list) else []
        if shodan is not None:
            shodan_ok += 1

        score = 0
        related_findings: List[str] = []

        if ip in feodo_index:
            row = feodo_index[ip]
            finding = _finding(
                finding_id=f"feodo-{ip}",
                severity_score=98,
                category="Threat intelligence",
                title="IP presente in Feodo Tracker come infrastruttura C2",
                description="L'indirizzo e presente nel feed pubblico Feodo Tracker dedicato a command-and-control di botnet.",
                ip=ip,
                evidence=[
                    f"Malware/famiglia: {row.get('malware') or row.get('malware_family') or 'non specificato'}",
                    f"Prima osservazione: {row.get('first_seen_utc') or row.get('first_seen') or 'non disponibile'}",
                    *observation.samples[:2],
                ],
                recommendation="Isolare gli host interni che hanno comunicato con questo IP, cercare beaconing e bloccare l'indicatore su firewall/DNS.",
                sources=["Feodo Tracker", "Traffico PCAP"],
                confidence=95,
                mitre=["T1071", "T1105"],
            )
            findings.append(finding)
            related_findings.append(finding.id)
            score = max(score, finding.score)

        if urlhaus and urlhaus.get("query_status") == "ok":
            url_count = str(urlhaus.get("url_count", "0"))
            finding = _finding(
                finding_id=f"urlhaus-{ip}",
                severity_score=92,
                category="Malware distribution",
                title="Host osservato in URLhaus",
                description="URLhaus associa questo host a URL usati per distribuzione malware.",
                ip=ip,
                evidence=[
                    f"URL osservati da URLhaus: {url_count}",
                    f"Primo avvistamento: {urlhaus.get('firstseen', 'non disponibile')}",
                    *[f"{item.get('url_status', 'unknown')} - {item.get('url', item.get('urlhaus_reference', 'URL non disponibile'))}" for item in urlhaus.get("urls", [])[:3] if isinstance(item, dict)],
                ],
                recommendation="Verificare se il traffico HTTP/TLS contiene download o redirect, bloccare l'host e cercare payload sugli endpoint coinvolti.",
                sources=["URLhaus", "Traffico PCAP"],
                confidence=90,
                mitre=["T1105", "T1204"],
            )
            findings.append(finding)
            related_findings.append(finding.id)
            score = max(score, finding.score)

        if shodan_vulns:
            finding = _finding(
                finding_id=f"vulns-{ip}",
                severity_score=86,
                category="Exposure",
                title="Servizi esposti con CVE note secondo Shodan InternetDB",
                description="InternetDB associa l'IP a servizi con vulnerabilita note; la fonte puo includere risultati non verificati.",
                ip=ip,
                evidence=[
                    f"CVE: {', '.join(shodan_vulns[:8])}",
                    f"Porte esposte: {', '.join(map(str, shodan_ports[:12])) or 'non disponibili'}",
                    *observation.samples[:2],
                ],
                recommendation="Confermare le CVE con scansione autorizzata, verificare patching e limitare l'accesso ai servizi esposti.",
                sources=["Shodan InternetDB", "Traffico PCAP"],
                confidence=78,
                mitre=["T1190"],
            )
            findings.append(finding)
            related_findings.append(finding.id)
            score = max(score, finding.score)

        exposed_admin = sorted((set(ports) | set(shodan_ports)) & REMOTE_ADMIN_PORTS)
        if exposed_admin:
            finding = _finding(
                finding_id=f"remote-admin-{ip}",
                severity_score=68 if external and external.hosting else 58,
                category="Remote access",
                title="Servizi di amministrazione remota osservati",
                description="Il traffico o InternetDB evidenzia porte amministrative raggiunte o esposte su un IP pubblico.",
                ip=ip,
                evidence=[
                    f"Porte amministrative: {', '.join(map(str, exposed_admin))}",
                    f"Peer distinti nel PCAP: {len(observation.peers)}",
                    *observation.samples[:2],
                ],
                recommendation="Verificare che l'accesso sia atteso, protetto da MFA/VPN e limitato a sorgenti autorizzate.",
                sources=["Traffico PCAP", *(["Shodan InternetDB"] if shodan_ports else [])],
                confidence=72,
                mitre=["T1021"],
            )
            findings.append(finding)
            related_findings.append(finding.id)
            score = max(score, finding.score)

        risky_data_ports = sorted(set(ports) & (DATABASE_PORTS | CLEAR_TEXT_PORTS | BOTNET_COMMON_PORTS))
        if risky_data_ports:
            finding = _finding(
                finding_id=f"risky-ports-{ip}",
                severity_score=48,
                category="Policy",
                title="Traffico verso porte sensibili o non cifrate",
                description="Sono state osservate porte che spesso indicano servizi non cifrati, database esposti o canali anomali.",
                ip=ip,
                evidence=[
                    f"Porte rilevate: {', '.join(map(str, risky_data_ports))}",
                    f"Protocolli: {', '.join(sorted(observation.protocols))}",
                ],
                recommendation="Validare la necessita del servizio, preferire canali cifrati e segmentare il traffico verso database e console.",
                sources=["Traffico PCAP"],
                confidence=64,
                mitre=["T1041", "T1571"],
            )
            findings.append(finding)
            related_findings.append(finding.id)
            score = max(score, finding.score)

        if external and (external.proxy or external.hosting):
            labels = []
            if external.proxy:
                labels.append("proxy/VPN")
            if external.hosting:
                labels.append("hosting/datacenter")
            finding = _finding(
                finding_id=f"infra-{ip}",
                severity_score=35,
                category="Infrastructure",
                title="Infrastruttura anonima o datacenter",
                description="L'arricchimento IP segnala caratteristiche spesso presenti in relay, proxy, C2 o infrastrutture temporanee.",
                ip=ip,
                evidence=[
                    f"Indicatori: {', '.join(labels)}",
                    f"ASN/Org: {external.asn or '-'} {external.as_name or external.org or ''}".strip(),
                    f"Paese: {external.country or external.country_code or 'non disponibile'}",
                ],
                recommendation="Contestualizzare con il processo/applicazione sorgente e verificare periodicita o volumi anomali.",
                sources=["Arricchimento IP", "Traffico PCAP"],
                confidence=55,
                mitre=["T1090"],
            )
            findings.append(finding)
            related_findings.append(finding.id)
            score = max(score, finding.score)

        if len(observation.peers) >= 20:
            finding = _finding(
                finding_id=f"fanout-{ip}",
                severity_score=42,
                category="Anomaly",
                title="Fan-out elevato verso molti peer",
                description="L'IP comunica con molti peer distinti: puo indicare scansione, discovery o servizio molto centrale.",
                ip=ip,
                evidence=[
                    f"Peer distinti: {len(observation.peers)}",
                    f"Pacchetti osservati: {observation.packets}",
                ],
                recommendation="Controllare direzione, frequenza e distribuzione temporale; correlare con asset inventory e log endpoint.",
                sources=["Traffico PCAP"],
                confidence=50,
                mitre=["T1046"],
            )
            findings.append(finding)
            related_findings.append(finding.id)
            score = max(score, finding.score)

        assessments[ip] = SecurityIPAssessmentModel(
            ip=ip,
            risk_score=score,
            severity=_severity_from_score(score),
            packets=observation.packets,
            bytes_out=observation.bytes_out,
            bytes_in=observation.bytes_in,
            ports=ports[:30],
            protocols=sorted(observation.protocols),
            peer_count=len(observation.peers),
            country=external.country if external else None,
            asn=external.asn if external else None,
            as_name=(external.as_name or external.org) if external else None,
            tags=shodan_tags,
            vulnerabilities=shodan_vulns[:20],
            findings=related_findings,
        )

    sources.append(SecuritySourceStatus(
        source="Shodan InternetDB",
        status="ok" if shodan_ok else "partial",
        detail=f"{shodan_ok}/{len(selected_ips)} IP con risposta utile o 404 gestito",
    ))
    sources.append(SecuritySourceStatus(
        source="Motore euristico PCAPCaper",
        status="ok",
        detail=f"{len(payload.packets)} pacchetti correlati localmente",
    ))

    findings.sort(key=lambda item: (item.score, item.confidence), reverse=True)
    ordered_assessments = sorted(
        assessments.values(),
        key=lambda item: (item.risk_score, item.packets),
        reverse=True,
    )

    counts = {level: len([item for item in findings if item.severity == level]) for level in ["critical", "high", "medium", "low", "info"]}
    summary = SecurityAnalysisSummary(
        total_ips=len(observations),
        analyzed_public_ips=len(selected_ips),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        total_findings=len(findings),
    )

    return SecurityAnalysisResponse(
        summary=summary,
        findings=findings[:100],
        ip_assessments=ordered_assessments[:150],
        sources=sources,
        errors=errors[:50],
    )

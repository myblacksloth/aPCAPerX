"""
Arricchimento esterno degli indirizzi IP.

Questo modulo viene usato solo quando l'utente preme il pulsante dedicato nel
frontend. In questo modo gli indirizzi estratti dal PCAP non vengono inviati a
servizi terzi durante la normale analisi del file.
"""

import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from typing import Dict, Iterable, List, Optional

from models import IPExternalInfo
from config import EXTERNAL_MAX_WORKERS, HTTP_TIMEOUT_SECONDS, MAX_ENRICHMENT_IPS, SOCKET_TIMEOUT_SECONDS


def _fetch_json(url: str) -> Dict:
    """Scarica e decodifica JSON da un servizio esterno usando solo stdlib."""
    request = urllib.request.Request(
        url,
        headers={
            # User-Agent esplicito per rendere identificabile l'applicazione.
            "User-Agent": "PCAPCaper/1.0 IP enrichment",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _append_source(info: IPExternalInfo, source: str) -> None:
    """Aggiunge una fonte evitando duplicati."""
    if source not in info.sources:
        info.sources.append(source)


def _first_string(values: Iterable) -> Optional[str]:
    """Restituisce la prima stringa non vuota da una sequenza generica."""
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _public_ip_or_skip(ip: str) -> Optional[ipaddress._BaseAddress]:
    """Valida l'IP e ritorna None se non deve essere inviato a servizi esterni."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return None

    # Evita di inviare a terzi tutto cio che non e instradabile pubblicamente.
    if not parsed.is_global:
        return None

    return parsed


def _reverse_dns(ip: str, info: IPExternalInfo) -> None:
    """Recupera il nome PTR tramite DNS inverso."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname:
            info.reverse_dns = hostname.rstrip(".")
            _append_source(info, "Reverse DNS")
    except (OSError, socket.herror) as exc:
        info.errors.append(f"Reverse DNS: {exc}")


def _team_cymru(ip: str, info: IPExternalInfo) -> None:
    """Interroga Team Cymru via WHOIS per ASN, prefisso BGP e registry."""
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=SOCKET_TIMEOUT_SECONDS) as sock:
            # -v abilita il formato esteso con prefisso, country, registry e descrizione AS.
            sock.sendall(f" -v {ip}\n".encode("ascii"))
            raw = sock.recv(4096).decode("utf-8", errors="replace")
    except OSError as exc:
        info.errors.append(f"Team Cymru: {exc}")
        return

    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) < 2:
        info.errors.append("Team Cymru: risposta vuota")
        return

    # Formato atteso:
    # AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    parts = [part.strip() for part in lines[-1].split("|")]
    if len(parts) >= 7:
        info.asn = info.asn or parts[0]
        info.bgp_prefix = info.bgp_prefix or parts[2]
        info.country_code = info.country_code or parts[3]
        info.registry = info.registry or parts[4]
        info.allocated = info.allocated or parts[5]
        info.as_name = info.as_name or parts[6]
        _append_source(info, "Team Cymru")


@lru_cache(maxsize=2)
def _rdap_bootstrap(version: int) -> Dict:
    """Carica il bootstrap RDAP IANA per IPv4 o IPv6."""
    filename = "ipv4.json" if version == 4 else "ipv6.json"
    return _fetch_json(f"https://data.iana.org/rdap/{filename}")


def _rdap_base_url(parsed_ip: ipaddress._BaseAddress) -> Optional[str]:
    """Trova il server RDAP corretto usando i bootstrap IANA."""
    bootstrap = _rdap_bootstrap(parsed_ip.version)
    for service in bootstrap.get("services", []):
        ranges, urls = service
        for value in ranges:
            try:
                if parsed_ip in ipaddress.ip_network(value, strict=False):
                    return _first_string(urls)
            except ValueError:
                continue
    return None


def _rdap_entities(data: Dict) -> List[str]:
    """Estrae nomi leggibili dalle entità RDAP principali."""
    entities: List[str] = []
    for entity in data.get("entities", [])[:8]:
        name = None
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for field in vcard[1]:
                if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                    name = field[3]
                    break
        handle = entity.get("handle")
        label = name or handle
        if isinstance(label, str) and label and label not in entities:
            entities.append(label)
    return entities


def _rdap_remarks(data: Dict) -> List[str]:
    """Estrae poche note RDAP utili evitando risposte troppo verbose."""
    remarks: List[str] = []
    for remark in data.get("remarks", [])[:4]:
        title = remark.get("title")
        description = " ".join(str(item) for item in remark.get("description", [])[:2])
        text = " - ".join(part for part in (title, description) if part)
        if text:
            remarks.append(text[:240])
    return remarks


def _rdap(ip: str, parsed_ip: ipaddress._BaseAddress, info: IPExternalInfo) -> None:
    """Interroga RDAP per dati autoritativi di assegnazione della risorsa IP."""
    try:
        base_url = _rdap_base_url(parsed_ip)
        if not base_url:
            info.errors.append("RDAP: server non trovato nel bootstrap IANA")
            return

        url = urllib.parse.urljoin(base_url.rstrip("/") + "/", f"ip/{ip}")
        data = _fetch_json(url)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        info.errors.append(f"RDAP: {exc}")
        return

    info.rdap_handle = info.rdap_handle or data.get("handle")
    info.rdap_name = info.rdap_name or data.get("name")
    info.rdap_type = info.rdap_type or data.get("type")
    info.rdap_start_address = info.rdap_start_address or data.get("startAddress")
    info.rdap_end_address = info.rdap_end_address or data.get("endAddress")
    info.country_code = info.country_code or data.get("country")
    info.org = info.org or data.get("name")
    info.rdap_entities = _rdap_entities(data)
    info.rdap_remarks = _rdap_remarks(data)
    _append_source(info, "RDAP/IANA")


def _ip_api(ip: str, info: IPExternalInfo) -> None:
    """Interroga ip-api.com per geolocalizzazione, ISP e indicatori proxy/hosting."""
    fields = ",".join([
        "status", "message", "country", "countryCode", "regionName", "city",
        "lat", "lon", "timezone", "isp", "org", "as", "asname",
        "mobile", "proxy", "hosting", "query",
    ])
    url = f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields={urllib.parse.quote(fields)}"

    try:
        data = _fetch_json(url)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        info.errors.append(f"ip-api: {exc}")
        return

    if data.get("status") != "success":
        info.errors.append(f"ip-api: {data.get('message', 'risposta non valida')}")
        return

    info.country = info.country or data.get("country")
    info.country_code = info.country_code or data.get("countryCode")
    info.region = info.region or data.get("regionName")
    info.city = info.city or data.get("city")
    info.lat = info.lat if info.lat is not None else data.get("lat")
    info.lon = info.lon if info.lon is not None else data.get("lon")
    info.timezone = info.timezone or data.get("timezone")
    info.isp = info.isp or data.get("isp")
    info.org = info.org or data.get("org")
    info.as_name = info.as_name or data.get("asname")
    info.mobile = data.get("mobile")
    info.proxy = data.get("proxy")
    info.hosting = data.get("hosting")

    # Il campo "as" contiene spesso "AS12345 Nome"; manteniamo il numero se manca.
    as_field = data.get("as")
    if not info.asn and isinstance(as_field, str):
        info.asn = as_field.split()[0].replace("AS", "")

    _append_source(info, "ip-api")


def enrich_ip(ip: str) -> IPExternalInfo:
    """Arricchisce un singolo IP pubblico aggregando più servizi esterni."""
    parsed_ip = _public_ip_or_skip(ip)
    if parsed_ip is None:
        return IPExternalInfo(
            ip=ip,
            status="skipped",
            reason="Indirizzo privato, locale, riservato o non valido: non inviato a servizi esterni.",
        )

    info = IPExternalInfo(ip=ip, status="enriched")
    _reverse_dns(ip, info)
    _team_cymru(ip, info)
    _rdap(ip, parsed_ip, info)
    _ip_api(ip, info)

    if not info.sources:
        info.status = "error"
        info.reason = "Nessun servizio esterno ha restituito dati utili."

    return info


def enrich_ips(ips: List[str]) -> Dict[str, IPExternalInfo]:
    """Arricchisce una lista di IP con concorrenza limitata e ordine stabile."""
    unique_ips = list(dict.fromkeys(ip.strip() for ip in ips if isinstance(ip, str) and ip.strip()))
    selected_ips = unique_ips[:MAX_ENRICHMENT_IPS]
    if not selected_ips:
        return {}

    results: Dict[str, IPExternalInfo] = {}
    # Parallelizza per IP, ma con pochi worker per non stressare servizi gratuiti.
    with ThreadPoolExecutor(max_workers=min(EXTERNAL_MAX_WORKERS, len(selected_ips))) as executor:
        future_to_ip = {executor.submit(enrich_ip, ip): ip for ip in selected_ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
            except Exception as exc:
                results[ip] = IPExternalInfo(
                    ip=ip,
                    status="error",
                    reason=f"Errore imprevisto durante l'arricchimento: {exc}",
                )

    return {ip: results[ip] for ip in selected_ips if ip in results}

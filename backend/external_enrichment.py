"""
Arricchimento esterno degli indirizzi IP.

Questo modulo viene usato solo quando l'utente preme il pulsante dedicato nel
frontend. In questo modo gli indirizzi estratti dal PCAP non vengono inviati a
servizi terzi durante la normale analisi del file.
"""

import ipaddress
import csv
import io
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Tuple

from models import IPExternalInfo, MACExternalInfo
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


def _fetch_json_any(url: str) -> Any:
    """Scarica e decodifica JSON quando la risposta puo essere dict o list."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "PCAPCaper/1.0 MAC enrichment",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _fetch_text(url: str) -> str:
    """Scarica testo semplice da un servizio esterno usando solo stdlib."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "PCAPCaper/1.0 MAC enrichment",
            "Accept": "text/plain",
        },
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8", errors="replace").strip()


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


def _normalize_mac(value: str) -> Optional[str]:
    """Normalizza un indirizzo MAC in formato aa:bb:cc:dd:ee:ff."""
    text = str(value or "").strip().lower().replace("-", ":")
    if "." in text and ":" not in text:
        compact = text.replace(".", "")
        if len(compact) == 12:
            text = ":".join(compact[i:i + 2] for i in range(0, 12, 2))

    parts = text.split(":")
    if len(parts) != 6:
        return None

    try:
        return ":".join(f"{int(part, 16):02x}" for part in parts)
    except ValueError:
        return None


def _mac_compact(mac: str) -> str:
    """Restituisce il MAC normalizzato come 12 cifre esadecimali maiuscole."""
    return mac.replace(":", "").upper()


def _mac_oui(mac: str) -> str:
    """Restituisce l'OUI MA-L come sei cifre esadecimali."""
    return _mac_compact(mac)[:6]


def _is_lookupable_mac(mac: str) -> bool:
    """Evita lookup esterni solo per MAC placeholder, broadcast o multicast."""
    if mac in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return False
    first_octet = int(mac.split(":")[0], 16)
    return (first_octet & 1) == 0


def _is_locally_administered_mac(mac: str) -> bool:
    """Rileva MAC con bit U/L impostato: spesso randomizzati o virtuali."""
    first_octet = int(mac.split(":")[0], 16)
    return (first_octet & 2) != 0


def _known_virtual_vendor(mac: str) -> Optional[Tuple[str, str]]:
    """Riconosce prefissi virtuali/locali comuni che spesso non sono nei DB OUI."""
    compact = _mac_compact(mac)
    known_prefixes = {
        "0242": "Docker container",
        "525400": "QEMU/KVM virtual machine",
        "080027": "Oracle VirtualBox",
        "0A0027": "Oracle VirtualBox",
        "000569": "VMware",
        "000C29": "VMware",
        "001C14": "VMware",
        "005056": "VMware",
        "00155D": "Microsoft Hyper-V",
        "001C42": "Parallels",
        "00163E": "Xen",
        "0A580A": "Kubernetes/CNI virtual interface",
    }
    for prefix, vendor in sorted(known_prefixes.items(), key=lambda item: len(item[0]), reverse=True):
        if compact.startswith(prefix):
            return vendor, prefix
    return None


@lru_cache(maxsize=3)
def _ieee_registry_map(registry: str) -> Dict[str, str]:
    """Scarica e indicizza un registro pubblico IEEE OUI/MA-M/OUI36."""
    filenames = {
        "oui": "oui.csv",
        "mam": "mam.csv",
        "oui36": "oui36.csv",
    }
    filename = filenames[registry]
    raw = _fetch_text(f"https://standards-oui.ieee.org/{registry}/{filename}")
    vendors: Dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(raw)):
        assignment = str(row.get("Assignment") or "").strip().upper().replace("-", "").replace(":", "")
        organization = str(row.get("Organization Name") or "").strip()
        if assignment and organization:
            vendors[assignment] = organization
    return vendors


def _ieee_vendor(mac: str) -> Optional[Tuple[str, str, str]]:
    """Cerca il vendor nei registri IEEE MA-L, MA-M e OUI36."""
    compact = _mac_compact(mac)
    lookups = [
        ("IEEE OUI36", "oui36", compact[:9]),
        ("IEEE MA-M", "mam", compact[:7]),
        ("IEEE MA-L", "oui", compact[:6]),
    ]
    errors: List[str] = []
    for source, registry, assignment in lookups:
        try:
            vendor = _ieee_registry_map(registry).get(assignment)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError, csv.Error) as exc:
            errors.append(f"{source}: {exc}")
            continue
        if vendor:
            return vendor, source, assignment
    if errors:
        raise OSError("; ".join(errors))
    return None


def _macvendors_vendor(mac: str) -> Optional[str]:
    """Consulta MACVendors provando sia MAC completo sia OUI compatto."""
    compact = _mac_compact(mac)
    candidates = [
        mac,
        compact,
        compact[:6],
        "-".join(compact[:6][i:i + 2] for i in range(0, 6, 2)),
    ]
    for candidate in candidates:
        try:
            vendor = _fetch_text(f"https://api.macvendors.com/{urllib.parse.quote(candidate)}")
            if vendor and "not found" not in vendor.lower() and "no vendor" not in vendor.lower():
                return vendor
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            continue
    return None


def _macvendorlookup_vendor(mac: str) -> Optional[str]:
    """Consulta macvendorlookup.com, che risponde con una lista JSON."""
    data = _fetch_json_any(f"https://www.macvendorlookup.com/api/v2/{urllib.parse.quote(mac)}")
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                vendor = _first_string([item.get("company"), item.get("vendorDetails"), item.get("name")])
                if vendor:
                    return vendor
    if isinstance(data, dict):
        return _first_string([data.get("company"), data.get("vendor"), data.get("organization"), data.get("name")])
    return None


def _maclookup_app_vendor(mac: str) -> Optional[str]:
    """Consulta maclookup.app quando disponibile senza API key."""
    data = _fetch_json_any(f"https://api.maclookup.app/v2/macs/{urllib.parse.quote(mac)}")
    if not isinstance(data, dict):
        return None
    if data.get("found") is False or data.get("success") is False:
        return None
    return _first_string([data.get("company"), data.get("vendor"), data.get("organization")])



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


def enrich_mac(mac: str) -> MACExternalInfo:
    """Arricchisce un singolo MAC recuperando il vendor da più fonti OUI."""
    normalized = _normalize_mac(mac)
    if normalized is None:
        return MACExternalInfo(
            mac=mac,
            status="skipped",
            reason="Indirizzo MAC non valido: non inviato a servizi esterni.",
        )

    oui = normalized[:8].upper().replace(":", "-")
    if not _is_lookupable_mac(normalized):
        return MACExternalInfo(
            mac=normalized,
            status="skipped",
            reason="MAC broadcast, multicast, locale o placeholder: lookup vendor non utile.",
            oui=oui,
        )

    info = MACExternalInfo(mac=normalized, status="enriched", oui=oui)

    known = _known_virtual_vendor(normalized)
    if known:
        vendor, prefix = known
        info.vendor = vendor
        info.oui = "-".join(prefix[:6][i:i + 2] for i in range(0, min(len(prefix), 6), 2))
        _append_source(info, "Prefissi virtuali noti")
        return info

    source_attempts = [
        ("IEEE", _ieee_vendor),
        ("MACVendors", lambda value: (
            (vendor, "MACVendors", _mac_oui(value))
            if (vendor := _macvendors_vendor(value))
            else None
        )),
        ("MacVendorLookup", lambda value: (
            (vendor, "MacVendorLookup", _mac_oui(value))
            if (vendor := _macvendorlookup_vendor(value))
            else None
        )),
        ("MacLookup.app", lambda value: (
            (vendor, "MacLookup.app", _mac_oui(value))
            if (vendor := _maclookup_app_vendor(value))
            else None
        )),
    ]

    for source_name, lookup in source_attempts:
        try:
            match = lookup(normalized)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            info.errors.append(f"{source_name}: {exc}")
            continue
        if not match:
            continue

        vendor, source, assignment = match
        info.vendor = vendor[:160]
        if assignment:
            info.oui = "-".join(assignment[:6][i:i + 2] for i in range(0, min(len(assignment), 6), 2))
        _append_source(info, source)
        return info

    info.status = "error"
    if _is_locally_administered_mac(normalized):
        info.reason = "Vendor OUI non trovato; il MAC e localmente amministrato o randomizzato."
    else:
        info.reason = "Vendor OUI non trovato nelle fonti consultate."

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


def enrich_macs(macs: List[str]) -> Dict[str, MACExternalInfo]:
    """Arricchisce una lista di MAC con lookup OUI e concorrenza limitata."""
    unique_macs = []
    seen = set()
    for value in macs:
        if not isinstance(value, str) or not value.strip():
            continue
        normalized = _normalize_mac(value)
        key = normalized or value.strip()
        if key in seen:
            continue
        seen.add(key)
        unique_macs.append(key)

    selected_macs = unique_macs
    if not selected_macs:
        return {}

    results: Dict[str, MACExternalInfo] = {}
    with ThreadPoolExecutor(max_workers=min(EXTERNAL_MAX_WORKERS, len(selected_macs))) as executor:
        future_to_mac = {executor.submit(enrich_mac, mac): mac for mac in selected_macs}
        for future in as_completed(future_to_mac):
            mac = future_to_mac[future]
            try:
                info = future.result()
                results[info.mac] = info
            except Exception as exc:
                results[mac] = MACExternalInfo(
                    mac=mac,
                    status="error",
                    reason=f"Errore imprevisto durante il lookup vendor: {exc}",
                )

    return results

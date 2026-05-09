"""
Threat intelligence DNS opt-in.

This module runs only when the user confirms the popup in the
DNS. Compares domains observed in the PCAP with open lists designed for
blocking DNS e, se configurato, interroga URLhaus per host legati a malware.
"""

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Set, Tuple

from models import DNSDomainIntel, DNSReputationResponse, SecuritySourceStatus


# Timeout prudente: una lista lenta non deve bloccare l'interfaccia.
HTTP_TIMEOUT_SECONDS = 8

# Open lists used as DNS-style sources, downloaded only on request.
ADGUARD_DNS_FILTER_URL = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
STEVENBLACK_HOSTS_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"


def _normalize_domain(domain: str) -> Optional[str]:
    """Normalizza un domainso DNS rimuovendo wildcard, punto finale e maiuscole."""
    value = domain.strip().lower().strip(".")
    value = value.removeprefix("*.").removeprefix("www.")
    if not value or " " in value or "/" in value:
        return None
    if "." not in value:
        return None
    return value


def _candidate_domains(domain: str) -> List[str]:
    """Produce domainso e parent-domain per catturare regole su suffissi."""
    parts = domain.split(".")
    candidates = []
    for index in range(0, max(len(parts) - 1, 0)):
        candidate = ".".join(parts[index:])
        if "." in candidate:
            candidates.append(candidate)
    return candidates


def _fetch_text(url: str) -> str:
    """Scarica testo da una lista remota usando solo libreria standard."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "PCAPCaper/1.0 dns-intelligence",
            "Accept": "text/plain,*/*",
        },
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8", errors="replace")


def _post_form_json(url: str, data: Dict[str, str], headers: Optional[Dict[str, str]] = None) -> Dict:
    """Invia una POST form-urlencoded e decodifica JSON per URLhaus."""
    body = urllib.parse.urlencode(data).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "User-Agent": "PCAPCaper/1.0 dns-intelligence",
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _category_from_rule(rule: str) -> str:
    """Stima una categoria leggibile dal testo della regola o dai modifier."""
    text = rule.lower()
    if any(token in text for token in ("malware", "phishing", "scam", "threat", "trojan")):
        return "malware/phishing"
    if any(token in text for token in ("track", "analytics", "metric", "telemetry", "pixel")):
        return "tracking"
    if any(token in text for token in ("ads", "advert", "doubleclick", "banner")):
        return "ads"
    if "crypto" in text or "miner" in text:
        return "cryptomining"
    return "blocklist"


def _extract_adguard_domains(text: str) -> Dict[str, Tuple[str, str]]:
    """Estrae domains da regole AdGuard compatibili con DNS-level blocking."""
    domains: Dict[str, Tuple[str, str]] = {}
    rule_re = re.compile(r"^\|\|([a-z0-9_.-]+\.[a-z0-9_.-]+)\^", re.IGNORECASE)

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("!", "#", "@@", "/", "[")):
            continue
        match = rule_re.match(line)
        if not match:
            continue
        domain = _normalize_domain(match.group(1))
        if domain:
            domains[domain] = (_category_from_rule(line), line[:180])
    return domains


def _extract_hosts_domains(text: str) -> Set[str]:
    """Estrae domains da un file hosts nel format 0.0.0.0 domainso."""
    domains: Set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[0] not in ("0.0.0.0", "127.0.0.1", "::1"):
            continue
        domain = _normalize_domain(parts[1])
        if domain:
            domains.add(domain)
    return domains


@lru_cache(maxsize=1)
def _load_adguard_filter() -> Dict[str, Tuple[str, str]]:
    """Scarica e indicizza il filtro DNS AdGuard una sola volta per processo."""
    return _extract_adguard_domains(_fetch_text(ADGUARD_DNS_FILTER_URL))


@lru_cache(maxsize=1)
def _load_stevenblack_hosts() -> Set[str]:
    """Scarica e indicizza la hosts list StevenBlack una sola volta per processo."""
    return _extract_hosts_domains(_fetch_text(STEVENBLACK_HOSTS_URL))


def _match_domain(domain: str, indexed: Iterable[str]) -> Optional[str]:
    """Searches a domain or one of its suffixes in the indexed list."""
    for candidate in _candidate_domains(domain):
        if candidate in indexed:
            return candidate
    return None


def _query_urlhaus_domain(domain: str, errors: List[str]) -> Optional[Dict]:
    """Interroga URLhaus per domainso solo se l'Auth-Key e configurata."""
    auth_key = os.getenv("URLHAUS_AUTH_KEY")
    if not auth_key:
        return None
    try:
        data = _post_form_json(
            "https://urlhaus-api.abuse.ch/v1/host/",
            {"host": domain},
            {"Auth-Key": auth_key},
        )
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        errors.append(f"URLhaus {domain}: {exc}")
        return None

    if data.get("query_status") == "ok":
        return data
    return None


def analyze_dns_reputation(domains: List[str], max_domains: int = 250) -> DNSReputationResponse:
    """Confronta domains DNS con liste aperte e ritorna reputazione aggregata."""
    errors: List[str] = []
    sources: List[SecuritySourceStatus] = []
    results: Dict[str, DNSDomainIntel] = {}
    selected = list(dict.fromkeys(
        normalized for domain in domains[:max_domains]
        if (normalized := _normalize_domain(domain))
    ))

    try:
        adguard = _load_adguard_filter()
        sources.append(SecuritySourceStatus(
            source="AdGuard DNS filter",
            status="ok",
            detail=f"{len(adguard)} regole domainso caricate",
        ))
    except Exception as exc:
        adguard = {}
        errors.append(f"AdGuard DNS filter: {exc}")
        sources.append(SecuritySourceStatus(source="AdGuard DNS filter", status="error", detail="Lista not available"))

    try:
        stevenblack = _load_stevenblack_hosts()
        sources.append(SecuritySourceStatus(
            source="StevenBlack hosts",
            status="ok",
            detail=f"{len(stevenblack)} domains hosts caricati",
        ))
    except Exception as exc:
        stevenblack = set()
        errors.append(f"StevenBlack hosts: {exc}")
        sources.append(SecuritySourceStatus(source="StevenBlack hosts", status="error", detail="Lista not available"))

    urlhaus_enabled = bool(os.getenv("URLHAUS_AUTH_KEY"))
    sources.append(SecuritySourceStatus(
        source="URLhaus",
        status="ok" if urlhaus_enabled else "skipped",
        detail="Host API enabled through URLHAUS_AUTH_KEY" if urlhaus_enabled else "Auth-Key not configured: source skipped",
    ))

    for domain in selected:
        categories: Set[str] = set()
        matched_rules: List[str] = []
        matched_sources: List[str] = []
        score = 0

        adguard_match = _match_domain(domain, adguard.keys())
        if adguard_match:
            category, rule = adguard[adguard_match]
            categories.add(category)
            matched_sources.append("AdGuard DNS filter")
            matched_rules.append(f"{adguard_match}: {rule}")
            score = max(score, 55 if category in ("ads", "tracking") else 70)

        stevenblack_match = _match_domain(domain, stevenblack)
        if stevenblack_match:
            categories.add("ads/tracking/malware")
            matched_sources.append("StevenBlack hosts")
            matched_rules.append(f"{stevenblack_match}: hosts blocklist")
            score = max(score, 60)

        urlhaus = _query_urlhaus_domain(domain, errors)
        if urlhaus:
            categories.add("malware")
            matched_sources.append("URLhaus")
            matched_rules.append(f"URLhaus: {urlhaus.get('url_count', 'n/a')} observed URLs")
            score = max(score, 95)

        results[domain] = DNSDomainIntel(
            domain=domain,
            status="listed" if matched_sources else "clean",
            categories=sorted(categories),
            sources=sorted(set(matched_sources)),
            matched_rules=matched_rules[:8],
            score=score,
        )

    return DNSReputationResponse(results=results, sources=sources, errors=errors[:50])

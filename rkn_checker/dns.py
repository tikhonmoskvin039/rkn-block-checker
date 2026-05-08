from __future__ import annotations

import json
import logging
import socket
from typing import Optional

import requests

logger = logging.getLogger(__name__)

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
DOH_TIMEOUT = 5.0


def resolve_system_all(host: str) -> frozenset[str]:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    except socket.gaierror as e:
        logger.debug("system DNS failed for %s: %s", host, e)
        return frozenset()
    return frozenset(info[4][0] for info in infos)


def resolve_doh_all(host: str, timeout: float = DOH_TIMEOUT) -> frozenset[str]:
    """Return every IPv4 address Cloudflare's DoH endpoint returns for `host`.

    Mirror of resolve_system_all but going over HTTPS to a public resolver,
    so callers can spot poisoning by comparing the two sets. Empty set on
    failure
    """
    try:
        r = requests.get(
            DOH_ENDPOINT,
            params={"name": host, "type": "A"},
            headers={"accept": "application/dns-json"},
            timeout=timeout,
        )
        if not r.ok:
            return frozenset()
        ips: set[str] = set()
        for ans in r.json().get("Answer", ()):
            if ans.get("type") == 1:
                data = ans.get("data")
                if data:
                    ips.add(data)
        return frozenset(ips)
    except (requests.RequestException, json.JSONDecodeError) as e:
        logger.debug("DoH failed for %s: %s", host, e)
        return frozenset()


def resolve_system(host: str) -> Optional[str]:
    ips = resolve_system_all(host)
    if not ips:
        return None
    return sorted(ips)[0]


def resolve_doh(host: str, timeout: float = DOH_TIMEOUT) -> Optional[str]:
    ips = resolve_doh_all(host, timeout=timeout)
    if not ips:
        return None
    return sorted(ips)[0]

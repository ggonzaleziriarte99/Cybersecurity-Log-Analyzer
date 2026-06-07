import json
from ipaddress import ip_address
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pandas as pd


def _is_private(ip: str) -> bool:
    try:
        addr = ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True


def _fetch_ipinfo(ip: str, api_key: str, timeout: int) -> Tuple[Optional[str], Optional[str]]:
    url = f"https://ipinfo.io/{ip}/json"
    if api_key:
        url = f"{url}?token={api_key}"
    req = Request(url, headers={"User-Agent": "CybersecurityLogAnalyzer/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("country"), data.get("city")


def _fetch_ipapi(ip: str, timeout: int) -> Tuple[Optional[str], Optional[str]]:
    url = f"https://ipapi.co/{ip}/json/"
    req = Request(url, headers={"User-Agent": "CybersecurityLogAnalyzer/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    country = data.get("country_name") or data.get("country")
    return country, data.get("city")


def enrich_ip_locations(
    ips: List[str],
    provider: str = "ipinfo",
    api_key: str = "",
    timeout: int = 4,
) -> pd.DataFrame:
    cache: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
    records = []

    for ip in sorted(set(ips)):
        if ip in cache:
            country, city = cache[ip]
        elif _is_private(ip):
            country, city = "Private", "Local"
            cache[ip] = (country, city)
        else:
            try:
                if provider == "ipinfo":
                    country, city = _fetch_ipinfo(ip, api_key, timeout)
                elif provider == "ipapi":
                    country, city = _fetch_ipapi(ip, timeout)
                else:
                    raise ValueError(f"Unknown provider: {provider}")
            except (HTTPError, URLError, ValueError, TimeoutError):
                country, city = None, None
            cache[ip] = (country, city)

        records.append({"ip_address": ip, "country": country, "city": city})

    return pd.DataFrame(records, columns=["ip_address", "country", "city"])

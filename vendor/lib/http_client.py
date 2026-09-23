from __future__ import annotations

from typing import Optional
from urllib.parse import quote, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from curl_cffi.requests import Session as CffiSession
except ImportError:
    CffiSession = None


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"


def normalize_proxy_url(proxy: Optional[str]) -> str:
    proxy_text = str(proxy or "").strip()
    if not proxy_text:
        return ""
    if "://" not in proxy_text:
        parts = proxy_text.split(":", 3)
        if len(parts) == 4 and parts[0] and parts[1].isdigit() and parts[2] and parts[3]:
            host, port, username, password = parts
            return f"http://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
    if proxy_text.startswith("socks5://"):
        return "socks5h://" + proxy_text[len("socks5://"):]
    parsed = urlparse(proxy_text)
    if parsed.scheme and parsed.netloc:
        return proxy_text
    return proxy_text


def create_http_session(proxy: Optional[str] = None, impersonate: str = "chrome136"):
    normalized_proxy = normalize_proxy_url(proxy)
    if CffiSession is not None:
        session = CffiSession(impersonate=impersonate)
        session.trust_env = False
        session.proxies = {"http": normalized_proxy, "https": normalized_proxy} if normalized_proxy else {"http": "", "https": ""}
        return session

    session = requests.Session()
    session.trust_env = False
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    if normalized_proxy:
        session.proxies = {"http": normalized_proxy, "https": normalized_proxy}
    session.headers["User-Agent"] = USER_AGENT
    return session

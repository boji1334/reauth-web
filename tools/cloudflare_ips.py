"""Cloudflare 回源 IP 段（用于只允许 CF 访问源站）。

用法: python tools/cloudflare_ips.py          # 打印空格分隔的 IP 段
      python tools/cloudflare_ips.py --json   # 打印 {"ipv4":[...],"ipv6":[...]}
"""

from __future__ import annotations

import json
import sys

import requests

API = "https://api.cloudflare.com/client/v4/ips"

# 官方文档里的固定段；接口拉取失败时用它兜底
FALLBACK_V4 = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)
FALLBACK_V6 = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)


def ranges(*, timeout: int = 15) -> dict:
    try:
        resp = requests.get(API, timeout=timeout)
        data = resp.json()
        result = data.get("result") or {}
        v4 = tuple(item for item in (result.get("ipv4_cidrs") or []) if item)
        v6 = tuple(item for item in (result.get("ipv6_cidrs") or []) if item)
        if v4:
            return {
                "ipv4": v4,
                "ipv6": v6,
                "source": "api",
                "etag": result.get("etag") or "",
            }
    except Exception:  # noqa: BLE001 - 拉不到就用兜底
        pass
    return {"ipv4": FALLBACK_V4, "ipv6": FALLBACK_V6, "source": "fallback"}


def main() -> int:
    data = ranges()
    if "--json" in sys.argv[1:]:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    print(" ".join((*data["ipv4"], *data["ipv6"])))
    print(f"# source={data['source']} v4={len(data['ipv4'])} v6={len(data['ipv6'])}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

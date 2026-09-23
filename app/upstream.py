"""对接上游成品站库存：卡密兑换 = 直接取回当时已生成的 sub2 / cpa 文件。

只调用两个只读接口：
  GET  /api/admin/account-lookup?email=…      查这个邮箱有没有可下载的成品
  POST /api/admin/recovery-export             直接把账号行换成文件（cpa/sub2/sub2-merged/cockpit）
"""

from __future__ import annotations

import json
import re
from urllib.parse import quote

import requests

UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
}

# 本站输出格式 -> 主站导出格式
FORMAT_MAP = {
    "cpa": "cpa",
    "sub2-merged": "sub2-merged",
    "sub2-single": "sub2",
    "cockpit": "cockpit",
}

FILENAME_RE = re.compile(r"filename\*=UTF-8''([^;]+)|filename=\"([^\"]+)\"")


class UpstreamError(RuntimeError):
    """主站接口调用失败。"""


def _decode_filename(disposition: str, fallback: str) -> str:
    match = FILENAME_RE.search(str(disposition or ""))
    if not match:
        return fallback
    raw = match.group(1) or match.group(2) or ""
    if match.group(1):
        from urllib.parse import unquote

        return unquote(raw) or fallback
    return raw or fallback


class UpstreamClient:
    def __init__(
        self,
        base_url: str,
        server_key: str,
        *,
        timeout: int = 90,
    ):
        self.base_url = str(base_url or "").rstrip("/")
        self.server_key = str(server_key or "").strip()
        self.timeout = max(10, int(timeout or 90))
        self.session = requests.Session()
        self.session.headers.update(UA)

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.server_key)

    def _headers(self) -> dict:
        return {"X-CPA-Server-Key": self.server_key}

    # ---------------- 库存查询 ----------------
    def lookup(self, email: str) -> dict:
        if not self.configured:
            raise UpstreamError("主站兑换通道未配置")
        target = str(email or "").strip().lower()
        try:
            resp = self.session.get(
                f"{self.base_url}/api/admin/account-lookup",
                params={"email": target},
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise UpstreamError(f"主站查询失败：{type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise UpstreamError(f"主站查询失败：HTTP {resp.status_code}")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise UpstreamError("主站返回的不是 JSON") from exc
        entries = [
            item
            for item in (payload.get("entries") or [])
            if isinstance(item, dict)
            and str(item.get("email") or "").strip().lower() == target
        ]
        available = [
            item for item in entries if bool(item.get("download_available"))
        ]
        if available:
            newest = max(
                available,
                key=lambda item: float(item.get("completed_at") or 0),
            )
            return {
                "ok": True,
                "available": True,
                "status": str(newest.get("status") or "complete"),
                "status_label": str(newest.get("status_label") or "已完成"),
                "file_expires_at": newest.get("file_expires_at"),
                "job_id": str(newest.get("id") or ""),
            }
        if entries:
            newest = max(
                entries,
                key=lambda item: float(
                    item.get("completed_at") or item.get("created_at") or 0
                ),
            )
            return {
                "ok": True,
                "available": False,
                "status": str(newest.get("status") or ""),
                "status_label": str(newest.get("status_label") or ""),
                "error": str(newest.get("error") or ""),
            }
        return {"ok": True, "available": False, "status": "", "status_label": "未找到"}

    # ---------------- 兑换导出 ----------------
    def export(
        self,
        account_text: str,
        output_format: str,
    ) -> tuple[str, bytes, str]:
        if not self.configured:
            raise UpstreamError("主站兑换通道未配置")
        upstream_format = FORMAT_MAP.get(str(output_format or "").strip().lower())
        if upstream_format is None:
            raise UpstreamError(f"不支持的导出格式：{output_format}")
        body = {
            "account_text": account_text,
            "account_mode": "totp",
            "output_format": upstream_format,
        }
        try:
            resp = self.session.post(
                f"{self.base_url}/api/admin/recovery-export",
                data=json.dumps(body).encode("utf-8"),
                headers={
                    **self._headers(),
                    "Content-Type": "application/json",
                },
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise UpstreamError(f"主站兑换失败：{type(exc).__name__}") from exc
        if resp.status_code != 200:
            detail = ""
            try:
                detail = str(resp.json().get("detail") or "")
            except ValueError:
                detail = resp.text[:120]
            raise UpstreamError(
                f"主站兑换失败：HTTP {resp.status_code} {detail}".strip()
            )
        fallback = f"redeem-{upstream_format}.zip"
        filename = _decode_filename(
            resp.headers.get("Content-Disposition", ""),
            fallback,
        )
        media_type = (
            resp.headers.get("Content-Type") or "application/octet-stream"
        )
        return filename, resp.content, media_type

    def probe(self) -> dict:
        """只做一次轻量探测，确认通道可用。"""
        if not self.configured:
            return {"ok": False, "error": "未配置主站地址或密钥"}
        try:
            resp = self.session.get(
                f"{self.base_url}/api/admin/account-lookup",
                params={"email": "probe@example.com"},
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {"ok": False, "error": f"{type(exc).__name__}"}
        return {
            "ok": resp.status_code == 200,
            "status": resp.status_code,
        }

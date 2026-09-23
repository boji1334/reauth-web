"""把重登拿到的 session 组装成 cpa / sub2api / cockpit 四种交付文件。"""

from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import datetime, timezone

from vendor.lib.session_formats import build_session_format_payloads

OUTPUT_KINDS = ("cpa", "sub2-merged", "sub2-single", "cockpit")

BLOCKED_NAME_RE = re.compile(r'[\x00-\x1f\x7f<>:"/\\|?*]+')
NAME_MAX_LENGTH = 120


def safe_name(value: str, fallback: str = "account") -> str:
    text = BLOCKED_NAME_RE.sub("_", str(value or "")).strip().strip(".")
    if not text:
        text = fallback
    return text[:NAME_MAX_LENGTH]


def dump_json(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def session_to_payloads(session: dict, email: str = "") -> dict:
    """session -> {item, sub2api, cpa, cockpit} 四种格式。"""
    item, payloads = build_session_format_payloads(session, email)
    return {
        "item": item,
        "sub2api": payloads.get("sub2api") or {},
        "cpa": payloads.get("cpa") or {},
        "cockpit": payloads.get("cockpit") or {},
    }


def sub2_merged_document(accounts: list[dict]) -> dict:
    exported_at = (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    return {"exported_at": exported_at, "proxies": [], "accounts": accounts}


def build_zip(members: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    used: set[str] = set()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members:
            candidate = name
            if candidate in used:
                stem, dot, suffix = candidate.rpartition(".")
                if not dot:
                    stem, suffix = candidate, ""
                index = 2
                while f"{stem}-{index}{suffix}" in used:
                    index += 1
                candidate = f"{stem}-{index}{suffix}"
            used.add(candidate)
            archive.writestr(candidate, payload)
    return buffer.getvalue()


def collect_outputs(results: list[dict]) -> dict:
    """results: [{email, plan_type, payloads}] -> 各交付文件的内容。"""
    succeeded = [
        item for item in results if str(item.get("status")) == "ok"
    ]
    cpa_files: list[tuple[str, bytes]] = []
    sub2_files: list[tuple[str, bytes]] = []
    cockpit_files: list[tuple[str, bytes]] = []
    merged_accounts: list[dict] = []
    for item in succeeded:
        email = str(item.get("email") or "")
        payloads = item.get("payloads") or {}
        base = safe_name(email)
        cpa_files.append((f"{base}.json", dump_json(payloads.get("cpa") or {})))
        cockpit_files.append(
            (f"{base}.json", dump_json(payloads.get("cockpit") or {}))
        )
        single = payloads.get("sub2api") or {}
        sub2_files.append((f"{base}.json", dump_json(single)))
        accounts = single.get("accounts") if isinstance(single, dict) else None
        if isinstance(accounts, list):
            merged_accounts.extend(accounts)
    return {
        "cpa": cpa_files,
        "sub2-merged": sub2_merged_document(merged_accounts),
        "sub2-single": sub2_files,
        "cockpit": cockpit_files,
        "count": len(succeeded),
    }


def output_bundle(outputs: dict, kind: str) -> tuple[str, bytes, str]:
    """返回 (文件名, 内容, content-type)。"""
    stamp = datetime.now().strftime("%m%d-%H%M")
    kind = str(kind or "").strip().lower()
    if kind == "sub2-merged":
        count = len((outputs.get("sub2-merged") or {}).get("accounts") or [])
        name = f"{count}-{stamp}-sub2合并.json"
        return name, dump_json(outputs["sub2-merged"]), "application/json"
    if kind not in {"cpa", "sub2-single", "cockpit"}:
        raise KeyError(kind)
    files: list[tuple[str, bytes]] = list(outputs.get(kind) or [])
    if not files:
        raise KeyError(kind)
    if len(files) == 1:
        name, payload = files[0]
        return name, payload, "application/json"
    suffix = {
        "cpa": "cpa",
        "sub2-single": "sub2单独",
        "cockpit": "cockpit",
    }[kind]
    name = f"{len(files)}-{stamp}-{suffix}.zip"
    return name, build_zip(files), "application/zip"

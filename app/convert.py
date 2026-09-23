"""把已生成的 sub2api 文件（单个 / 合并）转成 cpa / cockpit / sub2 三种结构。

这是「卡密兑换」的免登录快速通道：不碰账号密码、不做任何登录，
纯粹按字段映射转格式。
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone


class ConvertError(ValueError):
    """输入不是可识别的 sub2api 文件。"""


def _first(*values) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _jwt_payload(token: str) -> dict:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode((payload + padding).encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 - 解析失败就当没有
        return {}
    return data if isinstance(data, dict) else {}


def _iso_from_epoch(value) -> str:
    try:
        seconds = int(float(value))
    except (TypeError, ValueError):
        return ""
    if seconds <= 0:
        return ""
    return (
        datetime.fromtimestamp(seconds, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def extract_sub2_accounts(text: str) -> list[dict]:
    """接受合并文件{"accounts":[...]}、单个文件、或裸账号对象数组。"""
    raw = str(text or "").strip()
    if not raw:
        raise ConvertError("请粘贴 sub2api 文件内容")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ConvertError("不是合法的 JSON，请粘贴完整的 sub2api 文件") from exc
    if isinstance(data, dict) and isinstance(data.get("accounts"), list):
        accounts = data["accounts"]
    elif isinstance(data, list):
        accounts = data
    elif isinstance(data, dict) and (
        "credentials" in data or data.get("type") == "oauth"
    ):
        accounts = [data]
    else:
        raise ConvertError("没有识别到 accounts 数组，请确认是 sub2api 文件")
    clean = [item for item in accounts if isinstance(item, dict)]
    if not clean:
        raise ConvertError("sub2api 文件里没有可用账号")
    return clean


def convert_sub2_account(account: dict) -> dict:
    """一个 sub2api 账号 -> {cpa, cockpit, sub2api}。"""
    credentials = account.get("credentials")
    credentials = credentials if isinstance(credentials, dict) else {}
    extra = account.get("extra")
    extra = extra if isinstance(extra, dict) else {}
    access_token = _first(credentials.get("access_token"), account.get("access_token"))
    refresh_token = _first(
        credentials.get("refresh_token"),
        account.get("refresh_token"),
    )
    id_token = _first(credentials.get("id_token"), account.get("id_token"))
    if not access_token:
        raise ConvertError("账号缺少 access_token，无法转格式")
    payload = _jwt_payload(access_token)
    auth = payload.get("https://api.openai.com/auth")
    auth = auth if isinstance(auth, dict) else {}
    email = _first(
        credentials.get("email"),
        extra.get("email"),
        account.get("email"),
        account.get("name"),
    )
    account_id = _first(
        credentials.get("chatgpt_account_id"),
        account.get("chatgpt_account_id"),
        account.get("account_id"),
        auth.get("chatgpt_account_id"),
    )
    plan_type = _first(
        credentials.get("plan_type"),
        account.get("plan_type"),
        auth.get("chatgpt_plan_type"),
    )
    expired = _first(
        credentials.get("expires_at"),
        account.get("expires_at"),
        _iso_from_epoch(payload.get("exp")),
    )
    last_refresh = _first(
        extra.get("last_refresh"),
        account.get("last_refresh"),
        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    name = _first(account.get("name"), email, "ChatGPT Account")

    cpa = {
        "type": "codex",
        "account_id": account_id,
        "chatgpt_account_id": account_id,
        "email": email,
        "name": name,
        "plan_type": plan_type,
        "chatgpt_plan_type": plan_type,
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "last_refresh": last_refresh,
        "expired": expired,
    }
    cockpit = {
        "type": "codex",
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": last_refresh,
        "email": email,
        "expired": expired,
    }
    sub2api = {
        "name": name,
        "platform": "openai",
        "type": "oauth",
        "concurrency": int(account.get("concurrency") or 10),
        "priority": int(account.get("priority") or 1),
        "credentials": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": id_token,
            "chatgpt_account_id": account_id,
            "chatgpt_user_id": _first(
                credentials.get("chatgpt_user_id"),
                auth.get("chatgpt_user_id"),
            ),
            "email": email,
            "expires_at": expired,
            "expires_in": int(credentials.get("expires_in") or 0),
            "plan_type": plan_type,
        },
        "extra": {
            "email": email,
            "name": name,
            "source": "sub2api_convert",
            "last_refresh": last_refresh,
        },
    }
    return {
        "email": email,
        "plan_type": (plan_type or "unknown").lower(),
        "cpa": {key: value for key, value in cpa.items() if value not in ("", None)},
        "cockpit": {
            key: value for key, value in cockpit.items() if value not in ("", None)
        },
        "sub2api": {key: value for key, value in sub2api.items() if value not in ("", None)},
    }


def convert_sub2_text(text: str) -> list[dict]:
    return [convert_sub2_account(item) for item in extract_sub2_accounts(text)]

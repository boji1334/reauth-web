from __future__ import annotations

import base64
import json
import re
import time
from datetime import datetime, timezone
from typing import Any


def first_text(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            text = value.strip()
        else:
            text = str(value).strip()
        if text:
            return text
    return ""


def b64url_decode_json(value: str) -> dict[str, Any]:
    text = str(value or "")
    parts = text.split(".")
    if len(parts) < 2:
        raise ValueError("accessToken is not a JWT")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    data = base64.urlsafe_b64decode(payload.encode("ascii"))
    decoded = json.loads(data.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("JWT payload is not an object")
    return decoded


def b64url_json(data: dict[str, Any]) -> str:
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def iso_from_epoch(value: Any) -> str:
    try:
        epoch = int(value)
    except (TypeError, ValueError):
        return ""
    if epoch <= 0:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def epoch_seconds(value: str) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


def strip_empty(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            cleaned = strip_empty(item)
            if cleaned in (None, "", [], {}):
                continue
            out[key] = cleaned
        return out
    if isinstance(value, list):
        return [item for item in (strip_empty(x) for x in value) if item not in (None, "", [], {})]
    return value


def email_key(email: str) -> str:
    text = str(email or "").strip().lower()
    return re.sub(r"[^a-z0-9._+-]+", "_", text).strip("_")


def synthetic_id_token(email: str, account_id: str, plan_type: str, user_id: str, expires_at: str) -> str:
    if not (email or account_id or user_id):
        return ""
    now = int(time.time())
    exp = epoch_seconds(expires_at) or now + 3600
    header = {"alg": "none", "typ": "JWT"}
    payload = strip_empty({
        "email": email,
        "sub": user_id or account_id,
        "chatgpt_account_id": account_id,
        "chatgpt_user_id": user_id,
        "chatgpt_plan_type": plan_type,
        "iat": now,
        "exp": exp,
        "synthetic": True,
    })
    return f"{b64url_json(header)}.{b64url_json(payload)}."


def normalize_session_for_formats(session: dict[str, Any], email_value: str = "") -> dict[str, Any]:
    if not isinstance(session, dict):
        raise ValueError("session must be object")
    access_token = first_text(session.get("accessToken"), session.get("access_token"))
    if not access_token:
        raise ValueError("缺少 accessToken")

    payload = b64url_decode_json(access_token)
    auth_raw = payload.get("https://api.openai.com/auth")
    profile_raw = payload.get("https://api.openai.com/profile")
    auth = auth_raw if isinstance(auth_raw, dict) else {}
    profile = profile_raw if isinstance(profile_raw, dict) else {}
    user_raw = session.get("user")
    user = user_raw if isinstance(user_raw, dict) else {}

    expires_at = iso_from_epoch(payload.get("exp"))
    exported_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    email_resolved = first_text(user.get("email"), session.get("email"), profile.get("email"), payload.get("email"), email_value)
    account_id = first_text(auth.get("chatgpt_account_id"), session.get("account_id"), session.get("chatgptAccountId"))
    user_id = first_text(auth.get("chatgpt_user_id"), auth.get("user_id"), session.get("user_id"), session.get("chatgptUserId"))
    plan_type = first_text(auth.get("chatgpt_plan_type"), session.get("plan_type"), session.get("planType"))
    id_token = first_text(session.get("idToken"), session.get("id_token"))
    synthetic = False
    if not id_token:
        id_token = synthetic_id_token(email_resolved, account_id, plan_type, user_id, expires_at)
        synthetic = bool(id_token)

    exp_epoch = epoch_seconds(expires_at)
    return {
        "access_token": access_token,
        "session_token": first_text(session.get("sessionToken"), session.get("session_token")),
        "refresh_token": first_text(session.get("refreshToken"), session.get("refresh_token")),
        "id_token": id_token,
        "synthetic_id_token": synthetic,
        "email": email_resolved,
        "account_id": account_id,
        "user_id": user_id,
        "plan_type": plan_type,
        "expires_at": expires_at,
        "expires_in": max(0, exp_epoch - int(time.time())) if exp_epoch else 0,
        "exported_at": exported_at,
        "name": email_resolved or "ChatGPT Account",
    }


def build_session_format_payloads(session: dict[str, Any], email_value: str = "") -> tuple[dict[str, Any], dict[str, Any]]:
    item = normalize_session_for_formats(session, email_value)
    sub2api_account = strip_empty({
        "name": item["name"],
        "platform": "openai",
        "type": "oauth",
        "concurrency": 10,
        "priority": 1,
        "credentials": {
            "access_token": item["access_token"],
            "refresh_token": item["refresh_token"],
            "id_token": item["id_token"],
            "chatgpt_account_id": item["account_id"],
            "chatgpt_user_id": item["user_id"],
            "email": item["email"],
            "expires_at": item["expires_at"],
            "expires_in": item["expires_in"],
            "plan_type": item["plan_type"],
        },
        "extra": {
            "email": item["email"],
            "email_key": email_key(item["email"]),
            "name": item["name"],
            "source": "chatgpt_web_session",
            "last_refresh": item["exported_at"],
        },
    })
    cpa = strip_empty({
        "type": "codex",
        "account_id": item["account_id"],
        "chatgpt_account_id": item["account_id"],
        "email": item["email"],
        "name": item["name"],
        "plan_type": item["plan_type"],
        "chatgpt_plan_type": item["plan_type"],
        "id_token": item["id_token"],
        "id_token_synthetic": item["synthetic_id_token"] or None,
        "access_token": item["access_token"],
        "refresh_token": item["refresh_token"],
        "session_token": item["session_token"],
        "last_refresh": item["exported_at"],
        "expired": item["expires_at"],
    })
    cockpit = strip_empty({
        "type": "codex",
        "id_token": item["id_token"],
        "access_token": item["access_token"],
        "refresh_token": item["refresh_token"],
        "account_id": item["account_id"],
        "last_refresh": item["exported_at"],
        "email": item["email"],
        "expired": item["expires_at"],
    })
    router9 = strip_empty({
        "accessToken": item["access_token"],
        "refreshToken": item["refresh_token"],
        "expiresAt": item["expires_at"],
        "testStatus": "active",
        "expiresIn": item["expires_in"],
        "providerSpecificData": {
            "chatgptAccountId": item["account_id"],
            "chatgptPlanType": item["plan_type"],
        },
        "id": item["account_id"],
        "provider": "codex",
        "authType": "oauth",
        "name": item["name"],
        "email": item["email"],
        "priority": 9,
        "isActive": True,
        "createdAt": item["exported_at"],
        "updatedAt": item["exported_at"],
    })
    axonhub = {
        "auth_mode": "chatgpt",
        "last_refresh": item["exported_at"],
        "tokens": {
            "access_token": item["access_token"],
            "refresh_token": item["refresh_token"] or "__missing_refresh_token__",
            "id_token": item["id_token"],
        },
    }
    if not item["refresh_token"]:
        axonhub["axonhub_refresh_token_placeholder"] = True
        axonhub["axonhub_note"] = "refresh_token is a placeholder; access_token works only until it expires."

    return item, {
        "sub2api": {"exported_at": item["exported_at"], "proxies": [], "accounts": [sub2api_account]},
        "cpa": cpa,
        "cockpit": cockpit,
        "9router": router9,
        "axonhub": axonhub,
    }

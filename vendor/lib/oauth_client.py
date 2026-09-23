"""
OAuth 客户端模块 - 处理 Codex OAuth 登录流程
"""

import time
import secrets
import json
import base64
import gzip
import html
import zlib
import re
from urllib.parse import (
    parse_qs,
    parse_qsl,
    unquote,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

from .http_client import create_http_session, normalize_proxy_url
from .utils import generate_pkce, generate_datadog_trace
from .sentinel_token import build_sentinel_token

OAUTH_ISSUER = "https://auth.openai.com"
OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OAUTH_REDIRECT_URI = "http://localhost:1455/auth/callback"


class OAuthClient:
    """OAuth 客户端 - 用于获取 Access Token 和 Refresh Token"""
    
    def __init__(self, config, proxy=None, verbose=True):
        """
        初始化 OAuth 客户端
        
        Args:
            config: 配置字典
            proxy: 代理地址
            verbose: 是否输出详细日志
        """
        self.config = config or {}
        self.oauth_issuer = OAUTH_ISSUER
        self.oauth_client_id = OAUTH_CLIENT_ID
        self.oauth_redirect_uri = OAUTH_REDIRECT_URI
        self.proxy = normalize_proxy_url(proxy)
        self.verbose = verbose
        self.oauth_impersonates = self._split_config_csv(
            self.config.get(
                "sub2api_oauth_impersonates",
                "chrome124,chrome133a,chrome136,chrome120",
            )
        )

        # 创建 session
        self.session = create_http_session(proxy=self.proxy, impersonate=self.oauth_impersonates[0] if self.oauth_impersonates else "chrome136")

        # 手机验证策略：auto(有短信能力则填手机，否则刷新授权链接重新授权) / sms(强制填) / reauthorize(强制重授权)
        self.phone_strategy = str(self.config.get("oauth_phone_strategy", "auto")).strip().lower()
        # 最近一次 OAuth 失败原因（供 main.py 决定是否刷新授权重试），"phone_required" 表示遇到手机验证
        self.last_oauth_error = ""
        self.last_oauth_status = 0
        self.last_oauth_endpoint = ""
        self.last_oauth_page_type = ""
        self.email_otp_max_attempts = max(1, int(self.config.get("oauth_email_otp_max_attempts", 3) or 3))
        self.email_otp_timeout = max(30, int(self.config.get("oauth_email_otp_timeout", 150) or 150))
    
    def _log(self, msg):
        """输出日志"""
        if self.verbose:
            print(f"  [OAuth] {self._redact_text(msg)}")

    def _should_reauthorize_for_phone(self, phone_provider):
        """遇到手机验证时是否改走「刷新授权链接重新授权」（而非填手机）。

        auto: 有短信能力(provider 带 buy_number)则填手机，否则重授权；
        reauthorize: 总是重授权；sms: 总是填手机。
        """
        phone_capable = callable(getattr(phone_provider, "buy_number", None))
        return self.phone_strategy == "reauthorize" or (self.phone_strategy == "auto" and not phone_capable)

    @staticmethod
    def _split_config_csv(value):
        if isinstance(value, (list, tuple)):
            items = value
        else:
            items = str(value or "").split(",")
        return [str(x).strip() for x in items if str(x).strip()]

    @staticmethod
    def _config_truthy(value):
        return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}

    @staticmethod
    def _redact_url(url):
        raw = str(url or "")
        if not raw:
            return ""
        try:
            parsed = urlparse(raw)
            sensitive = {"code", "state", "access_token", "refresh_token", "id_token", "code_verifier", "login_verifier"}
            params = []
            for key, value in parse_qsl(parsed.query, keep_blank_values=True):
                params.append((key, "***" if key.lower() in sensitive else value))
            return urlunparse(parsed._replace(query=urlencode(params)))
        except Exception:
            return re.sub(r"(?i)(code|state|access_token|refresh_token|id_token|code_verifier|login_verifier)=([^&\s]+)", r"\1=***", raw)

    @staticmethod
    def _redact_text(text):
        raw = str(text or "")
        if not raw:
            return ""
        raw = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1***", raw)
        raw = re.sub(r"(?i)(cookie\s*[:=]\s*)[^\r\n]+", r"\1***", raw)
        raw = re.sub(r"(?i)((?:code|state|access_token|refresh_token|id_token|code_verifier|login_verifier|token)\s*['\"]?\s*[:=]\s*['\"]?)[^'\",}\s&]+", r"\1***", raw)
        raw = re.sub(r"(?<!\d)\d{6}(?!\d)", "***", raw)
        return raw

    @staticmethod
    def _clean_error_value(value):
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            try:
                text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            except Exception:
                text = str(value)
        else:
            text = str(value)
        text = " ".join(text.split()).strip()
        if text.lower() in {"", "none", "null", "undefined"}:
            return ""
        return text[:500]

    @classmethod
    def _response_error_details(cls, response):
        """Extract a compact, redacted error summary from an OAuth response."""
        try:
            status = int(getattr(response, "status_code", 0) or 0)
        except (TypeError, ValueError):
            status = 0

        try:
            data = response.json()
        except Exception:
            data = {}

        code = ""
        error_type = ""
        message = ""
        if isinstance(data, dict):
            containers = []
            error_value = data.get("error")
            detail_value = data.get("detail")
            if isinstance(error_value, dict):
                containers.append(error_value)
            elif error_value is not None:
                error_text = cls._clean_error_value(error_value)
                if re.fullmatch(r"[A-Za-z0-9_.-]+", error_text or ""):
                    code = error_text
                else:
                    message = error_text
            if isinstance(detail_value, dict):
                containers.append(detail_value)
            elif detail_value is not None and not message:
                message = cls._clean_error_value(detail_value)
            containers.append(data)

            for container in containers:
                if not code:
                    code = cls._clean_error_value(
                        container.get("code") or container.get("error_code")
                    )
                if not error_type:
                    error_type = cls._clean_error_value(container.get("type"))
                if not message:
                    message = cls._clean_error_value(
                        container.get("message")
                        or container.get("error_description")
                        or container.get("description")
                        or container.get("reason")
                    )

        if not message:
            message = cls._clean_error_value(getattr(response, "text", "") or "")

        return {
            "status": status,
            "code": cls._clean_error_value(code),
            "type": cls._clean_error_value(error_type),
            "message": cls._redact_text(message),
        }

    def _remember_oauth_http_failure(self, response, request_url=""):
        """Remember the real failing JSON API response.

        OAuth page navigation commonly contains valid 302 redirects before a
        later API call rejects a credential. Keeping the API failure prevents
        the final error from incorrectly blaming the earlier redirect.
        """
        details = self._response_error_details(response)
        status = int(details.get("status") or 0)
        error = str(
            details.get("code")
            or details.get("type")
            or (f"oauth_http_{status}" if status else "oauth_request_failed")
        ).strip()
        raw_url = str(
            getattr(response, "url", "")
            or request_url
            or ""
        ).strip()
        try:
            endpoint = urlparse(raw_url).path or "/"
        except Exception:
            endpoint = ""
        endpoint_low = endpoint.lower()
        if "password/verify" in endpoint_low:
            page_type = "login_password"
        elif "mfa" in endpoint_low:
            page_type = "mfa-challenge"
        elif "email" in endpoint_low or "otp" in endpoint_low:
            page_type = "email-verification"
        elif "phone" in endpoint_low:
            page_type = "add-phone"
        elif "authorize/continue" in endpoint_low:
            page_type = "log-in"
        else:
            page_type = ""

        self.last_oauth_error = error
        self.last_oauth_status = status
        self.last_oauth_endpoint = endpoint
        self.last_oauth_page_type = page_type
        return details

    @classmethod
    def _record_sms_phone_error(cls, sms_client, response, stage):
        details = cls._response_error_details(response)
        try:
            setter = getattr(sms_client, "set_last_phone_error", None)
            if callable(setter):
                setter(
                    stage=stage,
                    status=details["status"],
                    code=details["code"],
                    error_type=details["type"],
                    message=details["message"],
                )
            else:
                sms_client.last_phone_error_stage = stage
                sms_client.last_phone_error_status = details["status"]
                sms_client.last_phone_error_code = details["code"]
                sms_client.last_phone_error_type = details["type"]
                sms_client.last_phone_error_message = details["message"]
        except Exception:
            pass
        return details

    @staticmethod
    def _handle_explicit_phone_rejection(sms_client, order_id, reason):
        """Rotate a rejected number or request a fresh OAuth session.

        The CPA runner supplies ``handle_explicit_phone_rejection`` for the
        手机号供应商/local pool clients.  Older providers still use the legacy
        mark/cancel behavior and therefore retain their existing path.
        """
        handler = getattr(
            sms_client,
            "handle_explicit_phone_rejection",
            None,
        )
        if callable(handler):
            try:
                return str(
                    handler(order_id, reason=reason) or "defer"
                )
            except TypeError:
                return str(handler(order_id) or "defer")
        if hasattr(sms_client, "mark_order_abnormal"):
            sms_client.mark_order_abnormal(order_id)
        elif hasattr(sms_client, "cancel_order"):
            sms_client.cancel_order(order_id)
        return (
            "changed"
            if bool(getattr(sms_client, "change_number_requested", False))
            else "retry"
        )

    def _normalize_oauth_url(self, url):
        """将相对 OAuth URL 归一化为绝对地址"""
        if not url:
            return ""
        if url.startswith("/"):
            return f"{self.oauth_issuer}{url}"
        return url

    def _visit_oauth_page(self, url, referer=None, user_agent=None, impersonate=None):
        """访问 OAuth 流程页以推进服务端状态机"""
        target_url = self._normalize_oauth_url(url)
        if not target_url:
            return ""

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        if referer:
            headers["Referer"] = referer

        try:
            kwargs = {"headers": headers, "allow_redirects": True, "timeout": 30}
            if impersonate:
                kwargs["impersonate"] = impersonate

            r = self.session.get(target_url, **kwargs)
            final_url = str(r.url)
            self._log(f"预访问流程页 -> {r.status_code} {final_url[:100]}")
            return final_url
        except Exception as e:
            self._log(f"预访问流程页异常: {e}")
            return target_url
    
    def login_and_get_tokens(self, email, password, device_id, user_agent=None, sec_ch_ua=None, impersonate=None, mail_client=None, sms_client=None):
        """
        完整的 OAuth 登录流程，获取 tokens
        
        Args:
            email: 邮箱
            password: 密码
            device_id: 设备 ID
            user_agent: User-Agent
            sec_ch_ua: sec-ch-ua header
            impersonate: curl_cffi impersonate 参数
            mail_client: 邮件客户端（用于提供 OTP，如果需要）
            
        Returns:
            dict: tokens 字典，包含 access_token, refresh_token, id_token
        """
        self._log("开始 OAuth 登录流程...")
        
        # 1. 生成 PKCE 参数
        code_verifier, code_challenge = generate_pkce()
        state = secrets.token_urlsafe(32)
        
        # 2. Bootstrap OAuth session - 确保获取 login_session cookie
        self._log("步骤1: Bootstrap OAuth session...")
        authorize_params = {
            "response_type": "code",
            "client_id": self.oauth_client_id,
            "redirect_uri": self.oauth_redirect_uri,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        
        authorize_url = f"{self.oauth_issuer}/oauth/authorize"
        
        # 确保 oai-did cookie 在两个域上都设置
        self.session.cookies.set("oai-did", device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", device_id, domain="auth.openai.com")
        
        # 第一次尝试：GET /oauth/authorize
        has_login_session = False
        authorize_final_url = ""
        
        try:
            headers = {
                "User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
                "Referer": "https://chatgpt.com/",
            }
            
            kwargs = {"params": authorize_params, "headers": headers, "allow_redirects": True, "timeout": 30}
            if impersonate:
                kwargs["impersonate"] = impersonate
            
            r = self.session.get(authorize_url, **kwargs)
            authorize_final_url = str(r.url)
            redirects = len(getattr(r, "history", []) or [])
            
            self._log(f"/oauth/authorize -> {r.status_code}, redirects={redirects}")
            
            # 检查是否获取到 login_session cookie
            has_login_session = any(
                (cookie.name if hasattr(cookie, 'name') else str(cookie)) == "login_session"
                for cookie in self.session.cookies
            )
            
            self._log(f"login_session: {'已获取' if has_login_session else '未获取'}")
            
        except Exception as e:
            self._log(f"/oauth/authorize 异常: {e}")

        # 优先尝试：如果注册阶段留下了已登录 session，直接从 authorize/bootstrap 里提取 code
        direct_code = None
        if authorize_final_url:
            direct_code = self._extract_code_from_url(authorize_final_url)
            if not direct_code:
                direct_code, _ = self._oauth_follow_for_code(
                    authorize_final_url,
                    referer="https://chatgpt.com/",
                    user_agent=user_agent,
                    impersonate=impersonate,
                    max_hops=10,
                )
            if direct_code:
                self._log("检测到已登录 session，直接获取到 authorization code")
                tokens = self._exchange_code_for_tokens(direct_code, code_verifier, user_agent, impersonate)
                if tokens:
                    self._log("✅ OAuth 登录成功（复用已注册 session）")
                    return tokens
                self._log("直接 code 换 token 失败，回退常规 OAuth 流程")
        
        # 如果没有获取到 login_session，尝试 oauth2/auth 入口
        if not has_login_session:
            self._log("未获取到 login_session，尝试 /api/oauth/oauth2/auth...")
            try:
                oauth2_url = f"{self.oauth_issuer}/api/oauth/oauth2/auth"
                kwargs = {"params": authorize_params, "headers": headers, "allow_redirects": True, "timeout": 30}
                if impersonate:
                    kwargs["impersonate"] = impersonate
                
                r2 = self.session.get(oauth2_url, **kwargs)
                authorize_final_url = str(r2.url)
                redirects2 = len(getattr(r2, "history", []) or [])
                
                self._log(f"/api/oauth/oauth2/auth -> {r2.status_code}, redirects={redirects2}")
                
                has_login_session = any(
                    (cookie.name if hasattr(cookie, 'name') else str(cookie)) == "login_session"
                    for cookie in self.session.cookies
                )
                
                self._log(f"login_session(重试): {'已获取' if has_login_session else '未获取'}")
                
            except Exception as e:
                self._log(f"/api/oauth/oauth2/auth 异常: {e}")
        
        if not authorize_final_url:
            self._log("Bootstrap 失败")
            return None

        # 如果已有 auth 会话 cookie，优先直接走 consent/workspace 路径，绕过 log-in/password
        try:
            auth_session_cookie = (
                self.session.cookies.get("oai-client-auth-session", domain=".auth.openai.com")
                or self.session.cookies.get("oai-client-auth-session", domain="auth.openai.com")
            )
        except Exception:
            auth_session_cookie = None

        if auth_session_cookie:
            self._log("检测到 oai-client-auth-session，优先直走 consent/workspace")
            direct_consent_url = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
            direct_code = self._oauth_submit_workspace_and_org(
                direct_consent_url, device_id, user_agent, impersonate
            )
            if not direct_code:
                direct_code, _ = self._oauth_follow_for_code(
                    direct_consent_url,
                    referer="https://chatgpt.com/",
                    user_agent=user_agent,
                    impersonate=impersonate,
                    max_hops=12,
                )
            if direct_code:
                self._log("consent/workspace 直取到 authorization code")
                tokens = self._exchange_code_for_tokens(direct_code, code_verifier, user_agent, impersonate)
                if tokens:
                    self._log("✅ OAuth 登录成功（直走 consent/workspace）")
                    return tokens
                self._log("consent/workspace 直换 token 失败，继续回退常规流程")
        
        # 确定 continue_referer
        continue_referer = authorize_final_url if authorize_final_url.startswith(self.oauth_issuer) else f"{self.oauth_issuer}/log-in"
        
        # 3. 提交邮箱
        self._log("步骤2: POST /api/accounts/authorize/continue")
        sentinel_token = build_sentinel_token(
            self.session, device_id, flow="authorize_continue",
            user_agent=user_agent, sec_ch_ua=sec_ch_ua, impersonate=impersonate
        )
        
        if not sentinel_token:
            self._log("无法获取 sentinel token (authorize_continue)")
            return None
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": continue_referer,
            "Origin": self.oauth_issuer,
            "oai-device-id": device_id,
            "openai-sentinel-token": sentinel_token,
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        headers.update(generate_datadog_trace())
        
        payload = {
            "username": {"kind": "email", "value": email},
        }
        
        try:
            kwargs = {"json": payload, "headers": headers, "timeout": 30, "allow_redirects": False}
            if impersonate:
                kwargs["impersonate"] = impersonate
            
            r = self.session.post(
                f"{self.oauth_issuer}/api/accounts/authorize/continue",
                **kwargs
            )
            
            self._log(f"/authorize/continue -> {r.status_code}")
            
            # 如果是 400 且包含 invalid_auth_step，重新 bootstrap
            if r.status_code == 400 and "invalid_auth_step" in (r.text or ""):
                self._log("invalid_auth_step，重新 bootstrap...")
                # 重新执行 bootstrap
                try:
                    kwargs_retry = {"params": authorize_params, "headers": {"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Referer": "https://chatgpt.com/"}, "allow_redirects": True, "timeout": 30}
                    if impersonate:
                        kwargs_retry["impersonate"] = impersonate
                    r_retry = self.session.get(authorize_url, **kwargs_retry)
                    authorize_final_url = str(r_retry.url)
                    continue_referer = authorize_final_url if authorize_final_url.startswith(self.oauth_issuer) else f"{self.oauth_issuer}/log-in"
                    
                    # 重新提交
                    headers["Referer"] = continue_referer
                    headers.update(generate_datadog_trace())
                    kwargs = {"json": payload, "headers": headers, "timeout": 30, "allow_redirects": False}
                    if impersonate:
                        kwargs["impersonate"] = impersonate
                    r = self.session.post(f"{self.oauth_issuer}/api/accounts/authorize/continue", **kwargs)
                    self._log(f"/authorize/continue(重试) -> {r.status_code}")
                except Exception as e:
                    self._log(f"重试异常: {e}")
            
            if r.status_code != 200:
                self._log(f"提交邮箱失败: {r.text[:180]}")
                return None
            
            data = r.json()
            continue_url = data.get("continue_url", "")
            page_type = data.get("page", {}).get("type", "")
            self._log(f"continue page={page_type or '-'} next={self._redact_url(continue_url)[:80] if continue_url else '-'}...")

            # 某些新注册会话在提交邮箱后直接进入邮箱 OTP / consent / callback，
            # 此时如果继续强行 POST /password/verify，容易触发 401/409 invalid_state。
            direct_code = self._extract_code_from_url(continue_url)
            if direct_code:
                self._log("authorize/continue 已直接返回 callback code，跳过后续验证")
                tokens = self._exchange_code_for_tokens(direct_code, code_verifier, user_agent, impersonate)
                if tokens:
                    self._log("✅ OAuth 登录成功（authorize/continue 直达 callback）")
                    return tokens

            need_oauth_otp = (
                page_type == "email_otp_verification"
                or "email-verification" in (continue_url or "")
                or "email-otp" in (continue_url or "")
            )
            if need_oauth_otp and mail_client:
                self._log("authorize/continue 已进入邮箱 OTP 验证，跳过 password/verify")
                return self._handle_otp_verification(
                    email, device_id, user_agent, sec_ch_ua,
                    impersonate, mail_client, code_verifier, continue_url, page_type
                )

            if (
                ("consent" in (continue_url or ""))
                or ("sign-in-with-chatgpt" in (continue_url or ""))
                or ("workspace" in (continue_url or ""))
                or ("organization" in (continue_url or ""))
                or ("consent" in (page_type or ""))
                or ("organization" in (page_type or ""))
            ):
                self._log("authorize/continue 已进入 consent/workspace，跳过 password/verify")
                code = None
                consent_url = continue_url
                if consent_url and consent_url.startswith("/"):
                    consent_url = f"{self.oauth_issuer}{consent_url}"
                if not consent_url:
                    consent_url = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
                code = self._oauth_submit_workspace_and_org(consent_url, device_id, user_agent, impersonate)
                if not code:
                    code, _ = self._oauth_follow_for_code(
                        consent_url,
                        referer=continue_referer,
                        user_agent=user_agent,
                        impersonate=impersonate,
                        max_hops=12,
                    )
                if code:
                    self._log("consent/workspace 获取到 authorization code")
                    tokens = self._exchange_code_for_tokens(code, code_verifier, user_agent, impersonate)
                    if tokens:
                        self._log("✅ OAuth 登录成功（authorize/continue 直达 consent）")
                        return tokens

            password_page_url = self._normalize_oauth_url(continue_url)
            if password_page_url:
                visited_password_url = self._visit_oauth_page(
                    password_page_url,
                    referer=continue_referer,
                    user_agent=user_agent,
                    impersonate=impersonate,
                )
                if visited_password_url:
                    password_page_url = visited_password_url
            else:
                password_page_url = f"{self.oauth_issuer}/log-in/password"
            
        except Exception as e:
            self._log(f"提交邮箱异常: {e}")
            return None
        
        # 4. 提交密码
        self._log("步骤3: POST /api/accounts/password/verify")
        sentinel_pwd = build_sentinel_token(
            self.session, device_id, flow="password_verify",
            user_agent=user_agent, sec_ch_ua=sec_ch_ua, impersonate=impersonate
        )
        
        if not sentinel_pwd:
            self._log("无法获取 sentinel token (password_verify)")
            return None
        
        headers_verify = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": password_page_url,
            "Origin": self.oauth_issuer,
            "oai-device-id": device_id,
            "openai-sentinel-token": sentinel_pwd,
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        headers_verify.update(generate_datadog_trace())
        
        # 真实接口当前只接受顶层 password 字段；
        # username / origin_page_type / intent 放进去会分别触发
        # unknown_parameter 或 missing_required_parameter。
        payload_pwd = {"password": password}
        
        try:
            kwargs = {"json": payload_pwd, "headers": headers_verify, "timeout": 30, "allow_redirects": False}
            if impersonate:
                kwargs["impersonate"] = impersonate
            
            r = self.session.post(
                f"{self.oauth_issuer}/api/accounts/password/verify",
                **kwargs
            )
            
            self._log(f"/password/verify -> {r.status_code}")

            if r.status_code == 409 and "invalid_state" in (r.text or ""):
                self._log("password/verify 命中 invalid_state，重新访问密码页后重试一次")
                refreshed_password_url = self._visit_oauth_page(
                    password_page_url,
                    referer=continue_referer,
                    user_agent=user_agent,
                    impersonate=impersonate,
                )
                if refreshed_password_url:
                    password_page_url = refreshed_password_url
                    headers_verify["Referer"] = password_page_url
                    headers_verify.update(generate_datadog_trace())

                kwargs = {"json": payload_pwd, "headers": headers_verify, "timeout": 30, "allow_redirects": False}
                if impersonate:
                    kwargs["impersonate"] = impersonate

                r = self.session.post(
                    f"{self.oauth_issuer}/api/accounts/password/verify",
                    **kwargs
                )

                self._log(f"/password/verify(重试) -> {r.status_code}")

            if r.status_code in (401, 409):
                if r.status_code == 401 and mail_client is not None:
                    self._log("password/verify -> 401，尝试 passwordless/send-otp")
                    headers_pwdless = {
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Referer": password_page_url,
                        "Origin": self.oauth_issuer,
                        "oai-device-id": device_id,
                        "User-Agent": user_agent or "Mozilla/5.0",
                    }
                    headers_pwdless.update(generate_datadog_trace())
                    baseline_message_ids = set()
                    if hasattr(mail_client, "snapshot_openai_message_ids"):
                        try:
                            baseline_message_ids = mail_client.snapshot_openai_message_ids(email)
                        except Exception:
                            baseline_message_ids = set()
                    try:
                        kwargs_pwdless = {
                            "headers": headers_pwdless,
                            "timeout": 30,
                            "allow_redirects": False,
                            "json": {},
                        }
                        if impersonate:
                            kwargs_pwdless["impersonate"] = impersonate
                        r_pwdless = self.session.post(
                            f"{self.oauth_issuer}/api/accounts/passwordless/send-otp",
                            **kwargs_pwdless,
                        )
                        self._log(f"/passwordless/send-otp -> {r_pwdless.status_code}")
                        if r_pwdless.status_code == 200:
                            try:
                                pwdless_data = r_pwdless.json()
                            except Exception:
                                pwdless_data = {}
                            pwdless_continue_url = pwdless_data.get("continue_url", "")
                            pwdless_page_type = (pwdless_data.get("page") or {}).get("type", "")
                            self._log(
                                f"passwordless page={pwdless_page_type or '-'} next={pwdless_continue_url[:80] if pwdless_continue_url else '-'}..."
                            )
                            if pwdless_page_type in ("email_otp_verification", "contact_verification"):
                                tokens = self._handle_otp_verification(
                                    email, device_id, user_agent, sec_ch_ua, impersonate,
                                    mail_client, code_verifier, pwdless_continue_url, pwdless_page_type,
                                    baseline_message_ids=baseline_message_ids,
                                )
                                if tokens:
                                    self._log("✅ OAuth 登录成功（passwordless OTP）")
                                    return tokens
                    except Exception as e:
                        self._log(f"passwordless/send-otp 异常: {e}")

                self._log("password/verify 失败，尝试从现有 session 恢复 consent/workspace 流程")
                recovery_consent = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
                recovery_code = self._oauth_submit_workspace_and_org(
                    recovery_consent, device_id, user_agent, impersonate
                )
                if not recovery_code:
                    recovery_code, _ = self._oauth_follow_for_code(
                        recovery_consent,
                        referer=password_page_url,
                        user_agent=user_agent,
                        impersonate=impersonate,
                        max_hops=12,
                    )
                if recovery_code:
                    self._log("session 恢复成功，拿到 authorization code")
                    tokens = self._exchange_code_for_tokens(recovery_code, code_verifier, user_agent, impersonate)
                    if tokens:
                        self._log("✅ OAuth 登录成功（password/verify 失败后 session 恢复）")
                        return tokens
            
            if r.status_code != 200:
                self._log(f"密码验证失败: {r.text[:180]}")
                return None
            
            verify_data = r.json()
            continue_url = verify_data.get("continue_url", "") or continue_url
            page_type = verify_data.get("page", {}).get("type", "") or page_type
            self._log(f"verify page={page_type or '-'} next={self._redact_url(continue_url)[:80] if continue_url else '-'}...")
            
            # 检查是否需要 OTP
            need_oauth_otp = (
                page_type == "email_otp_verification"
                or "email-verification" in (continue_url or "")
                or "email-otp" in (continue_url or "")
            )
            
            if need_oauth_otp and mail_client:
                self._log("检测到需要邮箱 OTP 验证")
                return self._handle_otp_verification(
                    email, device_id, user_agent, sec_ch_ua,
                    impersonate, mail_client, code_verifier, continue_url, page_type
                )
            
        except Exception as e:
            self._log(f"密码验证异常: {e}")
            return None
        
        # 5. 处理 consent 流程
        self._log("步骤4: 处理 consent 流程...")
        code = None
        consent_url = continue_url
        
        if consent_url and consent_url.startswith("/"):
            consent_url = f"{self.oauth_issuer}{consent_url}"
        
        if not consent_url and "consent" in page_type:
            consent_url = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
        
        # 先检查 URL 中是否已经包含 code
        if consent_url:
            code = self._extract_code_from_url(consent_url)
        
        # 跟随 continue_url
        if not code and consent_url:
            self._log("步骤5: 跟随 continue_url 提取 code")
            code, _ = self._oauth_follow_for_code(consent_url, referer=f"{self.oauth_issuer}/log-in/password", user_agent=user_agent, impersonate=impersonate)
        
        # 检查是否需要 workspace/org 选择
        consent_hint = (
            ("consent" in (consent_url or ""))
            or ("sign-in-with-chatgpt" in (consent_url or ""))
            or ("workspace" in (consent_url or ""))
            or ("organization" in (consent_url or ""))
            or ("consent" in page_type)
            or ("organization" in page_type)
        )
        
        if not code and consent_hint:
            if not consent_url:
                consent_url = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
            self._log("步骤6: 执行 workspace/org 选择")
            code = self._oauth_submit_workspace_and_org(consent_url, device_id, user_agent, impersonate)
        
        # 最后回退（带重试机制）
        if not code:
            fallback_consent = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
            
            # 尝试最多 3 次
            for retry in range(3):
                if retry > 0:
                    self._log(f"步骤6: 回退 consent 路径重试 (尝试 {retry + 1}/3)")
                    time.sleep(0.5)  # 短暂延迟
                else:
                    self._log("步骤6: 回退 consent 路径重试")
                
                code = self._oauth_submit_workspace_and_org(fallback_consent, device_id, user_agent, impersonate)
                if code:
                    break
                
                code, _ = self._oauth_follow_for_code(fallback_consent, referer=f"{self.oauth_issuer}/log-in/password", user_agent=user_agent, impersonate=impersonate)
                if code:
                    break
        
        if not code:
            self._log("未获取到 authorization code")
            return None
        
        self._log("获取到 authorization code")
        
        # 6. 用 code 换取 tokens
        self._log("步骤7: POST /oauth/token")
        tokens = self._exchange_code_for_tokens(code, code_verifier, user_agent, impersonate)
        
        if tokens:
            self._log("✅ OAuth 登录成功")
            return tokens
        else:
            self._log("换取 tokens 失败")
            return None
    
    def authorize_external_oauth_url(self, oauth_url, chatgpt_client, *, sms_client=None, expected_state="", user_agent=None, impersonate=None, max_hops=18, email="", password="", mail_client=None, mfa_client=None):
        """使用已登录 ChatGPT session 跟随外部 OAuth URL，返回严格校验过的 callback code/state。"""
        self.last_oauth_error = ""
        self.last_oauth_status = 0
        self.last_oauth_endpoint = ""
        self.last_oauth_page_type = ""
        self.session = chatgpt_client.session
        device_id = getattr(chatgpt_client, "device_id", "") or ""
        user_agent = user_agent or getattr(chatgpt_client, "ua", "") or "Mozilla/5.0"
        impersonate = impersonate or getattr(chatgpt_client, "impersonate", None)
        email = email or getattr(chatgpt_client, "current_email", "") or ""
        password = str(password or "")
        expected_state = str(expected_state or "").strip()
        redirect_uri = str(self.config.get("sub2api_redirect_uri", OAUTH_REDIRECT_URI) or OAUTH_REDIRECT_URI).strip()
        try:
            max_hops = int(self.config.get("sub2api_oauth_max_hops", max_hops) or max_hops)
        except Exception:
            max_hops = 18
        if device_id:
            try:
                self.session.cookies.set("oai-did", device_id, domain=".auth.openai.com")
                self.session.cookies.set("oai-did", device_id, domain="auth.openai.com")
            except Exception:
                pass

        oauth_protocol = {
            "final_url": self._redact_url(oauth_url),
            "last_page_type": "start",
            "choose_account_attempted": False,
            "choose_account_status": "skipped",
            "used_phone_verification": False,
            "callback_url_validated": False,
        }

        result = self._follow_external_authorize_for_callback(
            oauth_url,
            expected_state=expected_state,
            redirect_uri=redirect_uri,
            user_agent=user_agent,
            impersonate=impersonate,
            sms_client=sms_client,
            email=email,
            password=password,
            mail_client=mail_client,
            mfa_client=mfa_client,
            device_id=device_id,
            max_hops=max_hops,
            oauth_protocol=oauth_protocol,
        )
        result["oauth_protocol"] = dict(oauth_protocol)
        return result

    def _parse_validated_callback_url(self, raw_url, expected_state="", redirect_uri=None):
        raw_url = str(raw_url or "").strip()
        if not raw_url:
            return None
        parsed = urlparse(raw_url)
        if parsed.scheme not in ("http", "https"):
            return None
        if parsed.hostname not in ("localhost", "127.0.0.1"):
            return None
        if parsed.port != 1455:
            return None
        if parsed.path.rstrip("/") != "/auth/callback":
            return None
        if redirect_uri:
            expected = urlparse(str(redirect_uri or ""))
            if expected.scheme and parsed.scheme != expected.scheme:
                return None
            if expected.port and parsed.port != expected.port:
                return None
            if expected.path and parsed.path.rstrip("/") != expected.path.rstrip("/"):
                return None
        qs = parse_qs(parsed.query)
        code = str((qs.get("code") or [""])[0] or "").strip()
        state = str((qs.get("state") or [""])[0] or "").strip()
        if not code or not state:
            return None
        if expected_state and state != expected_state:
            return None
        return {"code": code, "state": state, "callback_url": raw_url}

    def _is_tls_or_transient_oauth_error(self, exc):
        msg = str(exc or "").lower()
        markers = (
            "curl: (35)",
            "curl: (28)",
            "tls connect error",
            "openssl_internal",
            "sslerror",
            "connection reset",
            "connection aborted",
            "remote end closed",
            "eof occurred",
            "timed out",
        )
        return any(marker in msg for marker in markers)

    @staticmethod
    def _is_cloudflare_challenge_response(response):
        try:
            status = int(getattr(response, "status_code", 0) or 0)
        except (TypeError, ValueError):
            status = 0
        if status != 403:
            return False
        headers = getattr(response, "headers", {}) or {}
        server = str(headers.get("server", "") or "").lower()
        cf_ray = str(headers.get("cf-ray", "") or "")
        body = str(getattr(response, "text", "") or "").lower()
        return (
            server == "cloudflare"
            or bool(cf_ray)
        ) and any(
            marker in body
            for marker in (
                "just a moment",
                "cf-chl-",
                "/cdn-cgi/challenge-platform/",
            )
        )

    def _oauth_request(self, method, url, *, impersonate=None, **kwargs):
        candidates = []
        if impersonate:
            candidates.append(str(impersonate))
        candidates.extend([x for x in self.oauth_impersonates if x and x not in candidates])
        if not candidates:
            candidates.append(None)
        last_exc = None
        for idx, candidate in enumerate(candidates):
            try:
                request_kwargs = dict(kwargs)
                if candidate:
                    request_kwargs["impersonate"] = candidate
                response = self.session.request(
                    method,
                    url,
                    **request_kwargs,
                )
                if (
                    idx < len(candidates) - 1
                    and self._is_cloudflare_challenge_response(response)
                ):
                    self._log(
                        "OAuth 边缘校验拒绝当前浏览器指纹，"
                        "正在自动切换备用指纹"
                    )
                    continue
                try:
                    status = int(
                        getattr(response, "status_code", 0) or 0
                    )
                except (TypeError, ValueError):
                    status = 0
                if status >= 400:
                    self._remember_oauth_http_failure(
                        response,
                        request_url=url,
                    )
                return response
            except Exception as exc:
                last_exc = exc
                if idx >= len(candidates) - 1 or not self._is_tls_or_transient_oauth_error(exc):
                    raise
                self._log(f"OAuth 请求链路异常，切换 TLS 指纹重试: {type(exc).__name__}")
        if last_exc:
            raise last_exc
        raise RuntimeError("oauth_request_failed")

    def _extract_callback_from_exception(self, exc, expected_state, redirect_uri):
        for match in re.findall(r"https?://(?:localhost|127\.0\.0\.1)[^\s'\"<>]+", str(exc or "")):
            parsed = self._parse_validated_callback_url(match, expected_state=expected_state, redirect_uri=redirect_uri)
            if parsed:
                return parsed
        return None

    def _extract_callback_from_response_text(
        self,
        text,
        expected_state,
        redirect_uri,
    ):
        """Extract callback URLs embedded in HTML, JSON scripts, or RSC text."""
        decoded = html.unescape(str(text or ""))
        decoded = (
            decoded.replace("\\u0026", "&")
            .replace("\\u003d", "=")
            .replace("\\/", "/")
            .replace('\\"', '"')
        )
        candidates = re.findall(
            r"https?://(?:localhost|127\.0\.0\.1):1455/"
            r"auth/callback\?[^'\"<>\s\\]+",
            decoded,
            flags=re.IGNORECASE,
        )
        candidates.extend(
            unquote(match)
            for match in re.findall(
                r"https?%3A%2F%2F(?:localhost|127\.0\.0\.1)"
                r"%3A1455%2Fauth%2Fcallback%3F[^'\"<>\s]+",
                decoded,
                flags=re.IGNORECASE,
            )
        )
        for candidate in candidates:
            parsed = self._parse_validated_callback_url(
                candidate.rstrip("),.;"),
                expected_state=expected_state,
                redirect_uri=redirect_uri,
            )
            if parsed:
                return parsed
        return None

    def _extract_continue_url_from_response_text(self, text, current_url):
        decoded = html.unescape(str(text or ""))
        decoded = (
            decoded.replace("\\u0026", "&")
            .replace("\\u003d", "=")
            .replace("\\/", "/")
            .replace('\\"', '"')
        )
        for pattern in (
            r'"continue_url"\s*:\s*"([^"]+)"',
            r'"continueUrl"\s*:\s*"([^"]+)"',
        ):
            match = re.search(pattern, decoded, flags=re.IGNORECASE)
            if match:
                return self._normalize_continue_url(
                    match.group(1),
                    current_url,
                )
        return ""

    @staticmethod
    def _infer_external_page_type(url, body_text=""):
        url_low = str(url or "").lower()
        url_markers = (
            (
                "email-verification",
                ("email-verification", "email-otp"),
            ),
            ("mfa-challenge", ("mfa-challenge",)),
            ("add-phone", ("add-phone", "phone-verification")),
            ("choose-an-account", ("choose-an-account",)),
            ("organization", ("organization/select", "/organization")),
            ("workspace", ("workspace/select", "/workspace")),
            (
                "consent",
                (
                    "codex/consent",
                    "sign-in-with-chatgpt/consent",
                    "codex_consent",
                ),
            ),
            ("about-you", ("about-you",)),
            (
                "log-in",
                (
                    "/log-in",
                    "login_identifier",
                    "login_email",
                    "login_password",
                ),
            ),
        )
        for page_type, needles in url_markers:
            if any(needle in url_low for needle in needles):
                return page_type

        body_low = html.unescape(str(body_text or "")).replace(
            '\\"',
            '"',
        ).lower()
        structured_body_markers = (
            (
                "consent",
                (
                    '"type":"codex_consent"',
                    '"page_type":"codex_consent"',
                    '"type":"consent"',
                ),
            ),
            (
                "workspace",
                (
                    '"type":"workspace"',
                    '"workspace_id"',
                    '"workspaces"',
                ),
            ),
            (
                "organization",
                (
                    '"type":"organization"',
                    '"organization_id"',
                ),
            ),
            (
                "email-verification",
                (
                    '"type":"email_otp_verification"',
                    '"type":"contact_verification"',
                ),
            ),
            (
                "mfa-challenge",
                (
                    '"type":"mfa_challenge"',
                    '"page_type":"mfa_challenge"',
                ),
            ),
            (
                "add-phone",
                (
                    '"type":"add_phone"',
                    '"type":"phone_verification"',
                ),
            ),
            (
                "log-in",
                (
                    '"type":"login_identifier"',
                    '"type":"login_email"',
                    '"type":"login_password"',
                ),
            ),
        )
        for page_type, needles in structured_body_markers:
            if any(needle in body_low for needle in needles):
                return page_type
        return "http-page"

    def _normalize_continue_url(self, url, base_url=None):
        url = str(url or "").strip()
        if not url:
            return ""
        if url.startswith("/"):
            return urljoin(base_url or self.oauth_issuer, url)
        return url

    def _extract_continue_url_from_json(self, data):
        if not isinstance(data, dict):
            return ""
        out = str(data.get("continue_url") or data.get("url") or "").strip()
        if out:
            return out
        page = data.get("page") if isinstance(data.get("page"), dict) else {}
        payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
        return str(payload.get("url") or "").strip()

    def _response_next_url(self, resp, current_url):
        if getattr(resp, "status_code", 0) in (301, 302, 303, 307, 308):
            return self._normalize_continue_url((resp.headers.get("Location", "") or "").strip(), current_url)
        try:
            return self._normalize_continue_url(self._extract_continue_url_from_json(resp.json()), current_url)
        except Exception:
            return ""

    def _extract_workspace_id_from_html(self, html_text):
        text = (html_text or "").replace('\\"', '"')
        patterns = (
            r'workspaces".{0,1600}?"id","([0-9a-fA-F-]{36})"',
            r'"workspace_id"\s*:\s*"([0-9a-fA-F-]{36})"',
            r'"workspaceId"\s*:\s*"([0-9a-fA-F-]{36})"',
        )
        for pattern in patterns:
            m = re.search(pattern, text, flags=re.DOTALL | re.IGNORECASE)
            if m:
                return (m.group(1) or "").strip()
        return ""

    def _extract_workspace_id_from_session(self):
        data = self._decode_oauth_session_cookie()
        if not isinstance(data, dict):
            return ""
        wid = str(data.get("workspace_id") or "").strip()
        if wid:
            return wid
        workspaces = data.get("workspaces")
        if isinstance(workspaces, list):
            for item in workspaces:
                if isinstance(item, dict) and item.get("id"):
                    return str(item.get("id") or "").strip()
        return ""

    def _select_workspace_for_callback(self, current_url, html_text, expected_state, redirect_uri, user_agent, impersonate, device_id, max_hops, oauth_protocol):
        workspace_id = self._extract_workspace_id_from_session() or self._extract_workspace_id_from_html(html_text or "")
        if not workspace_id:
            return None, ""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": self.oauth_issuer,
            "Referer": current_url,
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        if device_id:
            headers["oai-device-id"] = device_id
        headers.update(generate_datadog_trace())
        resp = self._oauth_request(
            "POST",
            f"{self.oauth_issuer}/api/accounts/workspace/select",
            json={"workspace_id": workspace_id},
            headers=headers,
            allow_redirects=False,
            timeout=30,
            impersonate=impersonate,
        )
        self._log(f"workspace/select -> {getattr(resp, 'status_code', 0)}")
        callback = self._parse_validated_callback_url(str(getattr(resp, "url", "") or ""), expected_state, redirect_uri)
        if callback:
            return callback, callback["callback_url"]
        next_url = self._response_next_url(resp, current_url)
        callback = self._parse_validated_callback_url(next_url, expected_state, redirect_uri)
        if callback:
            return callback, next_url
        try:
            data = resp.json()
        except Exception:
            data = {}
        org_next = self._select_organization_for_callback(data, next_url or current_url, expected_state, redirect_uri, user_agent, impersonate, device_id, max_hops, oauth_protocol)
        if org_next[0] or org_next[1]:
            return org_next
        return None, next_url

    def _select_organization_for_callback(self, data, current_url, expected_state, redirect_uri, user_agent, impersonate, device_id, max_hops, oauth_protocol):
        orgs = []
        if isinstance(data, dict):
            root = data.get("data") if isinstance(data.get("data"), dict) else data
            orgs = root.get("orgs") or root.get("organizations") or []
        if not isinstance(orgs, list) or not orgs:
            return None, ""
        org = orgs[0] if isinstance(orgs[0], dict) else {}
        org_id = str(org.get("id") or org.get("org_id") or "").strip()
        projects = org.get("projects") if isinstance(org.get("projects"), list) else []
        project_id = str((projects[0] or {}).get("id") or "").strip() if projects and isinstance(projects[0], dict) else ""
        if not org_id:
            return None, ""
        body = {"org_id": org_id}
        if project_id:
            body["project_id"] = project_id
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": self.oauth_issuer,
            "Referer": current_url or f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent",
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        if device_id:
            headers["oai-device-id"] = device_id
        headers.update(generate_datadog_trace())
        resp = self._oauth_request(
            "POST",
            f"{self.oauth_issuer}/api/accounts/organization/select",
            json=body,
            headers=headers,
            allow_redirects=False,
            timeout=30,
            impersonate=impersonate,
        )
        self._log(f"organization/select -> {getattr(resp, 'status_code', 0)}")
        callback = self._parse_validated_callback_url(str(getattr(resp, "url", "") or ""), expected_state, redirect_uri)
        if callback:
            return callback, callback["callback_url"]
        next_url = self._response_next_url(resp, current_url)
        callback = self._parse_validated_callback_url(next_url, expected_state, redirect_uri)
        if callback:
            return callback, next_url
        return None, next_url

    def _oauth_complete_add_phone_for_continue(self, email, device_id, user_agent, impersonate, sms_client, current_url):
        if not sms_client or not all(hasattr(sms_client, name) for name in ("buy_number", "get_sms_code")):
            raise RuntimeError("add_phone_requires_sms_client")
        max_attempts = int(getattr(sms_client, "max_phone_attempts", 3) or 3)
        if callable(
            getattr(sms_client, "handle_explicit_phone_rejection", None)
        ):
            replacement_limit = max(
                0,
                int(
                    getattr(
                        sms_client,
                        "max_phone_replacements_per_oauth_session",
                        2,
                    )
                    or 0
                ),
            )
            max_attempts = min(max_attempts, replacement_limit + 1)
        last_error = ""
        for phone_attempt in range(1, max(1, max_attempts) + 1):
            order_id = ""
            phone, order_id = sms_client.buy_number(country=getattr(sms_client, "country", ""), operator=getattr(sms_client, "operator", None))
            if not phone:
                last_error = "add_phone_no_number"
                break
            baseline_codes = set()
            if hasattr(sms_client, "snapshot_sms_codes"):
                try:
                    baseline_codes = set(
                        sms_client.snapshot_sms_codes(order_id) or set()
                    )
                except Exception:
                    if bool(
                        getattr(
                            sms_client,
                            "change_number_requested",
                            False,
                        )
                    ):
                        self._log(
                            "phone receipt precheck requested a number "
                            "change; requesting the next number"
                        )
                        continue
                    raise
            phone_digits = re.sub(r"\D", "", str(phone or ""))
            submit_phone = f"+1{phone_digits}" if len(phone_digits) == 10 else str(phone or "").strip()
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Referer": current_url or f"{self.oauth_issuer}/add-phone",
                "Origin": self.oauth_issuer,
                "User-Agent": user_agent or "Mozilla/5.0",
            }
            if device_id:
                headers["oai-device-id"] = device_id
            headers.update(generate_datadog_trace())
            try:
                resp = self._oauth_request(
                    "POST",
                    f"{self.oauth_issuer}/api/accounts/add-phone/send",
                    json={"phone_number": submit_phone},
                    headers=headers,
                    timeout=30,
                    allow_redirects=False,
                    impersonate=impersonate,
                )
                body_text = getattr(resp, "text", "") or ""
                body_low = body_text.lower()
                rejection_details = self._response_error_details(resp)
                rejection_code = rejection_details["code"]
                rejection_type = rejection_details["type"]
                rejection_key = rejection_code or rejection_type
                send_rate_limited = (
                    getattr(resp, "status_code", 0) == 429
                    or rejection_key in {
                        "rate_limit_exceeded",
                        "phone_verification_rate_limited",
                    }
                    or "too many phone verification requests" in body_low
                )
                self._log(f"add-phone/send attempt={phone_attempt}/{max_attempts} -> {getattr(resp, 'status_code', 0)}")
                number_rejected = (
                    "unable to send" in body_low and "verification code" in body_low
                ) or (
                    "try again later" in body_low and "different number" in body_low
                ) or rejection_key in {
                    "phone_max_usage_exceeded",
                    "phone_number_invalid",
                    "phone_number_not_supported",
                    "phone_number_in_use",
                    "phone_verification_rate_limited",
                    "phone_verification_send_failed",
                }
                if getattr(resp, "status_code", 0) != 200:
                    self._record_sms_phone_error(sms_client, resp, "send")
                    session_invalid = (
                        rejection_code in {"invalid_auth_step", "invalid_state"}
                        or rejection_type in {"invalid_auth_step", "invalid_state"}
                        or "invalid_auth_step" in body_low
                        or "session is no longer valid" in body_low
                    )
                    if session_invalid:
                        # This response means the OAuth state machine is stale;
                        # it does not mean the phone number is bad.  Preserve the
                        # active SMS lease and ask the caller to rebuild the
                        # OAuth session automatically instead of consuming more
                        # numbers in the same invalid add-phone step.
                        handler = getattr(
                            sms_client,
                            "mark_oauth_session_invalid",
                            None,
                        )
                        if callable(handler):
                            handler(order_id)
                        raise RuntimeError(
                            "oauth_session_invalid: invalid_auth_step"
                        )
                    if send_rate_limited:
                        # A send limit belongs to the OAuth/account egress, not
                        # to the SMS number.  Bubble it up without calling
                        # mark_order_abnormal(), so the caller can retain the
                        # same lease and perform a timed automatic retry.
                        raise RuntimeError(
                            "oauth_phone_send_rate_limited: "
                            + (rejection_key or "rate_limit_exceeded")
                        )
                    last_error = (
                        rejection_key
                        or ("add_phone_number_rejected" if number_rejected else "")
                        or f"add_phone_send_http_{getattr(resp, 'status_code', 0)}"
                    )
                    # Only an explicit phone rejection rotates the number. A
                    # generic HTTP/redirect/session response tears down this
                    # attempt and lets the outer runner rebuild OAuth on the
                    # same 手机号供应商 lease.
                    if number_rejected:
                        rejection_action = self._handle_explicit_phone_rejection(
                            sms_client,
                            order_id,
                            last_error,
                        )
                        if rejection_action == "continue":
                            self._log(
                                "add-phone/send rejected current number; "
                                "using the next number in the same OAuth session"
                            )
                            continue
                        if rejection_action == "rollover":
                            raise RuntimeError(
                                "oauth_phone_session_rollover_required: "
                                + last_error
                            )
                    if bool(
                        getattr(
                            sms_client,
                            "change_number_requested",
                            False,
                        )
                    ):
                        self._log(
                            "add-phone/send rejected current number; "
                            "requesting the next number"
                        )
                        raise RuntimeError(
                            "oauth_phone_number_change_required: "
                            + last_error
                        )
                    raise RuntimeError(
                        f"oauth_phone_retry_same_number: {last_error}"
                    )
                try:
                    send_data = resp.json()
                except Exception:
                    send_data = {}
                send_next = self._normalize_continue_url(self._extract_continue_url_from_json(send_data), current_url)
                code = sms_client.get_sms_code(
                    order_id,
                    timeout=int(getattr(sms_client, "sms_timeout", 120) or 120),
                    exclude_codes=baseline_codes,
                )
                if not code:
                    last_error = "add_phone_sms_timeout"
                    if bool(
                        getattr(
                            sms_client,
                            "change_number_requested",
                            False,
                        )
                    ):
                        self._log(
                            "phone code input requested a number change; "
                            "requesting the next number"
                        )
                        raise RuntimeError(
                            "oauth_phone_number_change_required: "
                            + last_error
                        )
                    if bool(
                        getattr(sms_client, "yield_job_after_attempt", False)
                    ):
                        raise RuntimeError(
                            "oauth_phone_retry_same_number: "
                            + last_error
                        )
                    if hasattr(sms_client, "cancel_order"):
                        sms_client.cancel_order(order_id)
                    raise RuntimeError(
                        f"oauth_phone_number_change_required: {last_error}"
                    )
                validate_headers = dict(headers)
                validate_headers["Referer"] = send_next or f"{self.oauth_issuer}/phone-verification"
                resp2 = self._oauth_request(
                    "POST",
                    f"{self.oauth_issuer}/api/accounts/phone-otp/validate",
                    json={"code": str(code).strip()},
                    headers=validate_headers,
                    timeout=30,
                    allow_redirects=False,
                    impersonate=impersonate,
                )
                self._log(f"phone-otp/validate -> {getattr(resp2, 'status_code', 0)}")
                if getattr(resp2, "status_code", 0) != 200:
                    validation_details = self._record_sms_phone_error(
                        sms_client,
                        resp2,
                        "validate",
                    )
                    last_error = (
                        validation_details["code"]
                        or validation_details["type"]
                        or f"phone_otp_validate_http_{getattr(resp2, 'status_code', 0)}"
                    )
                    session_invalid = (
                        validation_details["code"] == "invalid_state"
                        or validation_details["type"] == "invalid_state"
                        or "session is no longer valid"
                        in validation_details["message"].lower()
                    )
                    if session_invalid:
                        handler = getattr(
                            sms_client,
                            "mark_oauth_session_invalid",
                            None,
                        )
                        if callable(handler):
                            handler(order_id)
                        raise RuntimeError("oauth_session_invalid")
                    # OTP validation failures are account/session outcomes by
                    # default. Rotate only when the response explicitly names
                    # the submitted number as rejected.
                    validation_message = validation_details["message"].lower()
                    validation_number_rejected = (
                        validation_details["code"] in {
                            "phone_number_invalid",
                            "phone_number_not_supported",
                            "phone_number_in_use",
                            "phone_max_usage_exceeded",
                        }
                        or "different number" in validation_message
                        or "phone number" in validation_message
                        and "not supported" in validation_message
                    )
                    if validation_number_rejected:
                        rejection_action = self._handle_explicit_phone_rejection(
                            sms_client,
                            order_id,
                            last_error,
                        )
                        if rejection_action == "continue":
                            self._log(
                                "phone verification rejected current number; "
                                "using the next number in the same OAuth session"
                            )
                            continue
                        if rejection_action == "rollover":
                            raise RuntimeError(
                                "oauth_phone_session_rollover_required: "
                                + last_error
                            )
                    if bool(
                        getattr(
                            sms_client,
                            "change_number_requested",
                            False,
                        )
                    ):
                        self._log(
                            "phone verification rejected current number; "
                            "requesting the next number"
                        )
                        raise RuntimeError(
                            "oauth_phone_number_change_required: "
                            + last_error
                        )
                    if bool(getattr(sms_client, "sms_consumed", False)):
                        # The code has already been consumed; a new attempt
                        # must use a fresh lease, but only after this OAuth
                        # context is torn down by the outer runner.
                        raise RuntimeError(
                            "oauth_phone_number_change_required: "
                            + last_error
                        )
                    raise RuntimeError(
                        f"oauth_phone_retry_same_number: {last_error}"
                    )
                if hasattr(sms_client, "finish_order"):
                    sms_client.finish_order(order_id)
                try:
                    validate_data = resp2.json()
                except Exception:
                    validate_data = {}
                return self._normalize_continue_url(self._extract_continue_url_from_json(validate_data), current_url) or self._response_next_url(resp2, current_url) or send_next or current_url
            except Exception as exc:
                if any(
                    marker in str(exc)
                    for marker in (
                        "oauth_phone_retry_restart",
                        "oauth_phone_number_change_required",
                        "oauth_phone_retry_same_number",
                        "oauth_session_invalid",
                        "oauth_phone_send_rate_limited",
                        "oauth_phone_session_rollover_required",
                    )
                ):
                    raise
                last_error = f"{type(exc).__name__}: {exc}"
                if hasattr(sms_client, "cancel_order"):
                    sms_client.cancel_order(order_id)
        raise RuntimeError(last_error or "add_phone_failed")

    def _follow_external_authorize_for_callback(self, start_url, *, expected_state, redirect_uri, user_agent, impersonate, sms_client, email, password, mail_client, mfa_client, device_id, max_hops, oauth_protocol, allow_add_phone=True):
        current_url = self._normalize_continue_url(start_url, self.oauth_issuer)
        original_url = current_url
        referer = "https://chatgpt.com/"
        chose_account = False
        used_phone = False

        def _success(callback):
            oauth_protocol["last_page_type"] = "callback"
            oauth_protocol["callback_url_validated"] = True
            oauth_protocol["final_url"] = self._redact_url(callback["callback_url"])
            oauth_protocol["used_phone_verification"] = used_phone
            return {
                "ok": True,
                "code": callback["code"],
                "state": callback["state"],
                "callback_url": self._redact_url(callback["callback_url"]),
                "callback_url_validated": True,
                "final_url": self._redact_url(callback["callback_url"]),
                "used_phone_verification": used_phone,
            }

        def _failure(error, final_url=""):
            failure_url = final_url or current_url
            if (
                self.last_oauth_error
                and str(error or "").strip() == self.last_oauth_error
            ):
                if self.last_oauth_status:
                    oauth_protocol["last_http_status"] = (
                        self.last_oauth_status
                    )
                if self.last_oauth_page_type:
                    oauth_protocol["last_page_type"] = (
                        self.last_oauth_page_type
                    )
                if self.last_oauth_endpoint:
                    failure_url = urljoin(
                        self.oauth_issuer,
                        self.last_oauth_endpoint,
                    )
            oauth_protocol["error"] = self._redact_text(error)
            oauth_protocol["final_url"] = self._redact_url(failure_url)
            oauth_protocol["used_phone_verification"] = used_phone
            return {
                "ok": False,
                "error": self._redact_text(error),
                "final_url": self._redact_url(failure_url),
                "callback_url_validated": False,
                "used_phone_verification": used_phone,
            }

        for hop in range(max(1, int(max_hops or 18))):
            callback = self._parse_validated_callback_url(current_url, expected_state, redirect_uri)
            if callback:
                return _success(callback)

            low = (current_url or "").lower()
            if "mfa-challenge" in low:
                oauth_protocol["last_page_type"] = "mfa-challenge"
                next_url = self._oauth_complete_totp_mfa_for_continue(
                    device_id=device_id,
                    user_agent=user_agent,
                    impersonate=impersonate,
                    mfa_client=mfa_client,
                    current_url=current_url,
                )
                if not next_url:
                    return _failure(
                        self.last_oauth_error or "mfa_totp_verification_failed",
                        current_url,
                    )
                referer = current_url
                current_url = self._normalize_continue_url(next_url, current_url)
                continue

            if "choose-an-account" in low and not chose_account:
                oauth_protocol["last_page_type"] = "choose-an-account"
                oauth_protocol["choose_account_attempted"] = True
                next_url = self._oauth_choose_account_select("", current_url, user_agent, impersonate)
                if not next_url:
                    oauth_protocol["choose_account_status"] = "failed"
                    return _failure("choose_account_failed", current_url)
                oauth_protocol["choose_account_status"] = "ok"
                chose_account = True
                referer = current_url
                current_url = self._normalize_continue_url(next_url if next_url != current_url else original_url, current_url)
                continue

            if ("add-phone" in low or "phone-verification" in low or "phone-verify" in low) and allow_add_phone:
                oauth_protocol["last_page_type"] = "add-phone"
                try:
                    current_url = self._oauth_complete_add_phone_for_continue(email, device_id, user_agent, impersonate, sms_client, current_url)
                    used_phone = True
                    oauth_protocol["used_phone_verification"] = True
                    referer = f"{self.oauth_issuer}/phone-verification"
                    continue
                except Exception as exc:
                    return _failure(f"add_phone_failed: {type(exc).__name__}: {exc}", current_url)

            if "about-you" in low:
                oauth_protocol["last_page_type"] = "about-you"
                if not self._oauth_try_complete_about_you(email, current_url, device_id, user_agent, impersonate):
                    return _failure("about_you_failed", current_url)
                referer = current_url
                current_url = original_url
                continue

            if "/log-in" in low:
                oauth_protocol["last_page_type"] = "log-in"
                next_url = self._oauth_drive_external_login_for_continue(
                    email=email,
                    password=password,
                    current_url=current_url,
                    device_id=device_id,
                    user_agent=user_agent,
                    impersonate=impersonate,
                    mail_client=mail_client,
                    mfa_client=mfa_client,
                    sms_client=sms_client,
                )
                if not next_url:
                    return _failure(
                        self.last_oauth_error or "login_continue_failed",
                        current_url,
                    )
                referer = current_url
                current_url = self._normalize_continue_url(next_url, current_url)
                continue

            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": user_agent or "Mozilla/5.0",
                "Referer": referer,
            }
            try:
                resp = self._oauth_request(
                    "GET",
                    current_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=30,
                    impersonate=impersonate,
                )
            except Exception as exc:
                callback = self._extract_callback_from_exception(exc, expected_state, redirect_uri)
                if callback:
                    return _success(callback)
                return _failure(f"{type(exc).__name__}: {exc}", current_url)

            final_url = str(getattr(resp, "url", "") or current_url)
            oauth_protocol["final_url"] = self._redact_url(final_url)
            oauth_protocol["last_http_status"] = int(
                getattr(resp, "status_code", 0) or 0
            )
            self._log(f"external-oauth[{hop + 1}] {getattr(resp, 'status_code', 0)} {self._redact_url(final_url)[:120]}")

            callback = self._parse_validated_callback_url(final_url, expected_state, redirect_uri)
            if callback:
                return _success(callback)

            response_text = str(getattr(resp, "text", "") or "")
            embedded_callback = self._extract_callback_from_response_text(
                response_text,
                expected_state,
                redirect_uri,
            )
            if embedded_callback:
                return _success(embedded_callback)

            if self._is_cloudflare_challenge_response(resp):
                oauth_protocol["last_page_type"] = "edge-challenge"
                return _failure(
                    "oauth_cloudflare_challenge",
                    final_url,
                )

            if getattr(resp, "status_code", 0) == 200:
                html_text = response_text
                body_low = html_text.lower()
                inferred_page = self._infer_external_page_type(
                    final_url,
                    html_text,
                )
                oauth_protocol["last_page_type"] = inferred_page
                if inferred_page == "email-verification":
                    if mail_client is None:
                        return _failure(
                            "email_otp_provider_required",
                            final_url,
                        )
                    baseline_ids = set()
                    if hasattr(
                        mail_client,
                        "snapshot_openai_message_ids",
                    ):
                        try:
                            baseline_ids = set(
                                mail_client.snapshot_openai_message_ids(
                                    email
                                )
                                or set()
                            )
                        except Exception:
                            baseline_ids = set()
                    next_url = (
                        self._oauth_complete_email_otp_for_continue(
                            email=email,
                            device_id=device_id,
                            user_agent=user_agent,
                            impersonate=impersonate,
                            mail_client=mail_client,
                            mfa_client=mfa_client,
                            continue_url=final_url,
                            page_type="email_otp_verification",
                            baseline_message_ids=baseline_ids,
                        )
                    )
                    if not next_url:
                        return _failure(
                            self.last_oauth_error
                            or "email_otp_verification_failed",
                            final_url,
                        )
                    referer = final_url
                    current_url = self._normalize_continue_url(
                        next_url,
                        final_url,
                    )
                    continue
                if inferred_page == "log-in":
                    next_url = self._oauth_drive_external_login_for_continue(
                        email=email,
                        password=password,
                        current_url=final_url,
                        device_id=device_id,
                        user_agent=user_agent,
                        impersonate=impersonate,
                        mail_client=mail_client,
                        mfa_client=mfa_client,
                        sms_client=sms_client,
                    )
                    if not next_url:
                        return _failure(
                            self.last_oauth_error
                            or "login_continue_failed",
                            final_url,
                        )
                    referer = final_url
                    current_url = self._normalize_continue_url(
                        next_url,
                        final_url,
                    )
                    continue
                if inferred_page == "mfa-challenge":
                    next_url = self._oauth_complete_totp_mfa_for_continue(
                        device_id=device_id,
                        user_agent=user_agent,
                        impersonate=impersonate,
                        mfa_client=mfa_client,
                        current_url=final_url,
                    )
                    if not next_url:
                        return _failure(
                            self.last_oauth_error
                            or "mfa_totp_verification_failed",
                            final_url,
                        )
                    referer = final_url
                    current_url = self._normalize_continue_url(
                        next_url,
                        final_url,
                    )
                    continue
                if "choose-an-account" in final_url.lower() and not chose_account:
                    oauth_protocol["last_page_type"] = "choose-an-account"
                    oauth_protocol["choose_account_attempted"] = True
                    next_url = self._oauth_choose_account_select(html_text, final_url, user_agent, impersonate)
                    if not next_url:
                        oauth_protocol["choose_account_status"] = "failed"
                        return _failure("choose_account_failed", final_url)
                    oauth_protocol["choose_account_status"] = "ok"
                    chose_account = True
                    referer = final_url
                    current_url = self._normalize_continue_url(next_url if next_url != final_url else original_url, final_url)
                    continue
                if ("workspace" in final_url.lower()) or "workspace_id" in body_low or "workspaces" in body_low:
                    oauth_protocol["last_page_type"] = "workspace"
                    callback, next_url = self._select_workspace_for_callback(final_url, html_text, expected_state, redirect_uri, user_agent, impersonate, device_id, max_hops, oauth_protocol)
                    if callback:
                        return _success(callback)
                    if next_url:
                        referer = final_url
                        current_url = self._normalize_continue_url(next_url, final_url)
                        continue
                if inferred_page in {"consent", "http-page"}:
                    if inferred_page == "consent":
                        oauth_protocol["last_page_type"] = "consent"
                    callback, next_url = self._select_workspace_for_callback(
                        final_url,
                        html_text,
                        expected_state,
                        redirect_uri,
                        user_agent,
                        impersonate,
                        device_id,
                        max_hops,
                        oauth_protocol,
                    )
                    if callback:
                        return _success(callback)
                    if next_url:
                        referer = final_url
                        current_url = self._normalize_continue_url(
                            next_url,
                            final_url,
                        )
                        continue
                if "add-phone" in body_low and allow_add_phone:
                    current_url = f"{self.oauth_issuer}/add-phone"
                    referer = final_url
                    continue

            next_url = self._response_next_url(resp, final_url)
            if not next_url:
                next_url = self._extract_continue_url_from_response_text(
                    response_text,
                    final_url,
                )
            callback = self._parse_validated_callback_url(next_url, expected_state, redirect_uri)
            if callback:
                return _success(callback)
            if not next_url:
                return _failure("oauth_callback_not_found", final_url)
            referer = final_url
            current_url = self._normalize_continue_url(next_url, final_url)

        return _failure("oauth_callback_timeout", current_url)

    @staticmethod
    def _oauth_page_type(data):
        if not isinstance(data, dict):
            return ""
        page = data.get("page") if isinstance(data.get("page"), dict) else {}
        return str(page.get("type") or data.get("page_type") or "").strip()

    @classmethod
    def _is_mfa_challenge(cls, page_type="", continue_url="", data=None):
        page_low = str(page_type or cls._oauth_page_type(data) or "").lower()
        url_low = str(continue_url or "").lower()
        return "mfa_challenge" in page_low or "mfa-challenge" in url_low

    @staticmethod
    def _mfa_factors_from_container(container):
        found = []
        visited = set()

        def walk(value, depth=0):
            if depth > 8 or id(value) in visited:
                return
            if isinstance(value, (dict, list)):
                visited.add(id(value))
            if isinstance(value, dict):
                for key in ("mfa_factors", "factors"):
                    items = value.get(key)
                    if isinstance(items, list):
                        for item in items:
                            if (
                                isinstance(item, dict)
                                and item.get("id")
                                and (item.get("factor_type") or item.get("type"))
                            ):
                                found.append(item)
                for nested in value.values():
                    walk(nested, depth + 1)
            elif isinstance(value, list):
                for nested in value:
                    walk(nested, depth + 1)

        walk(container)
        unique = []
        seen = set()
        for item in found:
            factor_id = str(item.get("id") or "").strip()
            factor_type = str(
                item.get("factor_type") or item.get("type") or ""
            ).strip().lower()
            key = (factor_id, factor_type)
            if factor_id and factor_type and key not in seen:
                unique.append(
                    {
                        **item,
                        "id": factor_id,
                        "factor_type": factor_type,
                    }
                )
                seen.add(key)
        return unique

    def _resolve_totp_factor(self, response_data=None, current_url=""):
        factors = self._mfa_factors_from_container(response_data)
        if not factors:
            try:
                factors = self._mfa_factors_from_container(
                    self._decode_oauth_session_cookie()
                )
            except Exception:
                factors = []

        html_text = ""
        if not factors and current_url:
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "User-Agent": "Mozilla/5.0",
            }
            try:
                response = self._oauth_request(
                    "GET",
                    current_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=30,
                )
                try:
                    factors = self._mfa_factors_from_container(response.json())
                except Exception:
                    html_text = str(getattr(response, "text", "") or "")
            except Exception:
                pass

        for factor in factors:
            if factor.get("factor_type") == "totp":
                return factor

        if html_text:
            decoded = html_text.replace('\\"', '"')
            patterns = (
                r'"id"\s*:\s*"([^"]+)"[^{}]{0,400}"factor_type"\s*:\s*"totp"',
                r'"factor_type"\s*:\s*"totp"[^{}]{0,400}"id"\s*:\s*"([^"]+)"',
            )
            for pattern in patterns:
                match = re.search(pattern, decoded, flags=re.IGNORECASE)
                if match:
                    return {"id": match.group(1), "factor_type": "totp"}

        path_match = re.search(
            r"/mfa-challenge/([^/?#]+)",
            str(current_url or ""),
            flags=re.IGNORECASE,
        )
        if path_match:
            return {"id": path_match.group(1), "factor_type": "totp"}
        return None

    def _mfa_next_url(self, data, current_url):
        next_url = self._normalize_continue_url(
            self._extract_continue_url_from_json(data),
            current_url,
        )
        if next_url:
            return next_url
        page_type = self._oauth_page_type(data).lower()
        if "codex" in page_type and "organization" in page_type:
            return f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/organization"
        if "codex" in page_type and "consent" in page_type:
            return f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
        if "consent" in page_type:
            return f"{self.oauth_issuer}/sign-in-with-chatgpt/consent"
        if "workspace" in page_type:
            return f"{self.oauth_issuer}/workspace"
        if "choose" in page_type and "account" in page_type:
            return f"{self.oauth_issuer}/choose-an-account"
        if "add_phone" in page_type or "phone_otp" in page_type:
            return f"{self.oauth_issuer}/add-phone"
        if "about" in page_type:
            return f"{self.oauth_issuer}/about-you"
        return self._response_next_url_from_data_fallback(data, current_url)

    def _response_next_url_from_data_fallback(self, data, current_url):
        if not isinstance(data, dict):
            return ""
        for key in ("redirect_uri", "redirect_url", "location"):
            value = str(data.get(key) or "").strip()
            if value:
                return self._normalize_continue_url(value, current_url)
        return ""

    def _oauth_complete_totp_mfa_for_continue(
        self,
        *,
        device_id,
        user_agent,
        impersonate,
        mfa_client,
        current_url,
        response_data=None,
    ):
        if mfa_client is None:
            self.last_oauth_error = "mfa_totp_secret_required"
            self._log("检测到 OpenAI 2FA，但当前模式没有提供 2FA 密钥")
            return ""

        factor = self._resolve_totp_factor(
            response_data=response_data,
            current_url=current_url,
        )
        if not factor:
            self.last_oauth_error = "mfa_totp_factor_not_available"
            self._log("OpenAI MFA 列表中没有可用的 TOTP 验证器")
            return ""

        factor_id = str(factor.get("id") or "").strip()
        factor_url = (
            f"{self.oauth_issuer}/mfa-challenge/{factor_id}"
            if factor_id
            else (current_url or f"{self.oauth_issuer}/mfa-challenge")
        )
        self._visit_oauth_page(
            factor_url,
            referer=current_url or f"{self.oauth_issuer}/mfa-challenge",
            user_agent=user_agent,
            impersonate=impersonate,
        )
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": factor_url,
            "Origin": self.oauth_issuer,
            "oai-device-id": device_id,
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        headers.update(generate_datadog_trace())
        issue_response = self._oauth_request(
            "POST",
            f"{self.oauth_issuer}/api/accounts/mfa/issue_challenge",
            json={
                "id": factor_id,
                "type": "totp",
                "force_fresh_challenge": False,
            },
            headers=headers,
            timeout=30,
            allow_redirects=False,
            impersonate=impersonate,
        )
        issue_status = int(getattr(issue_response, "status_code", 0) or 0)
        self._log(f"mfa/issue_challenge(totp) -> {issue_status}")
        if issue_status not in (200, 201, 204):
            details = self._response_error_details(issue_response)
            self.last_oauth_error = (
                details["code"]
                or details["type"]
                or f"mfa_issue_challenge_http_{issue_status}"
            )
            return ""

        max_attempts = max(
            1,
            int(getattr(mfa_client, "max_attempts", 3) or 3),
        )
        tried_codes = set()
        for attempt in range(1, max_attempts + 1):
            getter = getattr(mfa_client, "get_mfa_code", None)
            if not callable(getter):
                self.last_oauth_error = "mfa_totp_provider_invalid"
                return ""
            try:
                code = getter(
                    timeout=self.email_otp_timeout,
                    exclude_codes=tried_codes,
                )
            except TypeError:
                code = getter()
            code = str(code or "").strip()
            if not re.fullmatch(r"\d{6}", code):
                self.last_oauth_error = "mfa_totp_code_unavailable"
                return ""
            tried_codes.add(code)

            verify_response = self._oauth_request(
                "POST",
                f"{self.oauth_issuer}/api/accounts/mfa/verify",
                json={
                    "id": factor_id,
                    "type": "totp",
                    "code": code,
                },
                headers=headers,
                timeout=30,
                allow_redirects=False,
                impersonate=impersonate,
            )
            verify_status = int(
                getattr(verify_response, "status_code", 0) or 0
            )
            self._log(
                f"mfa/verify(totp) attempt={attempt}/{max_attempts} -> "
                f"{verify_status}"
            )
            try:
                verify_data = verify_response.json()
            except Exception:
                verify_data = {}

            still_mfa = self._is_mfa_challenge(
                data=verify_data,
                continue_url=self._extract_continue_url_from_json(verify_data),
            )
            if verify_status in (200, 201, 204) and not still_mfa:
                next_url = self._mfa_next_url(verify_data, current_url)
                if not next_url:
                    next_url = self._response_next_url(
                        verify_response,
                        current_url,
                    )
                if not next_url or self._is_mfa_challenge(
                    continue_url=next_url
                ):
                    next_url = (
                        f"{self.oauth_issuer}/sign-in-with-chatgpt/"
                        "codex/consent"
                    )
                self.last_oauth_error = ""
                self._log("OpenAI 2FA 动态码验证通过")
                return next_url

            details = self._response_error_details(verify_response)
            self.last_oauth_error = (
                details["code"]
                or details["type"]
                or f"mfa_totp_rejected_{verify_status}"
            )
            if verify_status == 429:
                break

        return ""

    def _oauth_drive_external_login_for_continue(self, *, email, password, current_url, device_id, user_agent, impersonate, mail_client=None, mfa_client=None, sms_client=None):
        email = str(email or "").strip()
        password = str(password or "")
        if not email:
            self._log("log-in 分支缺少邮箱")
            return ""

        sentinel = build_sentinel_token(
            self.session,
            device_id,
            flow="authorize_continue",
            user_agent=user_agent,
            impersonate=impersonate,
        )
        if not sentinel:
            self._log("log-in 分支无法获取 authorize_continue sentinel")
            return ""

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": current_url or f"{self.oauth_issuer}/log-in",
            "Origin": self.oauth_issuer,
            "oai-device-id": device_id,
            "openai-sentinel-token": sentinel,
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        headers.update(generate_datadog_trace())
        resp = self._oauth_request(
            "POST",
            f"{self.oauth_issuer}/api/accounts/authorize/continue",
            json={"username": {"kind": "email", "value": email}},
            headers=headers,
            timeout=30,
            allow_redirects=False,
            impersonate=impersonate,
        )
        self._log(f"log-in authorize/continue -> {getattr(resp, 'status_code', 0)}")
        if getattr(resp, "status_code", 0) != 200:
            self._log(f"log-in authorize/continue 失败: {getattr(resp, 'text', '')[:160]}")
            return ""
        try:
            data = resp.json()
        except Exception:
            data = {}
        continue_url = self._normalize_continue_url(self._extract_continue_url_from_json(data), current_url)
        page_type = str(((data.get("page") or {}) if isinstance(data, dict) else {}).get("type") or "").strip()
        page_low = page_type.lower()
        url_low = (continue_url or "").lower()

        if self._is_mfa_challenge(page_type, continue_url, data):
            return self._oauth_complete_totp_mfa_for_continue(
                device_id=device_id,
                user_agent=user_agent,
                impersonate=impersonate,
                mfa_client=mfa_client,
                current_url=continue_url or current_url,
                response_data=data,
            )

        if page_low == "login_password" or "/log-in/password" in url_low:
            password_page_url = continue_url or f"{self.oauth_issuer}/log-in/password"
            self._visit_oauth_page(password_page_url, referer=current_url, user_agent=user_agent, impersonate=impersonate)
            if not password:
                if not mail_client:
                    self.last_oauth_error = "mfa_primary_factor_required"
                    self._log(
                        "该账号先要求密码或邮箱验证码；仅有 2FA 密钥不足以完成首段登录"
                    )
                    return ""
                baseline_ids = set()
                if hasattr(mail_client, "snapshot_openai_message_ids"):
                    try:
                        baseline_ids = set(
                            mail_client.snapshot_openai_message_ids(email)
                            or set()
                        )
                    except Exception:
                        baseline_ids = set()
                headers_pwdless = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Referer": password_page_url,
                    "Origin": self.oauth_issuer,
                    "oai-device-id": device_id,
                    "User-Agent": user_agent or "Mozilla/5.0",
                }
                headers_pwdless.update(generate_datadog_trace())
                resp_pwdless = self._oauth_request(
                    "POST",
                    f"{self.oauth_issuer}/api/accounts/passwordless/send-otp",
                    json={},
                    headers=headers_pwdless,
                    timeout=30,
                    allow_redirects=False,
                    impersonate=impersonate,
                )
                pwdless_status = int(
                    getattr(resp_pwdless, "status_code", 0) or 0
                )
                self._log(
                    f"log-in passwordless/send-otp -> {pwdless_status}"
                )
                if pwdless_status not in (200, 201, 204):
                    details = self._response_error_details(resp_pwdless)
                    self.last_oauth_error = (
                        details["code"]
                        or details["type"]
                        or f"passwordless_send_otp_http_{pwdless_status}"
                    )
                    return ""
                try:
                    pwdless_data = resp_pwdless.json()
                except Exception:
                    pwdless_data = {}
                pwdless_continue_url = self._normalize_continue_url(
                    self._extract_continue_url_from_json(pwdless_data),
                    password_page_url,
                )
                pwdless_page_type = self._oauth_page_type(pwdless_data)
                return self._oauth_complete_email_otp_for_continue(
                    email=email,
                    device_id=device_id,
                    user_agent=user_agent,
                    impersonate=impersonate,
                    mail_client=mail_client,
                    mfa_client=mfa_client,
                    continue_url=(
                        pwdless_continue_url
                        or continue_url
                        or password_page_url
                    ),
                    page_type=pwdless_page_type,
                    baseline_message_ids=baseline_ids,
                )

            sentinel_pwd = build_sentinel_token(
                self.session,
                device_id,
                flow="password_verify",
                user_agent=user_agent,
                impersonate=impersonate,
            )
            if not sentinel_pwd:
                self._log("log-in 分支无法获取 password_verify sentinel")
                return ""
            headers_pwd = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Referer": password_page_url,
                "Origin": self.oauth_issuer,
                "oai-device-id": device_id,
                "openai-sentinel-token": sentinel_pwd,
                "User-Agent": user_agent or "Mozilla/5.0",
            }
            headers_pwd.update(generate_datadog_trace())
            resp_pwd = self._oauth_request(
                "POST",
                f"{self.oauth_issuer}/api/accounts/password/verify",
                json={"password": password},
                headers=headers_pwd,
                timeout=30,
                allow_redirects=False,
                impersonate=impersonate,
            )
            self._log(f"log-in password/verify -> {getattr(resp_pwd, 'status_code', 0)}")
            if getattr(resp_pwd, "status_code", 0) != 200:
                self._log(f"log-in password/verify 失败: {getattr(resp_pwd, 'text', '')[:160]}")
                if getattr(resp_pwd, "status_code", 0) == 401 and mail_client:
                    self._log("log-in password/verify -> 401，尝试 passwordless/send-otp")
                    baseline_ids = set()
                    if hasattr(mail_client, "snapshot_openai_message_ids"):
                        try:
                            baseline_ids = set(mail_client.snapshot_openai_message_ids(email) or set())
                        except Exception:
                            baseline_ids = set()
                    headers_pwdless = {
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Referer": password_page_url,
                        "Origin": self.oauth_issuer,
                        "oai-device-id": device_id,
                        "User-Agent": user_agent or "Mozilla/5.0",
                    }
                    headers_pwdless.update(generate_datadog_trace())
                    try:
                        resp_pwdless = self._oauth_request(
                            "POST",
                            f"{self.oauth_issuer}/api/accounts/passwordless/send-otp",
                            json={},
                            headers=headers_pwdless,
                            timeout=30,
                            allow_redirects=False,
                            impersonate=impersonate,
                        )
                        self._log(f"log-in passwordless/send-otp -> {getattr(resp_pwdless, 'status_code', 0)}")
                        if getattr(resp_pwdless, "status_code", 0) in (200, 201, 204):
                            try:
                                pwdless_data = resp_pwdless.json()
                            except Exception:
                                pwdless_data = {}
                            pwdless_continue_url = self._normalize_continue_url(self._extract_continue_url_from_json(pwdless_data), password_page_url)
                            pwdless_page_type = str(((pwdless_data.get("page") or {}) if isinstance(pwdless_data, dict) else {}).get("type") or "").strip()
                            pwdless_low = (pwdless_continue_url or "").lower()
                            if pwdless_page_type.lower() in {"email_otp_verification", "contact_verification"} or "email-verification" in pwdless_low or "email-otp" in pwdless_low:
                                next_url = self._oauth_complete_email_otp_for_continue(
                                    email=email,
                                    device_id=device_id,
                                    user_agent=user_agent,
                                    impersonate=impersonate,
                                    mail_client=mail_client,
                                    mfa_client=mfa_client,
                                    continue_url=pwdless_continue_url or continue_url or password_page_url,
                                    page_type=pwdless_page_type,
                                    baseline_message_ids=baseline_ids,
                                )
                                if next_url:
                                    return next_url
                            if pwdless_continue_url:
                                return pwdless_continue_url
                    except Exception as exc:
                        self._log(f"log-in passwordless/send-otp 异常: {type(exc).__name__}")
                return ""
            try:
                data = resp_pwd.json()
            except Exception:
                data = {}
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_json(data), password_page_url)
            page_type = str(((data.get("page") or {}) if isinstance(data, dict) else {}).get("type") or page_type).strip()
            page_low = page_type.lower()
            url_low = (continue_url or "").lower()

        if self._is_mfa_challenge(page_type, continue_url, data):
            return self._oauth_complete_totp_mfa_for_continue(
                device_id=device_id,
                user_agent=user_agent,
                impersonate=impersonate,
                mfa_client=mfa_client,
                current_url=continue_url or current_url,
                response_data=data,
            )

        if page_low in {"email_otp_verification", "contact_verification"} or "email-verification" in url_low or "email-otp" in url_low:
            if not mail_client:
                self._log("log-in 分支需要邮箱 OTP，但没有 mail_client")
                return continue_url or ""
            baseline_ids = set()
            if hasattr(mail_client, "snapshot_openai_message_ids"):
                try:
                    baseline_ids = set(mail_client.snapshot_openai_message_ids(email) or set())
                except Exception:
                    baseline_ids = set()
            return self._oauth_complete_email_otp_for_continue(
                email=email,
                device_id=device_id,
                user_agent=user_agent,
                impersonate=impersonate,
                mail_client=mail_client,
                mfa_client=mfa_client,
                continue_url=continue_url,
                page_type=page_type,
                baseline_message_ids=baseline_ids,
            )

        if ("add_phone" in page_low or "phone" in page_low or "add-phone" in url_low or "phone-verification" in url_low):
            return self._oauth_complete_add_phone_for_continue(email, device_id, user_agent, impersonate, sms_client, continue_url or current_url)

        return continue_url or ""

    def _oauth_complete_email_otp_for_continue(self, *, email, device_id, user_agent, impersonate, mail_client, continue_url, page_type, baseline_message_ids=None, mfa_client=None):
        tried_codes = set()
        snapshot_ids = set(baseline_message_ids or set())
        if hasattr(mail_client, "capture_openai_baseline"):
            try:
                snapshot_ids.update(mail_client.capture_openai_baseline(email=email, quiet=False) or set())
            except Exception:
                pass

        resend_headers = {
            "Accept": "application/json",
            "Origin": self.oauth_issuer,
            "Referer": self._normalize_continue_url(continue_url, self.oauth_issuer) or f"{self.oauth_issuer}/email-verification",
            "User-Agent": user_agent or "Mozilla/5.0",
            "oai-device-id": device_id,
        }
        resend_headers.update(generate_datadog_trace())

        def _request_email_otp():
            last_error = ""
            for path in (
                "/api/accounts/email-otp/resend",
                "/api/accounts/email-otp/send",
            ):
                try:
                    resp = self._oauth_request(
                        "POST",
                        f"{self.oauth_issuer}{path}",
                        headers=resend_headers,
                        timeout=30,
                        allow_redirects=False,
                        json={},
                        impersonate=impersonate,
                    )
                    self._log(
                        "log-in OTP 触发发码 "
                        f"{path} -> {getattr(resp, 'status_code', 0)}"
                    )
                    if getattr(resp, "status_code", 0) in (
                        200,
                        201,
                        204,
                    ):
                        mail_client.manual_resend_error = ""
                        return True
                    last_error = (
                        "OpenAI 重发接口返回 "
                        f"HTTP {getattr(resp, 'status_code', 0)}"
                    )
                except Exception as exc:
                    last_error = (
                        "OpenAI 重发接口异常："
                        f"{type(exc).__name__}"
                    )
                    self._log(
                        "log-in OTP 触发发码 "
                        f"{path} 异常: {type(exc).__name__}"
                    )
            mail_client.manual_resend_error = (
                last_error or "OpenAI 重发接口未返回成功"
            )
            return False

        _request_email_otp()

        headers_otp = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": self._normalize_continue_url(continue_url, self.oauth_issuer) or f"{self.oauth_issuer}/email-verification",
            "Origin": self.oauth_issuer,
            "oai-device-id": device_id,
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        headers_otp.update(generate_datadog_trace())
        max_attempts = max(1, int(getattr(self, "email_otp_max_attempts", 3) or 3))
        deadline = time.time() + self.email_otp_timeout
        attempt = 0
        while time.time() < deadline and attempt < max_attempts:
            remaining = max(1, int(deadline - time.time()))
            missing_resend_provider = object()
            previous_resend_provider = getattr(
                mail_client,
                "manual_resend_provider",
                missing_resend_provider,
            )
            mail_client.manual_resend_provider = _request_email_otp
            try:
                if hasattr(mail_client, "wait_for_new_verification_code"):
                    otp_code = mail_client.wait_for_new_verification_code(
                        email,
                        timeout=remaining,
                        exclude_codes=tried_codes,
                        exclude_message_ids=snapshot_ids,
                    )
                else:
                    otp_code = mail_client.wait_for_verification_code(
                        email,
                        timeout=remaining,
                        exclude_codes=tried_codes,
                    )
            finally:
                if previous_resend_provider is missing_resend_provider:
                    try:
                        delattr(mail_client, "manual_resend_provider")
                    except AttributeError:
                        pass
                else:
                    mail_client.manual_resend_provider = (
                        previous_resend_provider
                    )
            if not otp_code:
                fallback = getattr(mail_client, "get_latest_verification_code_fallback", None)
                if callable(fallback):
                    otp_code = fallback(
                        email,
                        exclude_codes=tried_codes,
                        exclude_message_ids=snapshot_ids,
                    )
            if not otp_code:
                break
            otp_code = str(otp_code).strip()
            if not re.fullmatch(r"\d{6}", otp_code):
                self._log(f"log-in OTP 忽略非 6 位候选码: {otp_code}")
                tried_codes.add(otp_code)
                continue
            attempt += 1
            tried_codes.add(otp_code)
            resp_otp = self._oauth_request(
                "POST",
                f"{self.oauth_issuer}/api/accounts/email-otp/validate",
                json={"code": str(otp_code).strip()},
                headers=headers_otp,
                timeout=30,
                allow_redirects=False,
                impersonate=impersonate,
            )
            status = getattr(resp_otp, "status_code", 0)
            body_preview = (getattr(resp_otp, "text", "") or "")[:180].replace("\n", "\\n")
            self._log(f"log-in email-otp/validate attempt={attempt}/{max_attempts} -> {status}")
            if status != 200:
                if body_preview:
                    self._log(f"log-in OTP 返回: {body_preview}")
                if status in (401, 403, 409):
                    self.last_oauth_error = f"email_otp_rejected_{status}"
                    manual_provider = getattr(
                        mail_client,
                        "manual_code_provider",
                        None,
                    )
                    if (
                        callable(manual_provider)
                        and attempt < max_attempts
                        and time.time() < deadline
                    ):
                        resend_ok = _request_email_otp()
                        mail_client.manual_prompt_reason = (
                            "验证码未通过并已重新发送，"
                            "自动刷新 30 秒仍未获取有效验证码"
                            if resend_ok
                            else
                            "验证码未通过，重新发送未确认成功，"
                            "自动刷新 30 秒仍未获取有效验证码"
                        )
                        progress = getattr(mail_client, "progress", None)
                        emitter = getattr(progress, "emit", None)
                        if callable(emitter):
                            emitter(
                                "LINK",
                                (
                                    "验证码未通过，已重新发送；"
                                    "继续自动刷新 30 秒"
                                    if resend_ok
                                    else
                                    "验证码未通过，重新发送未确认成功；"
                                    "继续自动刷新 30 秒"
                                ),
                            )
                        continue
                    break
                if status == 429:
                    self.last_oauth_error = "email_otp_rejected_429"
                    break
                continue
            try:
                data = resp_otp.json()
            except Exception:
                data = {}
            next_url = self._normalize_continue_url(self._extract_continue_url_from_json(data), continue_url)
            if not hasattr(mail_client, "_used_codes"):
                mail_client._used_codes = set()
            mail_client._used_codes.add(otp_code)
            if self._is_mfa_challenge(
                self._oauth_page_type(data),
                next_url,
                data,
            ):
                return self._oauth_complete_totp_mfa_for_continue(
                    device_id=device_id,
                    user_agent=user_agent,
                    impersonate=impersonate,
                    mfa_client=mfa_client,
                    current_url=next_url or continue_url,
                    response_data=data,
                )
            return next_url or continue_url or ""
        self._log(f"log-in OTP 验证失败，已尝试 {attempt} 个 6 位验证码")
        return ""

    def _oauth_choose_account_select(self, html_text, current_url, user_agent, impersonate):
        """处理 OpenAI OAuth 多账号选择页，返回下一跳 URL。"""
        import re
        session_match = re.search(r"us_[A-Za-z0-9]{16,}", html_text or "")
        if not session_match:
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": user_agent or "Mozilla/5.0",
                "Referer": "https://chatgpt.com/",
            }
            try:
                kwargs = {"headers": headers, "allow_redirects": False, "timeout": 30}
                r = self._oauth_request("GET", current_url, impersonate=impersonate, **kwargs)
                html_text = getattr(r, "text", "") or ""
                session_match = re.search(r"us_[A-Za-z0-9]{16,}", html_text)
                self._log(f"choose-an-account 页面刷新 -> {getattr(r, 'status_code', 'N/A')}")
            except Exception as exc:
                self._log(f"choose-an-account 页面读取异常: {type(exc).__name__}: {str(exc)[:100]}")
                return ""
        if not session_match:
            self._log("choose-an-account 未找到可选账号 session")
            return ""

        session_id = session_match.group(0)
        self._log("choose-an-account 选择已登录账号")
        base_headers = {
            "Origin": self.oauth_issuer,
            "Referer": f"{self.oauth_issuer}/choose-an-account",
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        candidates = [
            (f"{self.oauth_issuer}/api/accounts/session/select", {"session_id": session_id}, "json"),
            (f"{self.oauth_issuer}/choose-an-account", {"intent": "select", "session_id": session_id}, "form"),
        ]
        for url, body, kind in candidates:
            try:
                headers = dict(base_headers)
                if kind == "json":
                    headers.update({"Accept": "application/json", "Content-Type": "application/json"})
                    kwargs = {"headers": headers, "json": body, "allow_redirects": False, "timeout": 30}
                else:
                    headers.update({"Accept": "application/json, text/html;q=0.9", "Content-Type": "application/x-www-form-urlencoded"})
                    form_body = "&".join(f"{k}={v}" for k, v in body.items())
                    kwargs = {"headers": headers, "data": form_body, "allow_redirects": False, "timeout": 30}
                resp = self._oauth_request("POST", url, impersonate=impersonate, **kwargs)
                status = getattr(resp, "status_code", 0)
                self._log(f"choose-an-account {kind} -> {status}")
                next_url = ""
                if status in (200, 201, 302, 303, 307, 308):
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            next_url = data.get("continue_url", "") or data.get("url", "") or ""
                    except Exception:
                        pass
                    if not next_url:
                        next_url = (resp.headers.get("Location", "") or resp.headers.get("location", "") or "").strip()
                    if next_url.startswith("/"):
                        next_url = f"{self.oauth_issuer}{next_url}"
                    if next_url:
                        return next_url
                    if status == 200:
                        return current_url
            except Exception as exc:
                self._log(f"choose-an-account {kind} 异常: {type(exc).__name__}: {str(exc)[:100]}")
        return ""

    def _extract_code_from_url(self, url):
        """从 URL 中提取 code"""
        if not url or "code=" not in url:
            return None
        try:
            return parse_qs(urlparse(url).query).get("code", [None])[0]
        except Exception:
            return None

    def _extract_state_from_url(self, url):
        if not url or "state=" not in url:
            return ""
        try:
            return parse_qs(urlparse(url).query).get("state", [""])[0] or ""
        except Exception:
            return ""

    def _oauth_follow_for_code(self, start_url, referer, user_agent, impersonate, max_hops=16):
        """跟随 URL 获取 authorization code（手动跟随重定向）"""
        import re
        
        # 先检查 URL 中是否已经包含 code
        if "code=" in start_url:
            code = self._extract_code_from_url(start_url)
            if code:
                return code, start_url
        
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        if referer:
            headers["Referer"] = referer
        
        current_url = start_url
        last_url = start_url
        
        for hop in range(max_hops):
            try:
                kwargs = {"headers": headers, "allow_redirects": False, "timeout": 30}
                if impersonate:
                    kwargs["impersonate"] = impersonate
                
                r = self.session.get(current_url, **kwargs)
                last_url = str(r.url)
                self._log(f"follow[{hop+1}] {r.status_code} {last_url[:80]}")
                
            except Exception as e:
                # 从异常中提取 localhost URL
                maybe_localhost = re.search(r'(https?://localhost[^\s\'\"]+)', str(e))
                if maybe_localhost:
                    code = self._extract_code_from_url(maybe_localhost.group(1))
                    if code:
                        self._log("从 localhost 异常提取到 code")
                        return code, maybe_localhost.group(1)
                self._log(f"follow[{hop+1}] 异常: {str(e)[:100]}")
                return None, last_url
            
            # 检查当前 URL
            code = self._extract_code_from_url(last_url)
            if code:
                return code, last_url
            
            # 检查重定向
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("Location", "")
                if not location:
                    return None, last_url
                
                if location.startswith("/"):
                    location = f"{self.oauth_issuer}{location}"
                
                code = self._extract_code_from_url(location)
                if code:
                    return code, location
                
                current_url = location
                headers["Referer"] = last_url
            else:
                # 不是重定向，立即返回（原始代码的逻辑）
                return None, last_url
        
        return None, last_url
    
    def _oauth_submit_workspace_and_org(self, consent_url, device_id, user_agent, impersonate, max_retries=3):
        """提交 workspace 和 organization 选择（带重试）"""
        session_data = None
        
        # 尝试多次解码 cookie
        for attempt in range(max_retries):
            session_data = self._decode_oauth_session_cookie()
            if session_data:
                break
            
            if attempt < max_retries - 1:
                self._log(f"无法解码 oai-client-auth-session (尝试 {attempt + 1}/{max_retries})")
                time.sleep(0.3)  # 短暂延迟后重试
                
                # 重新访问 consent URL 以确保 cookie 被设置
                try:
                    headers = {
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "User-Agent": user_agent or "Mozilla/5.0",
                    }
                    kwargs = {"headers": headers, "allow_redirects": False, "timeout": 30}
                    if impersonate:
                        kwargs["impersonate"] = impersonate
                    self.session.get(consent_url, **kwargs)
                except Exception:
                    pass
            else:
                self._log("无法解码 oai-client-auth-session")
                return None
        
        workspaces = session_data.get("workspaces", [])
        if not workspaces:
            self._log("session 中没有 workspace 信息")
            return None
        
        workspace_id = (workspaces[0] or {}).get("id")
        if not workspace_id:
            self._log("workspace_id 为空")
            return None
        
        self._log(f"选择 workspace: {workspace_id}")
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": self.oauth_issuer,
            "Referer": consent_url,
            "User-Agent": user_agent or "Mozilla/5.0",
            "oai-device-id": device_id,
        }
        headers.update(generate_datadog_trace())
        
        try:
            kwargs = {
                "json": {"workspace_id": workspace_id},
                "headers": headers,
                "allow_redirects": False,
                "timeout": 30
            }
            if impersonate:
                kwargs["impersonate"] = impersonate
            
            r = self.session.post(
                f"{self.oauth_issuer}/api/accounts/workspace/select",
                **kwargs
            )
            
            self._log(f"workspace/select -> {r.status_code}")
            
            # 检查重定向
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("Location", "")
                if location.startswith("/"):
                    location = f"{self.oauth_issuer}{location}"
                if "code=" in location:
                    code = self._extract_code_from_url(location)
                    if code:
                        self._log("从 workspace/select 重定向获取到 code")
                        return code
            
            # 如果返回 200，检查响应中的 orgs
            if r.status_code == 200:
                try:
                    data = r.json()
                    orgs = data.get("data", {}).get("orgs", [])
                    continue_url = data.get("continue_url", "")
                    
                    if orgs:
                        org_id = (orgs[0] or {}).get("id")
                        projects = (orgs[0] or {}).get("projects", [])
                        project_id = (projects[0] or {}).get("id") if projects else None
                        
                        if org_id:
                            self._log(f"选择 organization: {org_id}")
                            
                            org_body = {"org_id": org_id}
                            if project_id:
                                org_body["project_id"] = project_id
                            
                            headers["Referer"] = continue_url if continue_url and continue_url.startswith("http") else consent_url
                            
                            kwargs = {
                                "json": org_body,
                                "headers": headers,
                                "allow_redirects": False,
                                "timeout": 30
                            }
                            if impersonate:
                                kwargs["impersonate"] = impersonate
                            
                            r_org = self.session.post(
                                f"{self.oauth_issuer}/api/accounts/organization/select",
                                **kwargs
                            )
                            
                            self._log(f"organization/select -> {r_org.status_code}")
                            
                            # 检查重定向
                            if r_org.status_code in (301, 302, 303, 307, 308):
                                location = r_org.headers.get("Location", "")
                                if location.startswith("/"):
                                    location = f"{self.oauth_issuer}{location}"
                                if "code=" in location:
                                    code = self._extract_code_from_url(location)
                                    if code:
                                        self._log("从 organization/select 重定向获取到 code")
                                        return code
                            
                            # 检查 continue_url
                            if r_org.status_code == 200:
                                try:
                                    org_data = r_org.json()
                                    org_continue_url = org_data.get("continue_url", "")
                                    org_page = org_data.get("page", {}).get("type", "")
                                    self._log(f"organization/select page={org_page or '-'} continue_url={org_continue_url[:80] if org_continue_url else 'None'}...")
                                    
                                    if org_continue_url:
                                        if org_continue_url.startswith("/"):
                                            org_continue_url = f"{self.oauth_issuer}{org_continue_url}"
                                        # 跟随 continue_url
                                        code, _ = self._oauth_follow_for_code(org_continue_url, headers["Referer"], user_agent, impersonate)
                                        if code:
                                            return code
                                except Exception as e:
                                    self._log(f"解析 organization/select 响应异常: {e}")
                    
                    # 如果有 continue_url，跟随它
                    if continue_url:
                        if continue_url.startswith("/"):
                            continue_url = f"{self.oauth_issuer}{continue_url}"
                        code, _ = self._oauth_follow_for_code(continue_url, headers["Referer"], user_agent, impersonate)
                        if code:
                            return code
                        
                except Exception as e:
                    self._log(f"处理 workspace/select 响应异常: {e}")
        
        except Exception as e:
            self._log(f"workspace/select 异常: {e}")
        
        return None
    
    def _decode_oauth_session_cookie(self):
        """解码 oai-client-auth-session cookie"""
        from urllib.parse import unquote

        def _with_padding(raw):
            return raw + ("=" * ((4 - len(raw) % 4) % 4))

        def _try_parse_json(raw_text):
            try:
                data = json.loads(raw_text)
                return data if isinstance(data, dict) else None
            except Exception:
                return None

        def _normalize_session_dict(data):
            if not isinstance(data, dict):
                return None
            if isinstance(data.get("client_auth_session"), dict):
                return data.get("client_auth_session")
            return data

        def _decode_candidates(raw_value):
            text = (raw_value or "").strip()
            if not text:
                return None

            candidates = []

            # 原始值、去引号值、URL decode 后的值都尝试一遍
            candidates.append(text)
            candidates.append(text.strip("\"'"))
            if text.startswith("s:"):
                candidates.append(text[2:])

            unquoted = unquote(text)
            if unquoted != text:
                candidates.append(unquoted)
                candidates.append(unquoted.strip("\"'"))
                if unquoted.startswith("s:"):
                    candidates.append(unquoted[2:])

            # 如果像 JWT / JWE，尝试分段 base64 解码
            for seed in list(candidates):
                if seed and seed.count(".") >= 1:
                    for part in seed.split("."):
                        if part:
                            candidates.append(part)

            seen = set()
            for candidate in candidates:
                if not candidate or candidate in seen:
                    continue
                seen.add(candidate)

                # 1. 直接就是 JSON
                parsed = _normalize_session_dict(_try_parse_json(candidate))
                if parsed:
                    return parsed

                # 2/3. 标准/URL-safe base64 + 可选 zlib/gzip
                for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                    try:
                        blob = decoder(_with_padding(candidate))
                    except Exception:
                        continue

                    for raw in (blob,):
                        try:
                            parsed = _normalize_session_dict(_try_parse_json(raw.decode("utf-8")))
                            if parsed:
                                return parsed
                        except Exception:
                            pass

                        for decomp in (zlib.decompress, gzip.decompress):
                            try:
                                inflated = decomp(raw).decode("utf-8")
                                parsed = _normalize_session_dict(_try_parse_json(inflated))
                                if parsed:
                                    return parsed
                            except Exception:
                                pass

            return None

        def _iter_cookie_triplets():
            cookie_store = getattr(self.session, "cookies", None)
            if cookie_store is None:
                return

            try:
                for name, value in cookie_store.items():
                    yield "", str(name or ""), str(value or "")
            except Exception:
                pass

            jar = getattr(cookie_store, "jar", None)
            if jar is not None:
                try:
                    for cookie in jar:
                        yield (
                            getattr(cookie, "domain", "") or "",
                            getattr(cookie, "name", "") or str(cookie),
                            getattr(cookie, "value", "") or "",
                        )
                except Exception:
                    pass
        
        try:
            found_cookie = False
            preview_logged = False
            for domain, name, value in _iter_cookie_triplets():
                try:
                    if name == "oai-client-auth-session":
                        found_cookie = True
                        if value:
                            if not preview_logged:
                                self._log(f"oai-client-auth-session@{domain or '-'} len={len(value)}")
                                preview_logged = True
                            data = _decode_candidates(value)
                            if data:
                                return data
                except Exception:
                    continue
            if not found_cookie:
                self._log("cookie 中未找到 oai-client-auth-session")
            else:
                self._log("oai-client-auth-session 存在，但无法按已知格式解码")
        except Exception:
            pass

        # 回退：直接读 dump 接口，至少拿到 client_auth_session 本体
        try:
            headers = {
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
                "Referer": f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent",
                "Origin": self.oauth_issuer,
            }
            r = self.session.get(
                f"{self.oauth_issuer}/api/accounts/client_auth_session_dump",
                headers=headers,
                timeout=30,
            )
            if r.status_code == 200:
                raw = r.json()
                parsed = _normalize_session_dict(raw)
                if parsed:
                    checksum = raw.get("checksum") if isinstance(raw, dict) else None
                    if checksum:
                        try:
                            self._log(f"client_auth_session_dump checksum={base64.b64decode(_with_padding(checksum)).decode('utf-8', errors='ignore')}")
                        except Exception:
                            pass
                    return parsed
        except Exception as e:
            self._log(f"client_auth_session_dump 回退异常: {e}")
        
        return None
    
    def _exchange_code_for_tokens(self, code, code_verifier, user_agent, impersonate):
        """用 authorization code 换取 tokens"""
        url = f"{self.oauth_issuer}/oauth/token"
        
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.oauth_redirect_uri,
            "client_id": self.oauth_client_id,
            "code_verifier": code_verifier,
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        
        try:
            kwargs = {"data": payload, "headers": headers, "timeout": 60}
            if impersonate:
                kwargs["impersonate"] = impersonate
            
            r = self.session.post(url, **kwargs)
            
            if r.status_code == 200:
                return r.json()
            else:
                self._log(f"换取 tokens 失败: {r.status_code} - {r.text[:200]}")
                
        except Exception as e:
            self._log(f"换取 tokens 异常: {e}")
        
        return None

    def probe_chatgpt_session_context(self, email, device_id, user_agent=None, impersonate=None):
        """提取当前成功注册号的 ChatGPT session 现场"""
        headers = {
            "Accept": "application/json",
            "User-Agent": user_agent or "Mozilla/5.0",
            "Referer": "https://chatgpt.com/",
            "Origin": "https://chatgpt.com",
        }

        result = {
            "email": email,
            "device_id": device_id,
            "captured_at": int(time.time()),
            "cookies": [],
            "chatgpt_auth_session": None,
            "accounts_check": None,
            "client_auth_session_dump": None,
            "codex_consent_follow": None,
            "errors": [],
        }

        try:
            cookies = []
            try:
                for name, value in self.session.cookies.items():
                    cookies.append({
                        "domain": "",
                        "name": str(name or ""),
                        "value": str(value or ""),
                    })
            except Exception:
                pass

            jar = getattr(self.session.cookies, "jar", None)
            if jar is not None:
                try:
                    for cookie in jar:
                        cookies.append({
                            "domain": getattr(cookie, "domain", "") or "",
                            "name": getattr(cookie, "name", "") or str(cookie),
                            "value": getattr(cookie, "value", "") or "",
                        })
                except Exception:
                    pass

            dedup = {}
            for item in cookies:
                key = (item.get("domain", ""), item.get("name", ""))
                if key not in dedup or item.get("value"):
                    dedup[key] = item
            result["cookies"] = list(dedup.values())
        except Exception as e:
            result["errors"].append(f"cookies: {e}")

        def _get_json(url, headers_override=None):
            try:
                kwargs = {
                    "headers": headers_override or headers,
                    "timeout": 30,
                    "allow_redirects": True,
                }
                if impersonate:
                    kwargs["impersonate"] = impersonate
                r = self.session.get(url, **kwargs)
                body_text = r.text[:4000] if hasattr(r, "text") else ""
                try:
                    body_json = r.json()
                except Exception:
                    body_json = None
                return {
                    "url": str(r.url),
                    "status_code": r.status_code,
                    "headers": dict(r.headers),
                    "json": body_json,
                    "text": body_text,
                }
            except Exception as e:
                result["errors"].append(f"{url}: {e}")
                return None

        result["chatgpt_auth_session"] = _get_json("https://chatgpt.com/api/auth/session")

        bearer = None
        try:
            bearer = (((result.get("chatgpt_auth_session") or {}).get("json") or {}).get("accessToken"))
        except Exception:
            bearer = None

        check_headers = dict(headers)
        if bearer:
            check_headers["Authorization"] = f"Bearer {bearer}"
            result["access_token_preview"] = f"{bearer[:24]}..." if len(bearer) > 24 else bearer

        result["accounts_check"] = _get_json(
            "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27",
            check_headers,
        )

        # 访问 Codex consent，看看是否能把 auth 会话升级出 workspaces
        try:
            consent_headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "User-Agent": user_agent or "Mozilla/5.0",
                "Referer": "https://chatgpt.com/",
            }
            kwargs = {
                "headers": consent_headers,
                "timeout": 30,
                "allow_redirects": True,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate
            r = self.session.get(f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent", **kwargs)
            result["codex_consent_follow"] = {
                "url": str(r.url),
                "status_code": r.status_code,
                "history": [str(x.url) for x in getattr(r, "history", []) or []],
                "text": (r.text[:2000] if hasattr(r, "text") else ""),
            }
        except Exception as e:
            result["errors"].append(f"codex_consent_follow: {e}")

        result["client_auth_session_dump"] = _get_json(
            f"{self.oauth_issuer}/api/accounts/client_auth_session_dump",
            {
                "Accept": "application/json",
                "User-Agent": user_agent or "Mozilla/5.0",
                "Referer": f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent",
                "Origin": self.oauth_issuer,
            },
        )

        # 尝试从 dump 里直接提取 workspace/org 线索
        dump_json = ((result.get("client_auth_session_dump") or {}).get("json") or {})
        if isinstance(dump_json, dict):
            session_obj = dump_json.get("client_auth_session") if isinstance(dump_json.get("client_auth_session"), dict) else dump_json
            summary = {}
            for key in ("app_name_enum", "openai_client_id", "email_verification_mode", "workspaces", "organizations", "projects"):
                if key in session_obj:
                    summary[key] = session_obj.get(key)
            if "checksum" in dump_json:
                summary["checksum"] = dump_json.get("checksum")
            result["client_auth_session_summary"] = summary

        return result
    
    def _oauth_try_complete_about_you(self, email, continue_url, device_id, user_agent, impersonate):
        """处理 about_you 分支，补齐 create_account 步骤"""
        referer = self._normalize_oauth_url(continue_url) or f"{self.oauth_issuer}/about-you"
        first = (email.split("@")[0] or "Alex").replace(".", " ").replace("_", " ").strip() or "Alex"
        first_name = first.split()[0][:16] or "Alex"
        last_name = "User"
        payload = {"name": f"{first_name} {last_name}", "birthdate": "1998-01-01"}
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": referer,
            "Origin": self.oauth_issuer,
            "oai-device-id": device_id,
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        headers.update(generate_datadog_trace())
        try:
            kwargs = {"json": payload, "headers": headers, "timeout": 30, "allow_redirects": False}
            if impersonate:
                kwargs["impersonate"] = impersonate
            r = self.session.post(f"{self.oauth_issuer}/api/accounts/create_account", **kwargs)
            self._log(f"about_you/create_account -> {r.status_code}")
            return r.status_code in (200, 400) and ("user_already_exists" in (r.text or "") or r.status_code == 200)
        except Exception as e:
            self._log(f"about_you/create_account 异常: {e}")
            return False

    def _oauth_try_complete_add_phone(self, email, device_id, user_agent, impersonate, mail_client):
        """处理 add_phone 分支（依赖具备 buy_number/get_sms_code 的客户端）"""
        if not mail_client or not all(hasattr(mail_client, x) for x in ("buy_number", "get_sms_code")):
            self._log("add_phone 分支：当前 mail_client 不支持短信能力")
            return False

        country = getattr(mail_client, "country", "france")
        operator = getattr(mail_client, "operator", None)
        try:
            max_phone_attempts = int(getattr(mail_client, "max_phone_attempts", 3) or 3)
            if callable(
                getattr(mail_client, "handle_explicit_phone_rejection", None)
            ):
                replacement_limit = max(
                    0,
                    int(
                        getattr(
                            mail_client,
                            "max_phone_replacements_per_oauth_session",
                            2,
                        )
                        or 0
                    ),
                )
                max_phone_attempts = min(
                    max_phone_attempts,
                    replacement_limit + 1,
                )
            saw_number_rejected = False
            for phone_attempt in range(1, max(1, max_phone_attempts) + 1):
                phone, order_id = mail_client.buy_number(country=country, operator=operator)
                if not phone:
                    self._log("add_phone 分支：购买手机号失败")
                    return False
                baseline_codes = set()
                if hasattr(mail_client, "snapshot_sms_codes"):
                    baseline_codes = set(mail_client.snapshot_sms_codes(order_id) or set())
                phone_digits = re.sub(r"\D", "", str(phone or ""))
                submit_phone = f"+1{phone_digits}" if len(phone_digits) == 10 else str(phone or "").strip()

                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Referer": f"{self.oauth_issuer}/add-phone",
                    "Origin": self.oauth_issuer,
                    "oai-device-id": device_id,
                    "User-Agent": user_agent or "Mozilla/5.0",
                }
                headers.update(generate_datadog_trace())
                kwargs = {"json": {"phone_number": submit_phone}, "headers": headers, "timeout": 30, "allow_redirects": False}
                if impersonate:
                    kwargs["impersonate"] = impersonate
                r1 = self.session.post(f"{self.oauth_issuer}/api/accounts/add-phone/send", **kwargs)
                body1 = (getattr(r1, "text", "") or "")[:500]
                body1_low = body1.lower()
                self._log(f"add_phone/send attempt={phone_attempt}/{max_phone_attempts} -> {r1.status_code} {body1[:180]}")
                send_details = (
                    self._record_sms_phone_error(mail_client, r1, "send")
                    if r1.status_code != 200
                    else {}
                )
                send_code = str(
                    (send_details or {}).get("code") or ""
                ).lower()
                send_type = str(
                    (send_details or {}).get("type") or ""
                ).lower()
                number_rejected = (
                    "unable to send" in body1_low and "verification code" in body1_low
                ) or (
                    "try again later" in body1_low and "different number" in body1_low
                ) or send_code in {
                    "phone_max_usage_exceeded",
                    "phone_number_invalid",
                    "phone_number_not_supported",
                    "phone_number_in_use",
                    "phone_verification_send_failed",
                }
                if r1.status_code != 200:
                    session_invalid = (
                        send_code in {"invalid_auth_step", "invalid_state"}
                        or send_type in {"invalid_auth_step", "invalid_state"}
                        or "invalid_auth_step" in body1_low
                        or "session is no longer valid" in body1_low
                    )
                    if session_invalid:
                        handler = getattr(
                            mail_client,
                            "mark_oauth_session_invalid",
                            None,
                        )
                        if callable(handler):
                            handler(order_id)
                        raise RuntimeError(
                            "oauth_session_invalid: invalid_auth_step"
                        )
                    if (
                        r1.status_code == 429
                        or send_code in {
                            "rate_limit_exceeded",
                            "phone_verification_rate_limited",
                        }
                        or "too many phone verification requests" in body1_low
                    ):
                        raise RuntimeError(
                            "oauth_phone_send_rate_limited: "
                            + (send_code or "rate_limit_exceeded")
                        )
                    if number_rejected:
                        saw_number_rejected = True
                        rejection_action = self._handle_explicit_phone_rejection(
                            mail_client,
                            order_id,
                            send_code or "add_phone_number_rejected",
                        )
                        if rejection_action == "continue":
                            self._log(
                                "add_phone 号码被拒绝，已在当前 OAuth 会话内更换手机号"
                            )
                            continue
                        if rejection_action == "rollover":
                            raise RuntimeError(
                                "oauth_phone_session_rollover_required: "
                                + (send_code or "add_phone_number_rejected")
                            )
                        self._log("add_phone 号码被拒绝，隔离并更换手机号")
                        raise RuntimeError(
                            "oauth_phone_number_change_required: "
                            "add_phone_number_rejected"
                        )
                    raise RuntimeError(
                        "oauth_phone_retry_same_number: "
                        + (send_code or f"add_phone_send_http_{r1.status_code}")
                    )

                try:
                    code = mail_client.get_sms_code(
                        order_id,
                        timeout=int(getattr(mail_client, "sms_timeout", 120) or 120),
                        exclude_codes=baseline_codes,
                    )
                except TypeError:
                    code = mail_client.get_sms_code(order_id, timeout=int(getattr(mail_client, "sms_timeout", 120) or 120))
                if not code:
                    self._log("add_phone 分支：未收到短信验证码，更换手机号")
                    if bool(
                        getattr(mail_client, "change_number_requested", False)
                    ):
                        raise RuntimeError(
                            "oauth_phone_number_change_required: "
                            "add_phone_sms_timeout"
                        )
                    if bool(
                        getattr(mail_client, "yield_job_after_attempt", False)
                    ):
                        raise RuntimeError(
                            "oauth_phone_retry_same_number: "
                            "add_phone_sms_timeout"
                        )
                    if hasattr(mail_client, "cancel_order"):
                        mail_client.cancel_order(order_id)
                    raise RuntimeError(
                        "oauth_phone_number_change_required: "
                        "add_phone_sms_timeout"
                    )

                headers["Referer"] = f"{self.oauth_issuer}/phone-verification"
                kwargs2 = {"json": {"code": str(code).strip()}, "headers": headers, "timeout": 30, "allow_redirects": False}
                if impersonate:
                    kwargs2["impersonate"] = impersonate
                r2 = self.session.post(f"{self.oauth_issuer}/api/accounts/phone-otp/validate", **kwargs2)
                self._log(f"phone-otp/validate -> {r2.status_code}")

                if hasattr(mail_client, "finish_order") and r2.status_code == 200:
                    mail_client.finish_order(order_id)
                    return True
                validation_details = self._record_sms_phone_error(
                    mail_client,
                    r2,
                    "validate",
                ) if r2.status_code != 200 else {}
                validation_code = str(
                    (validation_details or {}).get("code") or ""
                ).lower()
                validation_type = str(
                    (validation_details or {}).get("type") or ""
                ).lower()
                validation_message = str(
                    (validation_details or {}).get("message") or ""
                ).lower()
                if (
                    validation_code in {"invalid_state", "invalid_auth_step"}
                    or validation_type in {"invalid_state", "invalid_auth_step"}
                    or "session is no longer valid" in validation_message
                ):
                    handler = getattr(
                        mail_client,
                        "mark_oauth_session_invalid",
                        None,
                    )
                    if callable(handler):
                        handler(order_id)
                    raise RuntimeError("oauth_session_invalid")
                if (
                    validation_code in {
                        "phone_number_invalid",
                        "phone_number_not_supported",
                        "phone_number_in_use",
                        "phone_max_usage_exceeded",
                    }
                    or "different number" in validation_message
                ):
                    if hasattr(mail_client, "mark_order_abnormal"):
                        mail_client.mark_order_abnormal(order_id)
                    raise RuntimeError(
                        "oauth_phone_number_change_required: "
                        + (validation_code or "phone_otp_validate_rejected")
                    )
                if bool(getattr(mail_client, "sms_consumed", False)):
                    raise RuntimeError(
                        "oauth_phone_number_change_required: "
                        + (validation_code or "phone_otp_validate_failed")
                    )
                raise RuntimeError(
                    "oauth_phone_retry_same_number: "
                    + (validation_code or "phone_otp_validate_failed")
                )
            if saw_number_rejected:
                raise RuntimeError("add_phone_number_rejected")
            return False
        except RuntimeError as e:
            self._log(f"add_phone 分支异常: {e}")
            if any(
                marker in str(e)
                for marker in (
                    "add_phone_number_rejected",
                    "oauth_phone_number_change_required",
                    "oauth_phone_retry_same_number",
                    "oauth_session_invalid",
                    "oauth_phone_send_rate_limited",
                    "oauth_phone_session_rollover_required",
                )
            ):
                raise
            return False
        except Exception as e:
            self._log(f"add_phone 分支异常: {e}")
            return False

    def _handle_otp_verification(self, email, device_id, user_agent, sec_ch_ua, impersonate, mail_client, code_verifier, continue_url, page_type, baseline_message_ids=None, sms_client=None):
        """处理 OTP 验证流程"""
        self._log("步骤4: 检测到邮箱 OTP 验证")
        
        # OAuth 阶段不要继承“注册阶段”验证码去重集合，
        # 否则会把同一封邮件里的可用 OTP 直接跳过。
        tried_codes = set()
        if hasattr(mail_client, '_used_codes'):
            try:
                mail_client._used_codes = set()
            except Exception:
                pass

        headers_otp = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.oauth_issuer}/email-verification",
            "Origin": self.oauth_issuer,
            "oai-device-id": device_id,
            "User-Agent": user_agent or "Mozilla/5.0",
        }
        headers_otp.update(generate_datadog_trace())
        
        otp_success = False
        otp_deadline = time.time() + self.email_otp_timeout
        max_attempts = max(1, int(getattr(self, "email_otp_max_attempts", 3) or 3))
        attempt = 0
        snapshot_ids = set(baseline_message_ids or set())
        # ① 先抓"发码前"基线（OAuth 现场已有注册阶段那 1 封邮件，要算作旧）
        if hasattr(mail_client, "capture_openai_baseline"):
            try:
                snapshot_ids.update(mail_client.capture_openai_baseline(email=email, quiet=False) or set())
            except Exception:
                pass

        # ② 主动触发 OAuth 阶段重新发码（OpenAI 默认不会自动补发）
        resend_headers = {
            "Accept": "application/json",
            "Origin": self.oauth_issuer,
            "Referer": f"{self.oauth_issuer}/email-verification",
            "User-Agent": user_agent or "Mozilla/5.0",
            "oai-device-id": device_id,
        }
        resend_headers.update(generate_datadog_trace())

        def _request_email_otp():
            resend_ok = False
            resend_status = None
            resend_path_used = None
            last_error = ""
            for path in (
                "/api/accounts/email-otp/resend",
                "/api/accounts/email-otp/send",
            ):
                try:
                    kw = {"headers": resend_headers, "timeout": 30, "allow_redirects": False, "json": {}}
                    if impersonate:
                        kw["impersonate"] = impersonate
                    r_send = self.session.post(f"{self.oauth_issuer}{path}", **kw)
                    self._log(f"OAuth 触发发码 {path} -> {r_send.status_code}")
                    resend_status = r_send.status_code
                    resend_path_used = path
                    if r_send.status_code in (200, 201, 204):
                        resend_ok = True
                        mail_client.manual_resend_error = ""
                        break
                    last_error = (
                        f"OpenAI 重发接口返回 HTTP {r_send.status_code}"
                    )
                except Exception as e:
                    last_error = (
                        "OpenAI 重发接口异常："
                        f"{type(e).__name__}"
                    )
                    self._log(f"OAuth 触发发码 {path} 异常: {e}")
            try:
                from . import diagnostics as _diag
                _diag.event("oauth_resend", {
                    "ok": resend_ok,
                    "path": resend_path_used,
                    "status": resend_status,
                })
                # 触发 resend 时再抓一次邮件计数（OpenAI 是否真投递了邮件）
                if hasattr(mail_client, "_list_openai_messages"):
                    try:
                        oai_now = mail_client._list_openai_messages()
                        _diag.event("oauth_resend_inbox", {
                            "count": len(oai_now),
                            "top_uid": (oai_now[-1]["uid"] if oai_now else None),
                        })
                    except Exception:
                        pass
            except Exception:
                pass
            if not resend_ok:
                mail_client.manual_resend_error = (
                    last_error or "OpenAI 重发接口未返回成功"
                )
            return resend_ok

        resend_ok = _request_email_otp()
        if not resend_ok:
            self._log("⚠️ OAuth 触发发码均失败，仍会按 wait+回退老码尝试")

        while time.time() < otp_deadline and not otp_success and attempt < max_attempts:
            remaining = max(1, int(otp_deadline - time.time()))
            missing_resend_provider = object()
            previous_resend_provider = getattr(
                mail_client,
                "manual_resend_provider",
                missing_resend_provider,
            )
            mail_client.manual_resend_provider = _request_email_otp
            try:
                if hasattr(mail_client, "wait_for_new_verification_code"):
                    otp_code = mail_client.wait_for_new_verification_code(
                        email,
                        timeout=remaining,
                        exclude_codes=tried_codes,
                        exclude_message_ids=snapshot_ids,
                    )
                else:
                    otp_code = mail_client.wait_for_verification_code(
                        email,
                        timeout=remaining,
                        exclude_codes=tried_codes,
                    )
            finally:
                if previous_resend_provider is missing_resend_provider:
                    try:
                        delattr(mail_client, "manual_resend_provider")
                    except AttributeError:
                        pass
                else:
                    mail_client.manual_resend_provider = (
                        previous_resend_provider
                    )

            if not otp_code:
                fallback = getattr(mail_client, "get_latest_verification_code_fallback", None)
                if callable(fallback):
                    otp_code = fallback(
                        email,
                        exclude_codes=tried_codes,
                        exclude_message_ids=snapshot_ids,
                    )
                if not otp_code:
                    self._log("OTP 获取失败或已取消")
                    break

            otp_code = str(otp_code).strip()
            if not re.fullmatch(r"\d{6}", otp_code):
                self._log(f"OAuth OTP 忽略非 6 位候选码: {otp_code}")
                tried_codes.add(otp_code)
                continue
            attempt += 1
            tried_codes.add(otp_code)
            self._log(f"尝试 OTP: *** ({attempt}/{max_attempts})")

            try:
                kwargs = {
                    "json": {"code": otp_code},
                    "headers": headers_otp,
                    "timeout": 30,
                    "allow_redirects": False
                }
                if impersonate:
                    kwargs["impersonate"] = impersonate

                resp_otp = self.session.post(
                    f"{self.oauth_issuer}/api/accounts/email-otp/validate",
                    **kwargs
                )
            except Exception as e:
                self._log(f"email-otp/validate 异常: {e}")
                continue

            self._log(f"/email-otp/validate attempt={attempt}/{max_attempts} -> {resp_otp.status_code}")
            try:
                from . import diagnostics as _diag
                otp_body_text = ""
                otp_body_json = None
                try:
                    otp_body_json = resp_otp.json()
                except Exception:
                    otp_body_text = (resp_otp.text or "")[:240]
                _diag.event("oauth_otp_validate", {
                    "status": resp_otp.status_code,
                    "code_used": "***",
                    "page_type": ((otp_body_json or {}).get("page", {}) or {}).get("type", ""),
                    "continue_url": ((otp_body_json or {}).get("continue_url", "") or "")[:120],
                    "text": otp_body_text,
                })
            except Exception:
                pass

            if resp_otp.status_code != 200:
                self._log(f"OTP 无效: {(resp_otp.text or '')[:160]}")
                if resp_otp.status_code in (401, 403, 409, 429):
                    self.last_oauth_error = f"email_otp_rejected_{resp_otp.status_code}"
                    break
                continue

            try:
                otp_data = resp_otp.json()
            except Exception:
                self._log("email-otp/validate 响应解析失败")
                continue

            continue_url = otp_data.get("continue_url", "") or continue_url
            page_type = otp_data.get("page", {}).get("type", "") or page_type
            self._log(f"OTP 验证通过 page={page_type or '-'} next={self._redact_url(continue_url)[:80] if continue_url else '-'}...")
            otp_success = True

            if not hasattr(mail_client, '_used_codes'):
                mail_client._used_codes = set()
            mail_client._used_codes.add(otp_code)
        
        if not otp_success:
            self._log(f"OAuth 阶段 OTP 验证失败，已尝试 {attempt} 个 6 位验证码")
            return None
        
        # OTP 验证成功后，先处理 about_you / add_phone 分支，再继续 consent 流程
        code = None
        consent_url = continue_url

        if consent_url and consent_url.startswith("/"):
            consent_url = f"{self.oauth_issuer}{consent_url}"

        page_hint = (page_type or "").lower()
        url_hint = (consent_url or "").lower()

        if ("about" in page_hint) or ("about-you" in url_hint):
            self._log("检测到 about_you 分支，尝试补齐 create_account")
            self._oauth_try_complete_about_you(email, consent_url, device_id, user_agent, impersonate)
            consent_url = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"

        if ("add_phone" in page_hint) or ("phone" in page_hint) or ("add-phone" in url_hint) or ("phone-verification" in url_hint):
            use_reauthorize = self._should_reauthorize_for_phone(sms_client or mail_client)
            try:
                from . import diagnostics as _diag
                _diag.event("oauth_add_phone_branch", {"page_hint": page_hint, "url_hint": url_hint[:120], "strategy": self.phone_strategy, "reauthorize": use_reauthorize})
            except Exception:
                pass
            if use_reauthorize:
                # 不填手机：刷新授权链接重新授权（由 main.py 外层重试；一般重授权一次即可跳过手机拿到 rt）
                self._log("检测到 add_phone 分支：按策略刷新授权链接重新授权（不填手机）")
                self.last_oauth_error = "phone_required"
                return None
            self._log("检测到 add_phone 分支，执行手机号验证")
            ok_phone = self._oauth_try_complete_add_phone(email, device_id, user_agent, impersonate, sms_client or mail_client)
            if not ok_phone:
                self._log("add_phone 分支未完成，无法继续 OAuth")
                self.last_oauth_error = "add_phone_failed"
                return None
            consent_url = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"

        if not consent_url and "consent" in page_hint:
            consent_url = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"

        # 先检查 URL 中是否已经包含 code
        if consent_url:
            code = self._extract_code_from_url(consent_url)

        # 跟随 continue_url
        if not code and consent_url:
            self._log("步骤5: 跟随 continue_url 提取 code")
            code, _ = self._oauth_follow_for_code(consent_url, referer=f"{self.oauth_issuer}/email-verification", user_agent=user_agent, impersonate=impersonate)
        
        # 检查是否需要 workspace/org 选择
        consent_hint = (
            ("consent" in (consent_url or ""))
            or ("sign-in-with-chatgpt" in (consent_url or ""))
            or ("workspace" in (consent_url or ""))
            or ("organization" in (consent_url or ""))
            or ("consent" in page_type)
            or ("organization" in page_type)
        )
        
        if not code and consent_hint:
            if not consent_url:
                consent_url = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
            self._log("步骤6: 执行 workspace/org 选择")
            code = self._oauth_submit_workspace_and_org(consent_url, device_id, user_agent, impersonate)
        
        # 最后回退
        if not code:
            fallback_consent = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
            self._log("步骤6: 回退 consent 路径重试")
            code = self._oauth_submit_workspace_and_org(fallback_consent, device_id, user_agent, impersonate)
            if not code:
                code, _ = self._oauth_follow_for_code(fallback_consent, referer=f"{self.oauth_issuer}/email-verification", user_agent=user_agent, impersonate=impersonate)
        
        if not code:
            self._log("未获取到 authorization code")
            return None
        
        self._log("获取到 authorization code")
        
        # 用 code 换取 tokens
        self._log("步骤7: POST /oauth/token")
        tokens = self._exchange_code_for_tokens(code, code_verifier, user_agent, impersonate)
        
        if tokens:
            self._log("✅ OAuth 登录成功")
            return tokens
        else:
            self._log("换取 tokens 失败")
            return None

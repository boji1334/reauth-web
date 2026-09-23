"""
ChatGPT 注册客户端模块
使用 curl_cffi 模拟浏览器行为
"""

import random
import uuid
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .http_client import create_http_session, normalize_proxy_url
from .sentinel_token import build_sentinel_token, fetch_sentinel_challenge
from .utils import generate_datadog_trace


# Chrome 指纹配置
_CHROME_PROFILES = [
    {
        "major": 131, "impersonate": "chrome131",
        "build": 6778, "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "major": 133, "impersonate": "chrome133a",
        "build": 6943, "patch_range": (33, 153),
        "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    },
]


def _random_chrome_version(preferred_impersonate=None):
    """选择一个 Chrome 版本，默认优先使用当前通过率更高的指纹。"""
    preferred = str(preferred_impersonate or "chrome133a").strip()
    profile = next((item for item in _CHROME_PROFILES if item["impersonate"] == preferred), None)
    if profile is None:
        profile = random.choice(_CHROME_PROFILES)
    major = profile["major"]
    build = profile["build"]
    patch = random.randint(*profile["patch_range"])
    full_ver = f"{major}.0.{build}.{patch}"
    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
    return profile["impersonate"], major, full_ver, ua, profile["sec_ch_ua"]


def _redact_url(url):
    raw = str(url or "")
    if not raw:
        return ""
    try:
        parsed = urlparse(raw)
        sensitive = {"code", "state", "access_token", "refresh_token", "id_token", "code_verifier", "login_verifier"}
        params = []
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
            params.append((key, "***" if key.lower() in sensitive else (values[0] if values else "")))
        return urlunparse(parsed._replace(query=urlencode(params)))
    except Exception:
        return raw.replace("code=", "code=***")


class ChatGPTClient:
    """ChatGPT 注册客户端"""
    
    BASE = "https://chatgpt.com"
    AUTH = "https://auth.openai.com"
    
    def __init__(self, proxy=None, verbose=True, impersonate=None):
        """
        初始化 ChatGPT 客户端
        
        Args:
            proxy: 代理地址
            verbose: 是否输出详细日志
        """
        self.proxy = normalize_proxy_url(proxy)
        self.verbose = verbose
        self.device_id = str(uuid.uuid4())
        self.last_error = ""

        # 随机 Chrome 版本
        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version(impersonate)
        
        # 创建 session
        self.session = create_http_session(proxy=self.proxy, impersonate=self.impersonate)

        # 设置基础 headers
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": random.choice([
                "en-US,en;q=0.9", "en-US,en;q=0.9,zh-CN;q=0.8",
                "en,en-US;q=0.9", "en-US,en;q=0.8",
            ]),
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{self.chrome_full}"',
            "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
        })
        
        # 设置 oai-did cookie
        self.session.cookies.set("oai-did", self.device_id, domain="chatgpt.com")

    def _log(self, msg):
        """输出日志"""
        if self.verbose:
            print(f"  {msg}")

    def visit_homepage(self):
        """访问首页，建立 session"""
        self._log("访问 ChatGPT 首页...")
        self.last_error = ""
        url = f"{self.BASE}/"
        try:
            r = self.session.get(url, headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
            }, allow_redirects=True, timeout=30)
            if r.status_code != 200:
                self.last_error = f"HTTP {r.status_code}"
                self._log(f"访问首页 HTTP {r.status_code} body={(r.text or '')[:200]!r}")
            return r.status_code == 200
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            self._log(f"访问首页失败: {self.last_error}")
            return False
    
    def get_csrf_token(self):
        """获取 CSRF token"""
        self._log("获取 CSRF token...")
        url = f"{self.BASE}/api/auth/csrf"
        try:
            r = self.session.get(url, headers={
                "Accept": "application/json",
                "Referer": f"{self.BASE}/"
            }, timeout=30)
            
            if r.status_code == 200:
                data = r.json()
                token = data.get("csrfToken", "")
                if token:
                    self._log("CSRF token: ***")
                    return token
        except Exception as e:
            self._log(f"获取 CSRF token 失败: {e}")
        
        return None
    
    def signin(self, email, csrf_token):
        """
        提交邮箱，获取 authorize URL
        
        Returns:
            str: authorize URL
        """
        self._log(f"提交邮箱: {email}")
        url = f"{self.BASE}/api/auth/signin/openai"
        
        params = {
            "prompt": "login",
            "ext-oai-did": self.device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "screen_hint": "login_or_signup",
            "login_hint": email,
        }
        
        form_data = {
            "callbackUrl": f"{self.BASE}/",
            "csrfToken": csrf_token,
            "json": "true",
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Referer": f"{self.BASE}/",
            "Origin": self.BASE,
        }
        
        try:
            r = self.session.post(
                url,
                params=params,
                data=form_data,
                headers=headers,
                timeout=30
            )
            
            if r.status_code == 200:
                data = r.json()
                authorize_url = data.get("url", "")
                if authorize_url:
                    self._log(f"获取到 authorize URL")
                    return authorize_url
        except Exception as e:
            self._log(f"提交邮箱失败: {e}")
        
        return None
    
    def authorize(self, url, max_retries=3):
        """
        访问 authorize URL，跟随重定向（带重试机制）
        这是关键步骤，建立 auth.openai.com 的 session
        
        Returns:
            str: 最终重定向的 URL
        """
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    self._log(f"访问 authorize URL... (尝试 {attempt + 1}/{max_retries})")
                    time.sleep(1)  # 重试前等待
                else:
                    self._log("访问 authorize URL...")
                
                r = self.session.get(url, headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": f"{self.BASE}/",
                    "Upgrade-Insecure-Requests": "1",
                }, allow_redirects=True, timeout=30)
                
                final_url = str(r.url)
                self._log(f"重定向到: {final_url}")
                return final_url
                
            except Exception as e:
                error_msg = str(e)
                is_tls_error = "TLS" in error_msg or "SSL" in error_msg or "curl: (35)" in error_msg
                
                if is_tls_error and attempt < max_retries - 1:
                    self._log(f"Authorize TLS 错误 (尝试 {attempt + 1}/{max_retries}): {error_msg[:100]}")
                    continue
                else:
                    self._log(f"Authorize 失败: {e}")
                    return ""
        
        return ""
    
    def callback(self):
        """完成注册回调"""
        self._log("执行回调...")
        url = f"{self.AUTH}/api/accounts/authorize/callback"
        try:
            r = self.session.get(url, headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": f"{self.AUTH}/about-you",
            }, allow_redirects=True, timeout=30)
            return r.status_code == 200
        except Exception as e:
            self._log(f"回调失败: {e}")
            return False

    def _normalize_auth_url(self, url):
        if not url:
            return ""
        if url.startswith("/"):
            return f"{self.AUTH}{url}"
        return url

    def has_access_token(self):
        try:
            r = self.session.get(
                f"{self.BASE}/api/auth/session",
                headers={"Accept": "*/*", "Referer": f"{self.BASE}/"},
                timeout=30,
            )
            if r.status_code != 200:
                self._log(f"会话检查失败: HTTP {r.status_code}")
                return False
            data = r.json() or {}
            ok = bool(data.get("accessToken"))
            self._log(f"会话检查 accessToken: {'有' if ok else '无'}")
            return ok
        except Exception as e:
            self._log(f"会话检查异常: {e}")
            return False

    def reauthorize_for_session(self, original_auth_url):
        try:
            parsed = urlparse(original_auth_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params.pop("prompt", None)
            query = urlencode({k: v[0] for k, v in params.items()})
            current_url = urlunparse(parsed._replace(query=query))
            for hop in range(12):
                r = self.session.get(
                    current_url,
                    headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": f"{self.BASE}/",
                        "Upgrade-Insecure-Requests": "1",
                        "User-Agent": self.ua,
                    },
                    allow_redirects=False,
                    timeout=30,
                )
                location = (r.headers.get("Location", "") or "").strip()
                final_url = str(getattr(r, "url", current_url) or current_url)
                self._log(f"重新授权跳转 {hop + 1}: {r.status_code} {location[:120] if location else final_url[:120]}")
                if "chatgpt.com/api/auth/callback/openai" in final_url or "/api/auth/callback/openai" in final_url or "code=" in final_url:
                    self.visit_auth_flow_page(final_url, referer=f"{self.AUTH}/about-you")
                    return True
                if r.status_code not in (301, 302, 303, 307, 308) or not location:
                    return self.has_access_token()
                if location.startswith("/"):
                    origin = f"{urlparse(current_url).scheme}://{urlparse(current_url).netloc}"
                    location = origin + location
                current_url = location
            return self.has_access_token()
        except Exception as e:
            self._log(f"重新授权异常: {e}")
            return False

    def ensure_registered_session(self, original_auth_url=""):
        if self.has_access_token():
            return True
        self._log("注册后未拿到 accessToken，尝试重新授权刷新 ChatGPT session")
        if original_auth_url and self.reauthorize_for_session(original_auth_url) and self.has_access_token():
            return True
        self.visit_auth_flow_page(f"{self.BASE}/", referer=f"{self.AUTH}/about-you")
        return self.has_access_token()

    def visit_auth_flow_page(self, url, referer=None):
        """预访问 auth.openai.com 流程页，推进服务端状态机"""
        target = self._normalize_auth_url(url)
        if not target:
            return ""
        try:
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
                "Referer": referer or f"{self.AUTH}/email-verification",
                "User-Agent": self.ua,
            }
            r = self.session.get(target, headers=headers, allow_redirects=True, timeout=30)
            final_url = str(r.url)
            self._log(f"预访问流程页 -> {r.status_code} {final_url}")
            return final_url
        except Exception as e:
            self._log(f"预访问流程页异常: {e}")
            return target
    
    def send_email_otp(self):
        """触发发送邮箱验证码"""
        self._log("触发发送验证码...")
        url = f"{self.AUTH}/api/accounts/email-otp/send"

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"{self.AUTH}/create-account/password",
            "Upgrade-Insecure-Requests": "1",
        }

        try:
            r = self.session.get(url, headers=headers, allow_redirects=True, timeout=30)
            return r.status_code == 200
        except Exception as e:
            self._log(f"发送验证码失败: {e}")
            return False

    def resend_email_otp(self, referer=None):
        headers = {
            "Accept": "application/json",
            "Origin": self.AUTH,
            "Referer": referer or f"{self.AUTH}/email-verification",
            "User-Agent": self.ua,
            "oai-device-id": self.device_id,
        }
        headers.update(generate_datadog_trace())
        for path in ("/api/accounts/email-otp/resend", "/api/accounts/email-otp/send"):
            try:
                r = self.session.post(
                    f"{self.AUTH}{path}",
                    json={},
                    headers=headers,
                    allow_redirects=False,
                    timeout=30,
                )
                self._log(f"协议重发验证码 {path} -> {r.status_code}")
                if r.status_code in (200, 201, 204):
                    return True
            except Exception as e:
                self._log(f"协议重发验证码 {path} 异常: {e}")
        return False

    def verify_email_otp(self, otp_code):
        """
        验证邮箱 OTP 码
        
        Args:
            otp_code: 6位验证码
            
        Returns:
            tuple: (success, message)
        """
        self._log("验证 OTP 码: ***")
        url = f"{self.AUTH}/api/accounts/email-otp/validate"
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Referer": f"{self.AUTH}/email-verification",
            "Origin": self.AUTH,
            "oai-device-id": self.device_id,  # 必须包含device_id
            "User-Agent": self.ua,
        }
        headers.update(generate_datadog_trace())
        
        payload = {"code": otp_code}
        
        try:
            r = self.session.post(url, json=payload, headers=headers, timeout=30)
            
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    data = {}
                continue_url = data.get("continue_url", "")
                page_type = (data.get("page") or {}).get("type", "")
                self._log(f"验证成功 page={page_type or '-'} next={_redact_url(continue_url)[:120] if continue_url else '-'}")
                return True, {
                    "message": "验证成功",
                    "continue_url": continue_url,
                    "page_type": page_type,
                }
            else:
                error_msg = r.text[:200]
                self._log(f"验证失败: {r.status_code} - {error_msg}")
                return False, f"HTTP {r.status_code}"
                
        except Exception as e:
            self._log(f"验证异常: {e}")
            return False, str(e)
    

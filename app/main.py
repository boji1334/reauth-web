"""公益协议重登站：两个选项卡（协议重登 / 卡密兑换）。"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from . import __version__
from .config import load_settings
from .convert import ConvertError
from .formats import OUTPUT_KINDS, output_bundle
from .engine import STEPS_CONVERT, STEPS_LOGIN, STEPS_REDEEM
from .jobs import MODE_REDEEM, JobManager
from .parsing import AccountLineError, parse_account_lines
from .security import RateLimiter, SessionTokens
from .upstream import UpstreamError
from .visits import VisitTracker

settings = load_settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
manager = JobManager(settings)
visits = VisitTracker(settings.data_dir)
tokens = SessionTokens(settings.data_dir, settings.signing_secret)
api_limiter = RateLimiter(settings.rate_limit_per_minute)
submit_limiter = RateLimiter(settings.submit_limit_per_minute)
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'"
    ),
}

TOKEN_HEADER = "X-REAUTH-TOKEN"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    async def sweeper() -> None:
        while True:
            await asyncio.sleep(600)
            manager.cleanup()

    task = asyncio.create_task(sweeper())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(
    title="公益协议重登站",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

TOKEN_FREE_PATHS = {
    "/",
    "/robots.txt",
    "/api/health",
    "/api/meta",
    "/api/session",
    "/api/visit",
}


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    ip = _client_ip(request)
    user_agent = str(request.headers.get("User-Agent") or "")

    if path.startswith("/api/"):
        allowed, retry_after = api_limiter.allow(f"api:{ip}")
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "请求过于频繁，请稍后再试"},
                headers={
                    **SECURITY_HEADERS,
                    "Retry-After": str(retry_after),
                },
            )
    if path in {"/api/submit", "/api/convert"}:
        supplied = str(request.headers.get(TOKEN_HEADER) or "")
        if not tokens.verify(supplied, ip=ip, user_agent=user_agent):
            return JSONResponse(
                status_code=403,
                content={"detail": "会话校验失败，请刷新页面后重试"},
                headers=SECURITY_HEADERS,
            )
        allowed, retry_after = submit_limiter.allow(f"submit:{ip}")
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "提交太频繁，请歇一会再来"},
                headers={
                    **SECURITY_HEADERS,
                    "Retry-After": str(retry_after),
                },
            )

    response = await call_next(request)
    for key, value in SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    return response


class SubmitRequest(BaseModel):
    text: str = Field(default="", max_length=200000)
    mode: str = Field(default="reauth", max_length=32)


class ConvertRequest(BaseModel):
    text: str = Field(default="", max_length=2000000)


class VisitRequest(BaseModel):
    visitor_id: str = Field(default="", max_length=128)


def _client_ip(request: Request) -> str:
    """取真实访客 IP。

    本站只在 Cloudflare -> Caddy 后面，CF 会写 CF-Connecting-IP（真实访客 IP，
    稳定）；X-Forwarded-For 的第一段同理。直接扫源站已被 Caddy 白名单拦掉，
    所以这里信任这两个头是安全的。
    """
    connecting = str(request.headers.get("CF-Connecting-IP") or "").strip()
    if connecting:
        return connecting
    forwarded = str(request.headers.get("X-Forwarded-For") or "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return str(getattr(request.client, "host", "") or "")


def _job_or_404(job_id: str):
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="任务不存在或已过期")
    return job


@app.get("/api/health")
async def health() -> dict:
    return {
        "ok": True,
        "version": __version__,
        "concurrency": settings.concurrency,
        "proxy_configured": bool(settings.proxy),
        "timestamp": int(time.time()),
    }


@app.get("/api/session")
async def session_token(request: Request) -> dict:
    """下发短时会话令牌（绑定 IP + UA），页面提交时自动带上。"""
    token, ttl = tokens.issue(
        ip=_client_ip(request),
        user_agent=str(request.headers.get("User-Agent") or ""),
    )
    return {"ok": True, "token": token, "expires_in": ttl}


@app.get("/robots.txt")
async def robots() -> Response:
    return Response(
        content="User-agent: *\nDisallow: /\n",
        media_type="text/plain",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/meta")
async def meta() -> dict:
    return {
        "site_name": settings.site_name,
        "notice": settings.site_notice,
        "max_accounts": settings.max_accounts_per_submit,
        "concurrency": settings.concurrency,
        "outputs": list(OUTPUT_KINDS),
        "github_url": settings.github_url,
        "cache_ttl_seconds": settings.session_cache_ttl_seconds,
        "steps": {
            "reauth": [label for _key, label in STEPS_LOGIN],
            "redeem": [label for _key, label in STEPS_REDEEM],
            "convert": [label for _key, label in STEPS_CONVERT],
        },
        "redeem_source": (
            "upstream" if manager.upstream.configured else "unconfigured"
        ),
    }


@app.post("/api/visit")
async def visit(payload: VisitRequest, request: Request) -> dict:
    """匿名访客统计：右下角小挂件用，不写 cookie、不存 IP。"""
    visitor_id = str(payload.visitor_id or "").strip()
    if not visitor_id:
        visitor_id = f"anon-{_client_ip(request) or 'unknown'}"
    return await asyncio.to_thread(visits.record, visitor_id)


@app.get("/api/visit")
async def visit_snapshot() -> dict:
    return await asyncio.to_thread(visits.snapshot)


@app.post("/api/convert")
async def convert(payload: ConvertRequest, request: Request) -> dict:
    """免登录快速通道：粘贴 sub2api 文件，直接转 cpa / sub2 / cockpit。"""
    ip = _client_ip(request)
    if manager.active_jobs_for_ip(ip) >= settings.max_jobs_per_ip:
        raise HTTPException(
            status_code=429,
            detail="你还有任务在跑，等它跑完再提交",
        )
    try:
        job = manager.create_convert_job(payload.text, owner_ip=ip)
    except ConvertError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return job.snapshot()


@app.post("/api/submit")
async def submit(payload: SubmitRequest, request: Request) -> dict:
    ip = _client_ip(request)
    if manager.active_jobs_for_ip(ip) >= settings.max_jobs_per_ip:
        raise HTTPException(
            status_code=429,
            detail="你还有任务在跑，等它跑完再提交",
        )
    try:
        accounts, errors = parse_account_lines(
            payload.text,
            max_accounts=settings.max_accounts_per_submit,
        )
    except AccountLineError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    job = manager.create_job(
        accounts,
        mode=payload.mode,
        owner_ip=ip,
        errors=errors,
    )
    return job.snapshot()


@app.get("/api/job/{job_id}")
async def job_status(job_id: str) -> dict:
    return _job_or_404(job_id).snapshot()


@app.get("/api/job/{job_id}/download/{kind}")
async def job_download(job_id: str, kind: str):
    job = _job_or_404(job_id)
    if not job.finished_at:
        raise HTTPException(status_code=409, detail="任务还没跑完")
    if job.mode == MODE_REDEEM:
        if not (job.outputs or {}).get("count"):
            raise HTTPException(
                status_code=404,
                detail="这一批在主站没有可兑换的成品文件",
            )
        try:
            name, body, media_type = await asyncio.to_thread(
                manager.fetch_redeem_output,
                job,
                kind,
            )
        except UpstreamError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return Response(
            content=body,
            media_type=media_type,
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": (
                    f"attachment; filename=\"{quote(name)}\"; "
                    f"filename*=UTF-8''{quote(name)}"
                ),
            },
        )
    outputs = job.outputs or {}
    try:
        name, body, media_type = output_bundle(outputs, kind)
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail="这一批没有可下载的成功账号",
        ) from exc
    return Response(
        content=body,
        media_type=media_type,
        headers={
            "Cache-Control": "no-store",
            # HTTP 头只能放 ASCII，中文文件名必须百分号编码
            "Content-Disposition": (
                f"attachment; filename=\"{quote(name)}\"; "
                f"filename*=UTF-8''{quote(name)}"
            ),
        },
    )


@app.get("/")
async def index() -> Response:
    page = STATIC_DIR / "index.html"
    if not page.is_file():
        return JSONResponse({"detail": "界面文件缺失"}, status_code=500)
    return FileResponse(page, media_type="text/html; charset=utf-8")

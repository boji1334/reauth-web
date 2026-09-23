"""内存任务池：受限并发跑协议重登 / 免登录转格式，结果只在内存。"""

from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .cache import SessionCache
from .config import Settings
from .convert import ConvertError, convert_sub2_text
from .engine import (
    STEPS_CONVERT,
    STEPS_LOGIN,
    STEPS_REDEEM,
    ReauthError,
    reauth_account,
)
from .formats import collect_outputs, sub2_merged_document
from .parsing import AccountLine
from .upstream import UpstreamClient, UpstreamError

PENDING = "pending"
RUNNING = "running"
DONE = "done"
ERROR = "error"

MODE_REAUTH = "reauth"
MODE_REDEEM = "redeem"
MODE_CONVERT = "convert"


def step_labels(mode: str) -> list[tuple[str, str]]:
    if mode == MODE_CONVERT:
        return list(STEPS_CONVERT)
    if mode == MODE_REDEEM:
        return list(STEPS_REDEEM)
    return list(STEPS_LOGIN)


@dataclass
class StepState:
    key: str
    label: str
    status: str = PENDING
    at: float = 0.0
    message: str = ""


@dataclass
class AccountState:
    email: str
    mode: str = MODE_REAUTH
    status: str = PENDING
    message: str = "排队中"
    plan_type: str = ""
    cached: bool = False
    started_at: float = 0.0
    finished_at: float = 0.0
    steps: list[StepState] = field(default_factory=list)
    result: dict | None = None

    def begin_steps(self, labels: list[tuple[str, str]]) -> None:
        self.steps = [StepState(key=key, label=label) for key, label in labels]

    def mark(self, key: str, message: str = "") -> None:
        found = False
        for step in self.steps:
            if step.key == key:
                step.status = RUNNING
                step.at = time.time()
                step.message = str(message or "")
                found = True
            elif not found and step.status == RUNNING:
                step.status = DONE
        if not found and self.steps:
            self.steps[-1].status = RUNNING

    def finish_steps(self, *, failed: bool = False) -> None:
        now = time.time()
        for step in self.steps:
            if step.status == RUNNING:
                step.status = ERROR if failed else DONE
                step.at = now
            elif step.status == PENDING and not failed:
                step.status = DONE
                step.at = now

    def snapshot(self) -> dict:
        return {
            "email": self.email,
            "status": self.status,
            "message": self.message,
            "plan_type": self.plan_type,
            "cached": self.cached,
            "seconds": round(
                (self.finished_at or time.time())
                - self.started_at,
                1,
            )
            if self.started_at
            else 0,
            "steps": [
                {
                    "key": step.key,
                    "label": step.label,
                    "status": step.status,
                    "message": step.message,
                    "at": step.at,
                }
                for step in self.steps
            ],
        }


@dataclass
class Job:
    job_id: str
    created_at: float
    mode: str
    owner_ip: str
    accounts: list[AccountState] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    outputs: dict | None = None
    finished_at: float = 0.0
    redeem_text: str = ""
    redeem_cache: dict = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def total(self) -> int:
        return len(self.accounts)

    @property
    def done_count(self) -> int:
        return sum(
            1 for item in self.accounts if item.status in {DONE, ERROR}
        )

    @property
    def ok_count(self) -> int:
        return sum(1 for item in self.accounts if item.status == DONE)

    @property
    def failed_count(self) -> int:
        return sum(1 for item in self.accounts if item.status == ERROR)

    def snapshot(self) -> dict:
        return {
            "job_id": self.job_id,
            "mode": self.mode,
            "total": self.total,
            "done": self.done_count,
            "ok": self.ok_count,
            "failed": self.failed_count,
            "finished": bool(self.finished_at),
            "elapsed": round(
                (self.finished_at or time.time()) - self.created_at,
                1,
            ),
            "source": (self.outputs or {}).get("source") or "",
            "steps_template": [
                {"key": key, "label": label} for key, label in step_labels(self.mode)
            ],
            "errors": list(self.errors),
            "accounts": [item.snapshot() for item in self.accounts],
        }


class JobManager:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.cache = SessionCache(settings.session_cache_ttl_seconds)
        self.upstream = UpstreamClient(
            settings.upstream_base,
            settings.upstream_key,
            timeout=settings.upstream_timeout_seconds,
        )
        self.executor = ThreadPoolExecutor(
            max_workers=max(1, settings.concurrency),
            thread_name_prefix="reauth",
        )
        self._last_auth_at = 0.0
        self._auth_lock = threading.Lock()

    # ---------------- 生命周期 ----------------
    def active_jobs_for_ip(self, owner_ip: str) -> int:
        with self.lock:
            return sum(
                1
                for job in self.jobs.values()
                if job.owner_ip == owner_ip and not job.finished_at
            )

    def create_job(
        self,
        accounts: list[AccountLine],
        *,
        mode: str,
        owner_ip: str,
        errors: list[str] | None = None,
    ) -> Job:
        job = Job(
            job_id=uuid.uuid4().hex,
            created_at=time.time(),
            mode=mode,
            owner_ip=str(owner_ip or ""),
            accounts=[
                AccountState(email=account.email, mode=mode) for account in accounts
            ],
            errors=list(errors or []),
            redeem_text="\n".join(account.canonical for account in accounts),
        )
        for state in job.accounts:
            state.begin_steps(step_labels(mode))
        with self.lock:
            self.jobs[job.job_id] = job
        if mode == MODE_REDEEM:
            # 兑换不碰 OpenAI：只在主站库存里取成品，几秒就完事
            self.executor.submit(self._run_redeem_job, job, accounts)
        else:
            self.executor.submit(self._run_job, job, accounts)
        return job

    def create_convert_job(
        self,
        text: str,
        *,
        owner_ip: str,
        errors: list[str] | None = None,
    ) -> Job:
        """免登录快速通道：直接转格式，立即完成。"""
        items = convert_sub2_text(text)
        job = Job(
            job_id=uuid.uuid4().hex,
            created_at=time.time(),
            mode=MODE_CONVERT,
            owner_ip=str(owner_ip or ""),
            errors=list(errors or []),
        )
        results: list[dict] = []
        for index, item in enumerate(items, start=1):
            state = AccountState(
                email=str(item.get("email") or f"account-{index}"),
                mode=MODE_CONVERT,
                status=DONE,
                message="转格式完成",
                plan_type=str(item.get("plan_type") or ""),
                started_at=time.time(),
                finished_at=time.time(),
            )
            state.begin_steps(step_labels(MODE_CONVERT))
            for step in state.steps:
                step.status = DONE
                step.at = time.time()
            job.accounts.append(state)
            results.append(
                {
                    "email": state.email,
                    "plan_type": state.plan_type,
                    "status": "ok",
                    "payloads": {
                        "cpa": item.get("cpa") or {},
                        "cockpit": item.get("cockpit") or {},
                        "sub2api": sub2_merged_document(
                            [item.get("sub2api") or {}]
                        ),
                    },
                }
            )
        job.outputs = collect_outputs(results)
        job.finished_at = time.time()
        with self.lock:
            self.jobs[job.job_id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        with self.lock:
            return self.jobs.get(str(job_id or ""))

    def cleanup(self) -> int:
        deadline = time.time() - max(
            self.settings.job_ttl_seconds,
            self.settings.result_ttl_seconds,
        )
        removed = 0
        with self.lock:
            for job_id, job in list(self.jobs.items()):
                if job.finished_at and job.finished_at < deadline:
                    self.jobs.pop(job_id, None)
                    removed += 1
        self.cache.prune()
        return removed

    # ---------------- 执行 ----------------
    def _wait_slot(self) -> None:
        gap = float(self.settings.auth_min_interval_seconds or 0)
        if gap <= 0:
            return
        with self._auth_lock:
            wait = self._last_auth_at + gap - time.time()
            if wait > 0:
                time.sleep(wait)
            self._last_auth_at = time.time()

    def _cached_payloads(self, state: AccountState) -> dict | None:
        entry = self.cache.get(state.email)
        if entry is None:
            return None
        payloads = entry.get("payloads") or {}
        if not (payloads.get("sub2api") or {}).get("accounts"):
            return None
        state.cached = True
        state.plan_type = str(entry.get("plan_type") or "")
        return payloads

    # ---------------- 卡密兑换：只取主站成品，不动 OpenAI ----------------
    def _run_redeem_job(
        self,
        job: Job,
        accounts: list[AccountLine],
    ) -> None:
        if not self.upstream.configured:
            with job.lock:
                for state in job.accounts:
                    state.status = ERROR
                    state.message = "兑换通道未配置（缺少主站地址或密钥）"
                    state.finished_at = time.time()
                    state.finish_steps(failed=True)
                job.outputs = {"source": "upstream", "count": 0}
                job.finished_at = time.time()
            return

        ok = 0
        for account, state in zip(accounts, job.accounts, strict=True):
            with job.lock:
                state.status = RUNNING
                state.started_at = time.time()
                state.message = "正在主站查询这个邮箱"
                state.mark("read", "已解析邮箱 / 密码 / 2FA")
                state.mark("stock", "查询主站已生成的成品")
            try:
                info = self.upstream.lookup(account.email)
            except UpstreamError as exc:
                info = {"available": False, "status_label": str(exc)}
            with job.lock:
                if info.get("available"):
                    state.mark("fetch", "主站已有成品，可直接取回")
                    state.mark("finish", "整理交付文件")
                    state.status = DONE
                    state.message = "主站库存命中，可直接兑换"
                    state.plan_type = ""
                    ok += 1
                else:
                    label = str(info.get("status_label") or "").strip()
                    detail = str(info.get("error") or "").strip()
                    reason = "主站没有这个账号的成品文件"
                    if label:
                        reason += f"（{label}）"
                    if detail:
                        reason += f"：{detail}"
                    else:
                        reason += "，请改用协议重登"
                    state.status = ERROR
                    state.message = reason
                state.finished_at = time.time()
                state.finish_steps(failed=state.status == ERROR)

        with job.lock:
            job.outputs = {"source": "upstream", "count": ok}
            job.finished_at = time.time()

    def fetch_redeem_output(self, job: Job, kind: str) -> tuple[str, bytes, str]:
        """按需向主站兑换指定格式，同一任务内做一次缓存。"""
        with job.lock:
            cached = job.redeem_cache.get(kind)
        if cached is not None:
            return cached
        result = self.upstream.export(job.redeem_text, kind)
        with job.lock:
            job.redeem_cache[kind] = result
        return result

    def _run_job(self, job: Job, accounts: list[AccountLine]) -> None:
        for account, state in zip(accounts, job.accounts, strict=True):
            with job.lock:
                state.status = RUNNING
                state.started_at = time.time()
                state.message = "开始处理"
                state.mark("read", "已解析邮箱 / 密码 / 2FA")

            self._wait_slot()

            def on_step(key: str, message: str, state=state) -> None:
                with job.lock:
                    state.mark(key, message)
                    state.message = message or state.message

            try:
                result = reauth_account(
                    account,
                    self.settings,
                    on_step=on_step,
                )
            except ReauthError as exc:
                with job.lock:
                    state.status = ERROR
                    state.message = str(exc)
                    state.finished_at = time.time()
                    state.finish_steps(failed=True)
                continue
            except Exception as exc:  # noqa: BLE001 - 兜底，避免线程崩溃
                with job.lock:
                    state.status = ERROR
                    state.message = f"内部错误：{type(exc).__name__}"
                    state.finished_at = time.time()
                    state.finish_steps(failed=True)
                continue

            self.cache.put(
                account.email,
                payloads=result["payloads"],
                plan_type=str(result.get("plan_type") or ""),
                account_id=str(result.get("account_id") or ""),
                expires_at=str(result.get("expires_at") or ""),
            )
            with job.lock:
                state.mark("finish", "整理交付文件")
                state.status = DONE
                state.message = "重登成功"
                state.plan_type = str(result.get("plan_type") or "")
                state.result = result
                state.finished_at = time.time()
                state.finish_steps()

        results = [
            {
                "email": state.email,
                "plan_type": state.plan_type,
                "status": "ok" if state.status == DONE else "error",
                "payloads": (state.result or {}).get("payloads") or {},
            }
            for state in job.accounts
        ]
        outputs = collect_outputs(results)
        with job.lock:
            job.outputs = outputs
            job.finished_at = time.time()
        for state in job.accounts:
            state.result = None

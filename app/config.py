"""站点配置：全部来自环境变量，缺省值保证开箱可用。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return str(os.environ.get(name, default) or "").strip()


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, value)


@dataclass
class Settings:
    data_dir: Path
    proxy: str = ""
    impersonate: str = "chrome133a"
    impersonates: str = "chrome124,chrome133a,chrome136,chrome120"
    concurrency: int = 2
    max_accounts_per_submit: int = 200
    account_timeout_seconds: int = 420
    job_ttl_seconds: int = 3600 * 6
    result_ttl_seconds: int = 3600 * 6
    session_cache_ttl_seconds: int = 3600 * 6
    site_name: str = "公益协议重登站"
    site_notice: str = ""
    github_url: str = ""
    upstream_base: str = ""
    upstream_key: str = ""
    upstream_timeout_seconds: int = 90
    max_jobs_per_ip: int = 3
    auth_min_interval_seconds: int = 3
    totp_period: int = 30
    signing_secret: str = ""
    rate_limit_per_minute: int = 120
    submit_limit_per_minute: int = 6
    quiet: bool = True
    extra: dict = field(default_factory=dict)

    @property
    def jobs_dir(self) -> Path:
        return self.data_dir / "jobs"

    @property
    def impersonate_pool(self) -> list[str]:
        values = [
            item.strip()
            for item in str(self.impersonates or "").split(",")
            if item.strip()
        ]
        if self.impersonate and self.impersonate not in values:
            values.insert(0, self.impersonate)
        return values or ["chrome133a"]


def load_settings() -> Settings:
    data_dir = Path(_env("REAUTH_DATA_DIR", "/data")).expanduser()
    return Settings(
        data_dir=data_dir,
        proxy=_env("REAUTH_PROXY"),
        impersonate=_env("REAUTH_IMPERSONATE", "chrome133a") or "chrome133a",
        impersonates=(
            _env(
                "REAUTH_IMPERSONATES",
                "chrome124,chrome133a,chrome136,chrome120",
            )
            or "chrome133a"
        ),
        concurrency=_env_int("REAUTH_CONCURRENCY", 2, minimum=1),
        max_accounts_per_submit=_env_int(
            "REAUTH_MAX_ACCOUNTS",
            200,
            minimum=1,
        ),
        account_timeout_seconds=_env_int(
            "REAUTH_ACCOUNT_TIMEOUT_SECONDS",
            420,
            minimum=60,
        ),
        job_ttl_seconds=_env_int(
            "REAUTH_JOB_TTL_SECONDS",
            21600,
            minimum=600,
        ),
        result_ttl_seconds=_env_int(
            "REAUTH_RESULT_TTL_SECONDS",
            21600,
            minimum=600,
        ),
        session_cache_ttl_seconds=_env_int(
            "REAUTH_SESSION_CACHE_TTL_SECONDS",
            21600,
            minimum=300,
        ),
        site_name=_env("REAUTH_SITE_NAME", "公益协议重登站")
        or "公益协议重登站",
        site_notice=_env("REAUTH_SITE_NOTICE"),
        # GitHub star 入口：先预留位置，填了 REAUTH_GITHUB_URL 才会显示
        github_url=_env("REAUTH_GITHUB_URL"),
        # 卡密兑换的数据来源：主站（自动接码站）已生成的成品文件
        # 兑换站的数据来源（上游成品站）：地址不写进代码，只走环境变量
        upstream_base=_env("REAUTH_UPSTREAM_BASE").rstrip("/"),
        upstream_key=_env("REAUTH_UPSTREAM_KEY"),
        upstream_timeout_seconds=_env_int(
            "REAUTH_UPSTREAM_TIMEOUT_SECONDS",
            90,
            minimum=10,
        ),
        max_jobs_per_ip=_env_int("REAUTH_MAX_JOBS_PER_IP", 3, minimum=1),
        auth_min_interval_seconds=_env_int(
            "REAUTH_MIN_INTERVAL_SECONDS",
            3,
            minimum=0,
        ),
        totp_period=_env_int("REAUTH_TOTP_PERIOD", 30, minimum=10),
        # 防滥用参数
        signing_secret=_env("REAUTH_SIGNING_SECRET"),
        rate_limit_per_minute=_env_int(
            "REAUTH_RATE_LIMIT_PER_MINUTE",
            120,
            minimum=5,
        ),
        submit_limit_per_minute=_env_int(
            "REAUTH_SUBMIT_LIMIT_PER_MINUTE",
            6,
            minimum=1,
        ),
    )

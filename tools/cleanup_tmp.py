"""清理本地联调残留（.codex-tmp_* / cf_*.py / port_probe.py 等临时脚本与数据目录）。"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TEMP_PATTERNS = (
    ".codex-tmp_*",
    "cf_probe.py",
    "cf_records.py",
    "cf_summary.py",
    "cf_zone_probe.py",
    "cf_dns.py",
    "port_probe.py",
    "p80_*.py",
    "cleanup_tmp80.py",
    "caddy_check*.py",
    "https_check.py",
    "doh_check.py",
    "srv_probe.py",
    "srv_https_check.py",
    "verify_https.py",
    "ui_check.py",
)


def main() -> int:
    removed: list[str] = []
    for pattern in TEMP_PATTERNS:
        for path in sorted(ROOT.glob(pattern)):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
            removed.append(path.name)
    local_data = ROOT / "artifacts" / "local-data"
    if local_data.exists():
        shutil.rmtree(local_data)
        removed.append("artifacts/local-data")
    for name in removed:
        print("removed", name)
    print("clean_total", len(removed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# 公益协议重登站（reauth-web）

粘贴 `邮箱----密码----2fa`，现场完成 ChatGPT / OpenAI 协议登录，直接产出可用的
Sub2 / CPA / Cockpit 文件——**专治 API 文件 401**。

> 本项目只做「协议重登」与「本地转格式」两件事：不注册账号、不接手机号、
> 不含接码池、不含支付与订单系统。

## 功能

两个选项卡（默认进「卡密兑换」）：

| 选项卡 | 用途 | 输出 |
| --- | --- | --- |
| 🔄 协议重登 | 老文件 401，现场重新登录拿新 token | Sub2 合并 json、Sub2 单独 zip |
| 🧾 卡密兑换 | 贴卡密直接兑换成品（可选接自己的上游成品站），或贴 sub2 文件本地转格式 | CPA 文件、Sub2 合并 json、Sub2 单独 zip、Cockpit 文件 |

其它：

- 账号格式 `邮箱----密码----2fa`（兼容 `|` 分隔、`otpauth://` 密钥、以及带额外列的行）
- 套餐自动识别（free / plus / pro / team），界面直接显示
- 每账号分步骤进度（解析卡密 → 建立会话 → 登录 → 2FA → 换取 token → 生成文件 → 整理）
- 多账号自动打包：单账号文件为 `<邮箱>.json`，多个账号合成 zip
- 右下角自建匿名访客统计（今日访客 / 今日访问 / 近 10 分钟 + 7 天趋势，不存 IP/UA）
- 结果只在内存，任务过期自动销毁

## 协议链路（不依赖任何 CPA / sub2api 后端）

1. 本地生成 PKCE + state，拼出 `auth.openai.com/oauth/authorize` 授权链接
2. 用账号密码 + 本地生成的 2FA 动态码（RFC 6238）走完登录与授权，拿到 callback code
3. 用 code_verifier 换取 access / refresh / id token
4. 组装 cpa / sub2api / cockpit 三种结构（`vendor/lib/session_formats.py`）

`vendor/lib/` 只保留登录 / 授权 / 换取 token 所需部分；注册相关方法已由
`tools/build_open_source_bundle.py` 在打包时移除。

## 快速开始

```bash
# 1) 配代理（OpenAI 出口，必填）
export REAUTH_PROXY="host:port:user:pass"      # 或 socks5://user:pass@host:port

# 2) 起服务
docker compose up -d --build

# 3) 打开
open http://127.0.0.1:8899/                    # 默认端口只绑本机，建议前面再挂一层反代
```

本地开发：

```bash
pip install -r requirements.txt
pytest tests -q
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## 配置（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `REAUTH_PROXY` | 空（必填） | OpenAI 出口代理，`host:port:user:pass` 或 `socks5://…` |
| `REAUTH_CONCURRENCY` | 2 | 同时重登的账号数 |
| `REAUTH_MAX_ACCOUNTS` | 200 | 单次最多提交账号数 |
| `REAUTH_MAX_JOBS_PER_IP` | 3 | 同 IP 同时在跑的任务数 |
| `REAUTH_MIN_INTERVAL_SECONDS` | 3 | 两次登录之间的最小间隔 |
| `REAUTH_JOB_TTL_SECONDS` | 21600 | 任务结果保留时间 |
| `REAUTH_SESSION_CACHE_TTL_SECONDS` | 21600 | 会话缓存时间 |
| `REAUTH_SIGNING_SECRET` | 自动生成 | 会话令牌签名密钥（不填会自动生成并持久化） |
| `REAUTH_RATE_LIMIT_PER_MINUTE` | 120 | 每 IP 每分钟接口调用上限 |
| `REAUTH_SUBMIT_LIMIT_PER_MINUTE` | 6 | 每 IP 每分钟提交上限 |
| `REAUTH_UPSTREAM_BASE` / `REAUTH_UPSTREAM_KEY` | 空 | 可选：卡密兑换对接的上游成品站（不填则该通道关闭） |
| `REAUTH_GITHUB_URL` | 空 | 填了就在右下角显示 GitHub star 入口 |
| `REAUTH_DOMAIN` | reauth.example.com | Caddy 反代的站点域名 |
| `REAUTH_TRUSTED_IPS` | 127.0.0.1 | Caddy 回源白名单（通常填 Cloudflare 官方 IP 段） |

## 防滥用 / 防逆向

| 措施 | 位置 | 效果 |
| --- | --- | --- |
| 只允许白名单 IP 回源 | `Caddyfile` + `REAUTH_TRUSTED_IPS` | 直接扫源站 IP / 换 Host 一律 403 |
| 源站端口收口 | `docker-compose.yml` | 站点只绑 `127.0.0.1:8899`，对外只走反代 |
| 会话令牌 | `app/security.py` | `/api/submit`、`/api/convert` 必须带 `X-REAUTH-TOKEN`（HMAC 绑定 IP + UA） |
| 双层限流 | `app/security.py` | 超限返回 429 + `Retry-After` |
| 不暴露后端 | `app/main.py` | 关闭 `/docs`、`/openapi.json`；上游地址与密钥只在服务端 |
| 反指纹 / 反收录 | `Caddyfile`、`/robots.txt` | 去掉 `Server` 头、`noindex`、`Disallow: /`、CSP、X-Frame-Options |

浏览器一定会拿到前端代码，所以这里的加固目标是「不泄露密钥与后端逻辑 +
挡住脚本滥用 + 挡住直连源站」。

## 测试

```bash
pytest tests -q          # 57 个用例：解析 / 2FA / 格式转换 / 访客统计 /
                         # 会话缓存 / 上游兑换 / 安全与限流 / HTTP 层
```

## 免责声明

仅供个人处理自己账号的会话刷新使用。请遵守 OpenAI 服务条款与当地法律，
不要用于任何违规用途，作者不对使用后果负责。

# 🚂 RailGate — Rotating Proxy Gateway

[![CI](https://github.com/arynull/railgate/actions/workflows/ci.yml/badge.svg)](https://github.com/arynull/railgate/actions/workflows/ci.yml)

Give RailGate a list of upstream proxies (`http` / `https` / `socks4` / `socks5`,
as links or a `.txt` file) and it serves them through **one Railway URL** with
**smart rotation**: health-checked, speed-weighted, with automatic failover and
optional sticky sessions.

Railway exposes a single HTTP port per service, so RailGate offers two ways in:

- **Fetch API** (simplest) — `GET /fetch?url=https://target...`
- **HTTP forward proxy** (incl. `CONNECT` tunnelling for `https://` targets) —
  `curl -x https://<railway-host> http://target...`

The exit IP is always the upstream proxy's IP, never Railway's.

## Deploy on Railway

1. Fork/clone this repo, or push it and connect it in the Railway dashboard
   (or `railway init` + `railway up` from this directory).
2. Railway runs `npm start`; the port comes from `$PORT` automatically.
3. (Recommended) set the `GATEWAY_KEY` environment variable. From then on every
   request needs it:
   - Fetch API / management: `x-api-key: <key>` header (or `?key=<key>`)
   - Forward-proxy mode: `curl -x https://user:<key>@<host> ...`
4. Open `https://<your-app>.up.railway.app/` for the built-in web panel.

## Add proxies (3 ways)

```bash
APP=https://<your-app>.up.railway.app

# 1) JSON list
curl -X POST $APP/api/proxies -H "Content-Type: application/json" \
  -d '{"proxies":["socks5://user:pass@1.2.3.4:1080","http://5.6.7.8:8080"]}'

# 2) Upload a .txt file (one proxy per line)
curl -X POST $APP/api/proxies/upload -F "file=@proxies.txt"

# 3) Web panel — open $APP/ in a browser
```

Line format: `protocol://[user:pass@]host:port`, e.g.
`socks5://u:p@1.2.3.4:1080`, `http://5.6.7.8:8080`, or bare `9.10.11.12:3128`
(assumed `http`). Lines starting with `#` are ignored.

## Use it

```bash
# A) Fetch API
curl "$APP/fetch?url=https://api.ipify.org"

# Sticky session — same exit IP across requests
curl "$APP/fetch?url=https://api.ipify.org&session=USER123"

# B) HTTP forward proxy (http:// targets directly, https:// via CONNECT)
curl -x $APP_DOMAIN http://api.ipify.org
curl -x https://user:$GATEWAY_KEY@$APP_DOMAIN https://api.ipify.org
# Sticky session here: send header  X-Proxy-Session: USER123
```

Every response carries `x-proxy-used` (which upstream served it) and, for the
Fetch API, `x-proxy-latency-ms`.

## Smart rotation

- **Periodic health checks** (`CHECK_INTERVAL_MS`, default 60s) measure
  liveness + latency per upstream.
- **Speed-weighted random pick**; dead hosts and exponential-backoff hosts are
  skipped.
- **Automatic failover + retry** (`MAX_RETRIES`) across distinct upstreams.
- **Sticky sessions** (`SESSION_TTL_MS`, default 30 min) pin a client id to one
  upstream; the pin is released automatically if that proxy goes down.
- **SSRF guard** (`BLOCK_PRIVATE=true`): localhost / LAN / link-local /
  cloud-metadata targets are refused with `403`.
- **Empty pool**: with `ALLOW_DIRECT=true` requests go out directly, otherwise
  `502`.

## API reference

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | no | Liveness + counters |
| GET | `/` | no | Web panel (add / inspect / test) |
| GET | `/api/proxies` | yes | List upstreams + live status |
| POST | `/api/proxies` | yes | `{proxies:[...]}` or `{text:"..."}`; `replace:true` swaps the whole pool |
| POST | `/api/proxies/upload` | yes | Multipart `file` field (`.txt`) |
| DELETE | `/api/proxies?url=...` | yes | Remove one (`?clear=1` removes all) |
| POST | `/api/proxies/check` | yes | Health-check the pool right now |
| GET | `/api/stats` | yes | Request/error/session counters |
| DELETE | `/api/sessions/:id` | yes | Release a sticky session |
| GET/POST | `/fetch?url=...` | yes | Fetch a URL through the pool (`&session=`, `&retries=`, `&timeout=`) |
| ANY | `/proxy?url=...` | yes | Alias of `/fetch` |

Auth = `x-api-key` header or `?key=` query when `GATEWAY_KEY` is set.

## Environment variables

| Name | Default | Description |
|---|---|---|
| `PORT` | `3000` | Listen port (Railway injects its own) |
| `GATEWAY_KEY` | _(empty)_ | Shared secret; unset = no auth |
| `CHECK_INTERVAL_MS` | `60000` | Health-check period |
| `CHECK_TIMEOUT_MS` | `10000` | Per-proxy check timeout |
| `CHECK_URL` | `http://connectivitycheck.gstatic.com/generate_204` | Check target |
| `REQUEST_TIMEOUT_MS` | `30000` | Per-request upstream timeout |
| `MAX_RETRIES` | `3` | Failover attempts per request |
| `SESSION_TTL_MS` | `1800000` | Sticky-session lifetime |
| `BACKOFF_BASE_MS` / `BACKOFF_MAX_MS` | `30000` / `300000` | Exponential backoff for dead proxies |
| `ALLOW_DIRECT` | `true` | Go direct when the pool is empty |
| `BLOCK_PRIVATE` | `true` | Refuse private/internal targets (SSRF guard) |
| `MAX_BODY_MB` | `10` | Max forwarded request body |
| `DATA_FILE` | `./proxies.json` | Pool persistence file |

## Local development

```bash
npm install
npm test          # smoke tests (boots the real server on :3457)
node server.js    # PORT=3000 by default, panel at http://localhost:3000/
```

CI (`.github/workflows/ci.yml`) runs `npm ci` + `npm test` on Node 20/22 and a
boot check against `/health` on every push/PR to `main`.

## License

MIT — see [LICENSE](LICENSE).

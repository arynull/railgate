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

## Subscription sources (auto-fetch)

Instead of pasting proxies by hand, give RailGate **proxy-list URLs** and it
re-fetches each on its own timer, merging new proxies into the pool (then
health-checking them like any other upstream):

```bash
# Add one or more list URLs (immediate first fetch, then every 10 min here)
curl -X POST $APP/api/sources -H "Content-Type: application/json" \
  -d '{"urls":["https://example.com/proxies.txt"],"intervalMin":10}'

# Re-fetch one source now / change its timer / remove it
curl -X POST $APP/api/sources/<id>/fetch
curl -X PATCH $APP/api/sources/<id> -d '{"intervalMin":60}'
curl -X DELETE "$APP/api/sources/<id>?deleteProxies=1"
```

Per-source options: `intervalMin` (min 1), `prune:true` (drop this source's
proxies when they vanish from its list). Intake is capped (`SUB_MAX_PROXIES`,
default 3000) and the pool itself is capped (`MAX_POOL`, default 3000) — giant
public lists can't OOM the host or stall health-checks; checks run in
round-robin batches (`CHECK_BATCH_SIZE`, default 200). Or seed sources via the
`SUBSCRIPTION_URLS` env var (comma/newline-separated — handy as a Railway
Variable). The web panel has a dedicated **Sources** tab for all of this.

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
| GET | `/api/sources` | yes | List subscription sources + fetch status |
| POST | `/api/sources` | yes | `{url}` or `{urls:[...]}` + `intervalMin`, `prune`; fetches immediately |
| POST | `/api/sources/:id/fetch` | yes | Re-fetch one source now |
| PATCH | `/api/sources/:id` | yes | Change `intervalMin` / `prune` |
| DELETE | `/api/sources/:id` | yes | Remove source (`?deleteProxies=1` also drops its proxies) |
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
| `SUBSCRIPTION_URLS` | _(empty)_ | Seed subscription URLs (comma/newline-separated, e.g. Railway Variable) |
| `SUBSCRIPTION_INTERVAL_MS` | `600000` | Default re-fetch period per source (min 1 min) |
| `SUBSCRIPTION_TIMEOUT_MS` | `20000` | Fetch timeout per source |
| `SUBSCRIPTION_MAX_KB` | `2048` | Max list size accepted per fetch |
| `SUBSCRIPTION_PRUNE` | `false` | Default: drop a source's proxies when they vanish from its list |
| `SUBSCRIPTION_ALLOW_PRIVATE` | `false` | Accept private/LAN entries found in subscription lists |
| `MAX_POOL` | `3000` | Hard cap on pool size — oldest dead/unchecked dropped first (also trims on boot) |
| `CHECK_BATCH_SIZE` | `200` | Proxies health-checked per interval, round-robin |
| `SUB_MAX_PROXIES` | `3000` | Max proxies accepted from a single subscription fetch |

## Local development

```bash
npm install
npm test          # smoke + subscription suites (real servers on :3457/:3458 plus a local list)
node server.js    # PORT=3000 by default, panel at http://localhost:3000/
```

CI (`.github/workflows/ci.yml`) runs `npm ci` + `npm test` on Node 20/22 and a
boot check against `/health` on every push/PR to `main`.

## License

MIT — see [LICENSE](LICENSE).

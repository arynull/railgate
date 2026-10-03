/**
 * railgate — rotating proxy gateway (Railway-ready)
 *
 * What it does:
 *  - You POST a list of upstream proxies (http/https/socks4/socks5) as JSON or .txt file
 *  - It health-checks them periodically (alive + latency)
 *  - Clients call the ONE Railway URL and it rotates smartly between upstreams:
 *      1) Fetch API (simple):   GET/POST /fetch?url=https://target...&session=abc
 *      2) HTTP forward proxy:   curl -x https://<railway-host> http://target...
 *         (incl. CONNECT tunnelling for https:// targets)
 *  - Smart rotation: skips dead/backoff hosts, weights by speed, failover+retry,
 *    optional sticky sessions via ?session=ID
 *
 * Env:
 *  PORT=3000  GATEWAY_KEY= (optional shared secret; if set, required as
 *             x-api-key header or ?key= for /fetch + management APIs, and as
 *             Proxy-Authorization password for forward-proxy use)
 *  CHECK_INTERVAL_MS=60000  CHECK_TIMEOUT_MS=10000  CHECK_URL=
 *  REQUEST_TIMEOUT_MS=30000  MAX_RETRIES=3  SESSION_TTL_MS=1800000
 *  BACKOFF_BASE_MS=30000  BACKOFF_MAX_MS=300000
 *  ALLOW_DIRECT=true  (if no proxies configured, go direct instead of 502)
 *  BLOCK_PRIVATE=true (SSRF guard: refuse localhost/LAN/cloud-metadata targets)
 *  MAX_BODY_MB=10
 *  SUBSCRIPTION_URLS= (comma/newline-separated subscription links seeded on boot)
 *  SUBSCRIPTION_INTERVAL_MS=600000  SUBSCRIPTION_TIMEOUT_MS=20000
 *  SUBSCRIPTION_PRUNE=false (drop this source's proxies missing from latest fetch)
 *  SUBSCRIPTION_MAX_KB=2048  SUBSCRIPTION_ALLOW_PRIVATE=false
 *  MAX_POOL=3000 (hard cap on pool size — oldest dead/unchecked dropped first)
 *  CHECK_BATCH_SIZE=200 (incremental health-checks per interval, round-robin)
 *  SUB_MAX_PROXIES=3000 (max accepted from one subscription fetch)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const dns = require('dns').promises;
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { SocksClient } = require('socks');

// ---------------------------------------------------------------- config

const PORT = parseInt(process.env.PORT || '3000', 10);
const GATEWAY_KEY = (process.env.GATEWAY_KEY || '').trim();
const CHECK_INTERVAL_MS = parseInt(process.env.CHECK_INTERVAL_MS || '60000', 10);
const CHECK_TIMEOUT_MS = parseInt(process.env.CHECK_TIMEOUT_MS || '10000', 10);
const CHECK_URL = process.env.CHECK_URL || 'http://connectivitycheck.gstatic.com/generate_204';
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS || '30000', 10);
const MAX_RETRIES = parseInt(process.env.MAX_RETRIES || '3', 10);
const SESSION_TTL_MS = parseInt(process.env.SESSION_TTL_MS || '1800000', 10); // 30 min
const BACKOFF_BASE_MS = parseInt(process.env.BACKOFF_BASE_MS || '30000', 10);
const BACKOFF_MAX_MS = parseInt(process.env.BACKOFF_MAX_MS || '300000', 10);
const ALLOW_DIRECT = (process.env.ALLOW_DIRECT || 'true').toLowerCase() !== 'false';
const BLOCK_PRIVATE = (process.env.BLOCK_PRIVATE || 'true').toLowerCase() !== 'false';
const MAX_BODY_MB = parseInt(process.env.MAX_BODY_MB || '10', 10);
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'proxies.json');
// Auto-fetch subscriptions: poll proxy-list URLs every N minutes.
const SUBSCRIPTION_URLS = (process.env.SUBSCRIPTION_URLS || '').trim();
const SUBSCRIPTION_INTERVAL_MS = parseInt(process.env.SUBSCRIPTION_INTERVAL_MS || '600000', 10);
const SUBSCRIPTION_TIMEOUT_MS = parseInt(process.env.SUBSCRIPTION_TIMEOUT_MS || '20000', 10);
const SUBSCRIPTION_MAX_KB = parseInt(process.env.SUBSCRIPTION_MAX_KB || '2048', 10);
const SUBSCRIPTION_PRUNE = (process.env.SUBSCRIPTION_PRUNE || 'false').toLowerCase() !== 'false';
const SUBSCRIPTION_ALLOW_PRIVATE = (process.env.SUBSCRIPTION_ALLOW_PRIVATE || 'false').toLowerCase() !== 'false';
// Scale guards: a 40k+ pool kills health-checks, store writes and list
// responses on small hosts. Pool is capped, checks run incrementally.
const MAX_POOL = Math.max(100, parseInt(process.env.MAX_POOL || '3000', 10));
const CHECK_BATCH_SIZE = Math.max(10, parseInt(process.env.CHECK_BATCH_SIZE || '200', 10));
const SUB_MAX_PROXIES = Math.max(100, parseInt(process.env.SUB_MAX_PROXIES || '3000', 10));

// ---------------------------------------------------------------- store

// proxy entry: { url, protocol, alive, latencyMs, success, fail, consecFails,
//                lastCheck, backoffUntil, lastUsed, source }
// source entry: { id, url, intervalMs, prune, lastFetch, lastStatus, lastAdded,
//                 lastTotal, lastSkipped, lastError }
let proxies = [];
let sources = [];
let totalRequests = 0;
let totalErrors = 0;
let subStats = { runs: 0, lastRun: null };
const sessions = new Map(); // sessionId -> { proxyUrl, expires }

let saveTimer = null;
let savePending = false;
function saveStore() {
  // Debounced: health-checks + traffic dirty state constantly; on a big pool
  // a synchronous write per check blocks the event loop. Flush at most ~1/sec.
  savePending = true;
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    if (savePending) saveNow();
  }, 1000);
  if (saveTimer.unref) saveTimer.unref();
}
function saveNow() {
  savePending = false;
  try {
    const cleanSources = sources.map(s => {
      const { _timer, ...rest } = s;
      return rest;
    });
    fs.writeFileSync(DATA_FILE, JSON.stringify({ proxies, sources: cleanSources }));
  } catch (e) { console.error('[store] save failed:', e.message); }
}
process.on('beforeExit', () => { if (savePending) { try { saveNow(); } catch { /* */ } } });
function loadStore() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (Array.isArray(d.proxies)) proxies = d.proxies.filter(p => p && p.url);
      if (Array.isArray(d.sources)) sources = d.sources.filter(s => s && s.url);
      console.log(`[store] loaded ${proxies.length} proxies + ${sources.length} sources from ${DATA_FILE}`);
    }
  } catch (e) { console.error('[store] load failed:', e.message); }
}

// ---------------------------------------------------------------- parsing

function normalizeLine(line) {
  let s = (line || '').trim();
  if (!s || s.startsWith('#')) return null;
  // strip surrounding quotes
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1).trim();
  }
  // bare host:port -> assume http
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s)) s = 'http://' + s;
  let u;
  try { u = new URL(s); } catch { return { error: s }; }
  let proto = u.protocol.toLowerCase(); // http: https: socks: socks4: socks5:
  if (!['http:', 'https:', 'socks:', 'socks4:', 'socks5:'].includes(proto)) return { error: s };
  if (proto === 'socks:') proto = 'socks5:';
  if (!u.hostname) return { error: s };
  if (!u.port) {
    // WHATWG URL strips explicit default ports (http:80, https:443) so .port
    // reads '' — restore from the raw string. Truly port-less entries
    // (bare hostnames) stay invalid.
    const mPort = /:\/\/[^/]*:(\d+)(?=[/?#]|$)/.exec(s);
    if (!mPort) return { error: s };
    try { u.port = mPort[1]; } catch { return { error: s }; }
  }
  u.protocol = proto;
  return { url: u.toString(), protocol: proto.replace(':', '') };
}

function parseProxyList(text) {
  const added = [], invalid = [];
  const parts = String(text || '').split(/[\r\n,;]+/);
  for (const part of parts) {
    const r = normalizeLine(part);
    if (!r) continue;
    if (r.error) invalid.push(r.error);
    else added.push(r);
  }
  return { added, invalid };
}

function addProxies(items, replace) {
  if (replace) proxies = [];
  const seen = new Set(proxies.map(p => p.url));
  let added = 0, droppedForCap = 0;
  for (const it of items) {
    if (seen.has(it.url)) continue;
    seen.add(it.url);
    proxies.push({
      url: it.url, protocol: it.protocol,
      alive: null, latencyMs: null, success: 0, fail: 0,
      consecFails: 0, lastCheck: null, backoffUntil: 0, lastUsed: null,
    });
    added++;
  }
  droppedForCap = enforcePoolCap();
  saveStore();
  return { added, droppedForCap };
}

/** Hard pool cap: drop oldest dead/never-checked first, keep proven alive ones. */
function enforcePoolCap() {
  if (proxies.length <= MAX_POOL) return 0;
  const rank = p => (p.alive === true ? 2 : (p.alive === null ? 1 : 0));
  proxies.sort((a, b) => rank(a) - rank(b) || (a.lastUsed || 0) - (b.lastUsed || 0));
  const drop = proxies.length - MAX_POOL;
  proxies.splice(0, drop);
  return drop;
}

// ---------------------------------------------------------------- subscriptions (auto-fetch proxy lists)

function parseUrlList(text) {
  return String(text || '').split(/[\r\n,;]+/).map(s => s.trim()).filter(s => s && !s.startsWith('#'));
}

let subTimer = null;
const subFetching = new Set();

async function fetchSubscription(source, { manual = false } = {}) {
  if (!source || !source.url) throw Object.assign(new Error('missing-url'), { status: 400 });
  if (subFetching.has(source.id)) return { ok: false, skipped: 'already-running' };
  if (await targetBlocked(source.url)) throw Object.assign(new Error('forbidden-target: private source URL'), { status: 400 });
  subFetching.add(source.id);
  const t0 = Date.now();
  try {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(new Error('subscription-timeout')), SUBSCRIPTION_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(source.url, {
        signal: ctrl.signal, redirect: 'follow',
        headers: { 'user-agent': 'railgate-subscription/1.0', accept: 'text/plain,*/*' },
      });
    } finally { clearTimeout(to); }
    if (!res.ok) throw new Error(`subscription-http-${res.status}`);
    const ctype = (res.headers.get('content-type') || '').toLowerCase();
    if (ctype.includes('text/html')) throw new Error('subscription-not-a-proxy-list (got HTML)');
    const reader = res.body.getReader();
    const chunks = [];
    let bytes = 0;
    const cap = Math.max(64, SUBSCRIPTION_MAX_KB) * 1024;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.length;
      if (bytes > cap) { reader.cancel().catch(() => {}); throw new Error('subscription-too-large'); }
      chunks.push(value);
    }
    const text = Buffer.concat(chunks).toString('utf8');
    const { added, invalid } = parseProxyList(text);
    // cap intake: giant public lists (40k+) would blow the pool, the
    // health-checker and every list response on small hosts.
    let capped = 0;
    if (added.length > SUB_MAX_PROXIES) {
      capped = added.length - SUB_MAX_PROXIES;
      added.length = SUB_MAX_PROXIES;
    }
    // drop private/LAN entries from public lists unless explicitly allowed
    let items = added;
    let skippedPrivate = 0;
    if (!SUBSCRIPTION_ALLOW_PRIVATE) {
      items = [];
      for (const it of added) {
        try {
          const u = new URL(it.url);
          const h = u.hostname.toLowerCase();
          let priv = net.isIP(h) ? ipBlocked(h)
            : (['localhost', 'localhost.localdomain'].includes(h) || h.endsWith('.local') || h.endsWith('.internal'));
          if (!priv && !net.isIP(h)) {
            try { priv = ipBlocked((await dns.lookup(h)).address); } catch { priv = true; }
          }
          if (priv) { skippedPrivate++; continue; }
          items.push(it);
        } catch { skippedPrivate++; }
      }
    }
    const seen = new Set(items.map(i => i.url));
    let n = 0, skippedForCap = 0;
    const urlSet = new Set(proxies.map(p => p.url));
    for (const it of items) {
      if (urlSet.has(it.url)) continue;
      if (proxies.length >= MAX_POOL) { skippedForCap++; continue; }
      urlSet.add(it.url);
      proxies.push({
        url: it.url, protocol: it.protocol,
        alive: null, latencyMs: null, success: 0, fail: 0,
        consecFails: 0, lastCheck: null, backoffUntil: 0, lastUsed: null,
        source: source.id,
      });
      n++;
    }
    if (source.prune) {
      const before = proxies.length;
      proxies = proxies.filter(p => p.source !== source.id || seen.has(p.url));
      source.lastPruned = before - proxies.length;
    }
    source.lastFetch = Date.now();
    source.lastStatus = 'ok';
    source.lastError = null;
    source.lastAdded = n;
    source.lastTotal = items.length;
    source.lastSkipped = invalid.length + skippedPrivate + capped + skippedForCap;
    saveStore();
    console.log(`[sub] ${source.id}: +${n} new (${items.length} listed, ${invalid.length} invalid, ${skippedPrivate} private, ${capped} over-fetch-cap, ${skippedForCap} over-pool-cap) in ${Date.now() - t0}ms`);
    const r = await checkAll();
    subStats.runs++;
    subStats.lastRun = Date.now();
    if (manual) { /* immediate response below */ }
    return { ok: true, added: n, listed: items.length, invalid: invalid.length, skippedPrivate, capped, skippedForCap, checked: r.checked, ms: Date.now() - t0 };
  } catch (e) {
    source.lastFetch = Date.now();
    source.lastStatus = 'error';
    source.lastError = String(e.message || e).slice(0, 200);
    saveStore();
    console.error(`[sub] ${source.id}: ${source.lastError}`);
    throw Object.assign(new Error(source.lastError), { status: 502 });
  } finally {
    subFetching.delete(source.id);
  }
}

function scheduleSource(source) {
  if (source._timer) { clearInterval(source._timer); source._timer = null; }
  const ms = Math.max(60000, parseInt(source.intervalMs, 10) || SUBSCRIPTION_INTERVAL_MS);
  source._timer = setInterval(() => {
    fetchSubscription(source).catch(() => {});
  }, ms);
  if (source._timer.unref) source._timer.unref();
}

function rescheduleAllSources() {
  if (subTimer) { clearInterval(subTimer); subTimer = null; }
  for (const s of sources) scheduleSource(s);
}

function addSource(url, { intervalMs, prune } = {}) {
  let u;
  try { u = new URL(url); } catch { throw Object.assign(new Error('bad-url'), { status: 400 }); }
  if (!['http:', 'https:'].includes(u.protocol)) throw Object.assign(new Error('only http(s) subscription URLs'), { status: 400 });
  const clean = u.toString();
  let s = sources.find(x => x.url === clean);
  if (s) {
    if (intervalMs) s.intervalMs = intervalMs;
    if (prune !== undefined) s.prune = !!prune;
  } else {
    s = {
      id: 'sub' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
      url: clean,
      intervalMs: Math.max(60000, parseInt(intervalMs, 10) || SUBSCRIPTION_INTERVAL_MS),
      prune: prune !== undefined ? !!prune : SUBSCRIPTION_PRUNE,
      lastFetch: null, lastStatus: 'pending', lastError: null,
      lastAdded: 0, lastTotal: 0, lastSkipped: 0,
    };
    sources.push(s);
  }
  saveStore();
  scheduleSource(s);
  return s;
}

function removeSource(id) {
  const s = sources.find(x => x.id === id || x.url === id);
  if (!s) return null;
  if (s._timer) clearInterval(s._timer);
  sources = sources.filter(x => x !== s);
  saveStore();
  return s;
}

function backoffFor(p) {
  const n = Math.min(p.consecFails || 1, 6);
  return Math.min(BACKOFF_BASE_MS * Math.pow(2, n - 1), BACKOFF_MAX_MS);
}
function markSuccess(p, latencyMs) {
  p.alive = true; p.latencyMs = latencyMs; p.success++;
  p.consecFails = 0; p.backoffUntil = 0; p.lastCheck = Date.now(); p.lastUsed = Date.now();
}
function markFail(p, reason) {
  p.fail++; p.consecFails = (p.consecFails || 0) + 1;
  p.alive = false; p.lastCheck = Date.now();
  if (reason) p.lastError = String(reason).slice(0, 160);
  p.backoffUntil = Date.now() + backoffFor(p);
}

/** Effective dial URL: https entries that turned out to be plain-HTTP
 *  (extremely common in free "https" lists) are auto-downgraded. */
function effectiveUrl(p) {
  if (p.transport && p.transport !== p.protocol) {
    try { const u = new URL(p.url); u.protocol = p.transport + ':'; return u.toString(); }
    catch { return p.url; }
  }
  return p.url;
}
function effectiveProto(p) { return p.transport || p.protocol; }

// ---------------------------------------------------------------- proxy dialing
// node:http(s) + per-protocol agents. (The built-in undici fetch ignores an
// agent-base `dispatcher`, which silently sent every proxied request DIRECT —
// the old 'fetch failed' mystery. Raw node:http has no such bypass.)
const agentCache = new Map();
function agentFor(proxyUrl, secureTarget) {
  const cacheKey = `${secureTarget ? 'https' : 'http'}+${proxyUrl}`;
  let a = agentCache.get(cacheKey);
  if (!a) {
    const proto = new URL(proxyUrl).protocol;
    if (proto.startsWith('socks')) a = new SocksProxyAgent(proxyUrl);
    else if (proto === 'https:') a = new HttpsProxyAgent(proxyUrl);
    else a = secureTarget ? new HttpsProxyAgent(proxyUrl) : new HttpProxyAgent(proxyUrl);
    agentCache.set(cacheKey, a);
    if (agentCache.size > 500) {
      const oldest = agentCache.keys().next().value;
      try { agentCache.get(oldest).destroy(); } catch { /* */ }
      agentCache.delete(oldest);
    }
  }
  return a;
}

function errMsg(e) {
  return String((e && e.cause && e.cause.message) || (e && e.message) || e).slice(0, 160);
}

/** Plain node:http(s) request through `agent` (null = direct). */
function rawRequest(target, { method = 'GET', headers = {}, body = null, agent = null, timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(target);
    const lib = u.protocol === 'https:' ? https : http;
    const payload = (method === 'GET' || method === 'HEAD' || body == null)
      ? null : (Buffer.isBuffer(body) ? body : Buffer.from(String(body)));
    const req = lib.request({
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: (u.pathname || '/') + (u.search || ''),
      method,
      headers: { connection: 'close', ...(payload ? { 'content-length': String(payload.length) } : {}), ...headers },
      agent: agent || undefined,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error('request-timeout')));
    req.once('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** GET/POST through proxy entry `p` (null = direct), following redirects. */
async function fetchThroughProxy(p, target, { method = 'GET', headers = {}, body = null, timeoutMs = REQUEST_TIMEOUT_MS } = {}, maxRedirects = 5) {
  let url = target;
  let m = method;
  let b = body;
  for (let i = 0; i <= maxRedirects; i++) {
    const secure = new URL(url).protocol === 'https:';
    const out = await rawRequest(url, {
      method: m, headers, body: (m === 'GET' || m === 'HEAD') ? null : b,
      agent: p ? agentFor(effectiveUrl(p), secure) : null, timeoutMs,
    });
    if ([301, 302, 303, 307, 308].includes(out.status) && out.headers.location) {
      url = new URL(out.headers.location, url).toString();
      if (out.status === 303 || ((out.status === 301 || out.status === 302) && m === 'POST')) { m = 'GET'; b = null; }
      continue;
    }
    return out;
  }
  throw new Error('too-many-redirects');
}

function alivePool() {
  const now = Date.now();
  return proxies.filter(p => p.alive !== false && p.backoffUntil <= now);
}

/** Weighted random pick: weight = 1/(latency+50); unknown-latency gets medium weight. */
function weightedPick(pool) {
  if (pool.length === 0) return null;
  if (pool.length === 1) return pool[0];
  const weights = pool.map(p => (p.latencyMs == null ? 1 / 400 : 1 / (p.latencyMs + 50)));
  const total = weights.reduce((a, b) => a + b, 0);
  let r = Math.random() * total;
  for (let i = 0; i < pool.length; i++) {
    r -= weights[i];
    if (r <= 0) return pool[i];
  }
  return pool[pool.length - 1];
}

function pickProxy(sessionId) {
  // sticky session
  if (sessionId) {
    const s = sessions.get(sessionId);
    if (s) {
      if (s.expires < Date.now()) sessions.delete(sessionId);
      else {
        const pinned = proxies.find(p => p.url === s.proxyUrl);
        if (pinned && pinned.backoffUntil <= Date.now()) {
          s.expires = Date.now() + SESSION_TTL_MS;
          return pinned;
        }
      }
    }
  }
  let pool = alivePool();
  if (pool.length === 0) {
    // all dead/in-backoff: use least-recently-failed as last resort
    const sorted = [...proxies].sort((a, b) => (a.backoffUntil || 0) - (b.backoffUntil || 0));
    if (sorted.length) pool = [sorted[0]];
  }
  const p = weightedPick(pool);
  if (p && sessionId) sessions.set(sessionId, { proxyUrl: p.url, expires: Date.now() + SESSION_TTL_MS });
  return p;
}

setInterval(() => { // expire sticky sessions
  const now = Date.now();
  for (const [k, v] of sessions) if (v.expires < now) sessions.delete(k);
}, 60000).unref();

// ---------------------------------------------------------------- health checker

let checking = false;
let checkCursor = 0; // round-robin position for incremental checks
async function checkOne(p) {
  const t0 = Date.now();
  const tlsish = m => /ssl|tls|cert|eproto|wrong version|handshake|alert|record layer/i.test(String(m || ''));
  try {
    const out = await fetchThroughProxy(p, CHECK_URL, { timeoutMs: CHECK_TIMEOUT_MS });
    const status = out.status;
    if (status >= 200 && status < 400) { markSuccess(p, Date.now() - t0); return; }
    // plain-HTTP entry that is actually a TLS-only proxy answers 400 to plain HTTP
    if (p.protocol === 'http' && !p.transport && status === 400) {
      try {
        p.transport = 'https';
        const out2 = await fetchThroughProxy(p, CHECK_URL, { timeoutMs: CHECK_TIMEOUT_MS });
        if (out2.status >= 200 && out2.status < 400) { markSuccess(p, Date.now() - t0); return; }
        markFail(p, 'http-' + out2.status);
        return;
      } catch (e2) { p.transport = null; markFail(p, errMsg(e2)); return; }
    }
    markFail(p, 'http-' + status);
  } catch (e) {
    const msg = errMsg(e);
    // "https" entry that is actually plain HTTP: the TLS handshake blows up —
    // downgrade once and retry instead of marking dead.
    if (p.protocol === 'https' && (p.transport || p.protocol) === 'https' && tlsish(msg)) {
      try {
        p.transport = 'http';
        const out2 = await fetchThroughProxy(p, CHECK_URL, { timeoutMs: CHECK_TIMEOUT_MS });
        if (out2.status >= 200 && out2.status < 400) { markSuccess(p, Date.now() - t0); return; }
        markFail(p, 'http-' + out2.status);
        return;
      } catch (e2) { markFail(p, errMsg(e2)); return; }
    }
    markFail(p, msg);
  }
}

// Incremental: at most CHECK_BATCH_SIZE per round, round-robin so every
// proxy is eventually covered. A 40k pool no longer means 40k concurrent
// connections + a multi-MB store rewrite in one go.
async function checkAll({ full = false } = {}) {
  if (checking || proxies.length === 0) return { checked: 0 };
  checking = true;
  try {
    let batch;
    if (full || proxies.length <= CHECK_BATCH_SIZE) {
      batch = proxies;
    } else {
      batch = [];
      for (let i = 0; i < CHECK_BATCH_SIZE; i++) {
        batch.push(proxies[(checkCursor + i) % proxies.length]);
      }
      checkCursor = (checkCursor + CHECK_BATCH_SIZE) % proxies.length;
    }
    const CONC = 10;
    for (let i = 0; i < batch.length; i += CONC) {
      await Promise.allSettled(batch.slice(i, i + CONC).map(checkOne));
    }
    saveStore(); // debounced — flushes ~1/sec, not per check
    return { checked: batch.length, pool: proxies.length };
  } finally { checking = false; }
}

setInterval(() => {
  checkAll().then(r => { if (r.checked) console.log(`[check] ${r.checked} proxies checked`); });
}, CHECK_INTERVAL_MS).unref();

// ---------------------------------------------------------------- SSRF guard

function ipBlocked(ip) {
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip === '169.254.169.254') return true;
  if (ip.startsWith('172.')) {
    const n = parseInt(ip.split('.')[1], 10);
    if (n >= 16 && n <= 31) return true;
  }
  if (/^(fc|fd)[0-9a-f]{0,2}:/i.test(ip) || ip.toLowerCase().startsWith('fe80:')) return true;
  if (ip.startsWith('169.254.')) return true;
  return false;
}

async function targetBlocked(target) {
  if (!BLOCK_PRIVATE) return false;
  let u;
  try { u = new URL(target); } catch { return 'bad-url'; }
  if (!['http:', 'https:'].includes(u.protocol)) return 'protocol-not-allowed';
  const h = u.hostname.toLowerCase();
  if (['localhost', 'localhost.localdomain'].includes(h) || h.endsWith('.local') || h.endsWith('.internal')) return 'private-host';
  if (net.isIP(h)) return ipBlocked(h) ? 'private-ip' : false;
  try {
    const { address } = await dns.lookup(h);
    if (ipBlocked(address)) return 'private-ip';
  } catch { return 'dns-failed'; }
  return false;
}

// ---------------------------------------------------------------- fetch-via-proxy core

const HOP_HEADERS = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-encoding', 'content-length', 'host']);

async function fetchViaRotator(target, { method = 'GET', headers = {}, body = null, sessionId = null, timeoutMs = REQUEST_TIMEOUT_MS, retries = MAX_RETRIES } = {}) {
  const blocked = await targetBlocked(target);
  if (blocked) { const e = new Error('forbidden-target: ' + blocked); e.status = 403; throw e; }

  const cleanHeaders = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (!HOP_HEADERS.has(k.toLowerCase())) cleanHeaders[k] = v;
  }

  const attempts = Math.max(1, Math.min(retries, Math.max(proxies.length, 1)));
  let lastErr = null, triedDirect = false;

  for (let i = 0; i < attempts; i++) {
    const p = proxies.length ? pickProxy(sessionId) : null;
    if (!p) {
      if (ALLOW_DIRECT && !triedDirect) {
        triedDirect = true;
        try {
          return await doFetch(null, '[direct]');
        } catch (e) { lastErr = e; break; }
      }
      break;
    }
    try {
      return await doFetch(p, p.url);
    } catch (e) {
      lastErr = e;
      if (!String(e.message || '').startsWith('forbidden-target')) markFail(p);
      // on sticky session, unpin so next attempt picks a different proxy
      if (sessionId) sessions.delete(sessionId);
    }
  }
  totalErrors++;
  throw lastErr || Object.assign(new Error(proxies.length ? 'all-proxies-failed' : 'no-proxies-configured'), { status: 502 });

  async function doFetch(p, label) {
    const t0 = Date.now();
    let out;
    try {
      out = await fetchThroughProxy(p, target, {
        method, headers: cleanHeaders,
        body: (method === 'GET' || method === 'HEAD' || body == null) ? undefined : body,
        timeoutMs,
      });
    } catch (e) {
      // one-shot http<->https downgrade (same as health-checker)
      const m = errMsg(e);
      if (p && p.protocol === 'https' && (p.transport || p.protocol) === 'https' &&
          /ssl|tls|cert|eproto|wrong version|handshake|alert|record layer/i.test(m)) {
        p.transport = 'http';
        out = await fetchThroughProxy(p, target, {
          method, headers: cleanHeaders,
          body: (method === 'GET' || method === 'HEAD' || body == null) ? undefined : body,
          timeoutMs,
        });
      } else throw e;
    }
    const outHeaders = {};
    for (const [k, v] of Object.entries(out.headers || {})) {
      if (!HOP_HEADERS.has(k.toLowerCase())) outHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
    }
    totalRequests++;
    if (p) { markSuccess(p, Date.now() - t0); saveStore(); }
    return { status: out.status, headers: outHeaders, body: out.body, proxy: label, latencyMs: Date.now() - t0 };
  }
}

// ---------------------------------------------------------------- app

const app = express();
app.use(cors());
app.disable('x-powered-by');

// --- forward-proxy requests for plain http:// targets (absolute-URI form).
// Must run BEFORE body parsers so we can stream the raw body ourselves.
app.use((req, res, next) => {
  if (/^https?:\/\//i.test(req.url || '')) {
    handleForwardProxy(req, res).catch(e => {
      console.error('[forward]', e.message);
      if (!res.headersSent) res.status(e.status || 502).json({ ok: false, error: e.message });
    });
    return;
  }
  next();
});

// Fetch API routes BEFORE body parsers so POST bodies stay raw and forward byte-identical.
const rawBody = express.raw({ type: '*/*', limit: `${MAX_BODY_MB}mb` });
app.get('/fetch', gatewayAuth, handleFetch);
app.post('/fetch', gatewayAuth, rawBody, handleFetch);
app.all('/proxy', gatewayAuth, rawBody, handleFetch);

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// --- auth
function gatewayAuth(req, res, next) {
  if (!GATEWAY_KEY) return next();
  const key = req.headers['x-api-key'] || req.query.key;
  let proxyAuth = req.headers['proxy-authorization'];
  let ok = key === GATEWAY_KEY;
  if (!ok && proxyAuth) {
    try {
      const decoded = Buffer.from(String(proxyAuth).split(' ')[1] || '', 'base64').toString();
      ok = decoded.includes(GATEWAY_KEY);
    } catch { /* no */ }
  }
  if (!ok) return res.status(401).json({ ok: false, error: 'unauthorized' });
  next();
}

async function handleForwardProxy(req, res) {
  if (GATEWAY_KEY) {
    const pa = req.headers['proxy-authorization'];
    let ok = false;
    if (pa) {
      try {
        ok = Buffer.from(String(pa).split(' ')[1] || '', 'base64').toString().includes(GATEWAY_KEY);
      } catch { /* no */ }
    }
    if (!ok) {
      res.setHeader('Proxy-Authenticate', 'Basic realm="railgate"');
      return res.status(407).json({ ok: false, error: 'proxy-auth-required' });
    }
  }
  const target = req.url; // absolute URI
  const sessionId = req.query?.session || req.headers['x-proxy-session'] || null;
  const chunks = [];
  req.on('data', c => {
    chunks.push(c);
    if (Buffer.concat(chunks).length > MAX_BODY_MB * 1024 * 1024) { req.destroy(new Error('body-too-large')); }
  });
  await new Promise((resolve, reject) => {
    req.on('end', resolve); req.on('error', reject);
  });
  const body = chunks.length ? Buffer.concat(chunks) : null;
  const headers = { ...req.headers };
  delete headers['proxy-authorization']; delete headers['proxy-connection'];
  const out = await fetchViaRotator(target, {
    method: req.method, headers, body,
    sessionId: sessionId ? String(sessionId) : null,
  });
  res.status(out.status);
  for (const [k, v] of Object.entries(out.headers)) { try { res.setHeader(k, v); } catch { /* skip */ } }
  res.setHeader('x-proxy-used', out.proxy);
  res.send(out.body);
}

// --- health
app.get('/health', (req, res) => {
  res.json({
    ok: true, service: 'railgate', time: new Date().toISOString(),
    upstreams: proxies.length,
    alive: proxies.filter(p => p.alive === true).length,
    requests: totalRequests, errors: totalErrors,
    sessions: sessions.size,
  });
});

// --- management API
function summarizePool() {
  let alive = 0, dead = 0, unchecked = 0;
  const byProto = {};
  for (const p of proxies) {
    if (p.alive === true) alive++;
    else if (p.alive === false) dead++;
    else unchecked++;
    byProto[p.protocol] = (byProto[p.protocol] || 0) + 1;
  }
  return { total: proxies.length, alive, dead, unchecked, byProto, maxPool: MAX_POOL };
}
app.get('/api/proxies', gatewayAuth, (req, res) => {
  const limit = Math.max(1, Math.min(parseInt(req.query.limit, 10) || 200, 1000));
  const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
  const filter = (req.query.filter || 'all').toLowerCase();
  const q = (req.query.q || '').toLowerCase();
  let list = proxies;
  if (filter === 'alive') list = list.filter(p => p.alive === true);
  else if (filter === 'dead') list = list.filter(p => p.alive === false);
  else if (filter === 'unchecked') list = list.filter(p => p.alive == null);
  if (q) list = list.filter(p => p.url.toLowerCase().includes(q) || (p.protocol || '').includes(q));
  const page = list.slice(offset, offset + limit);
  const lastErrors = {};
  for (const p of proxies) {
    if (p.lastError) lastErrors[p.lastError] = (lastErrors[p.lastError] || 0) + 1;
  }
  const topErrors = Object.entries(lastErrors)
    .sort((a, b) => b[1] - a[1]).slice(0, 8)
    .map(([error, count]) => ({ error, count }));
  res.json({
    ok: true, count: proxies.length, offset, limit, returned: page.length,
    summary: summarizePool(), topErrors,
    proxies: page.map(p => ({
      url: redact(p.url), protocol: p.protocol, transport: p.transport || null,
      alive: p.alive, lastError: p.lastError || null,
      latencyMs: p.latencyMs, success: p.success, fail: p.fail,
      lastCheck: p.lastCheck, lastUsed: p.lastUsed, source: p.source || null,
      backoffSec: p.backoffUntil > Date.now() ? Math.ceil((p.backoffUntil - Date.now()) / 1000) : 0,
    })),
  });
});

app.post('/api/proxies', gatewayAuth, async (req, res) => {
  const { proxies: list, text, replace } = req.body || {};
  const raw = Array.isArray(list) ? list.join('\n') : (text || '');
  if (!raw.trim()) return res.status(400).json({ ok: false, error: 'empty-list (send {proxies:[...]} or {text:"..."} )' });
  const { added, invalid } = parseProxyList(raw);
  const { added: n, droppedForCap } = addProxies(added, !!replace);
  const r = await checkAll();
  res.json({ ok: true, added: n, invalid, droppedForCap, total: proxies.length, checked: r.checked, summary: summarizePool() });
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024 } });
app.post('/api/proxies/upload', gatewayAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, error: 'no file (field name "file", .txt)' });
  const { added, invalid } = parseProxyList(req.file.buffer.toString('utf8'));
  const { added: n, droppedForCap } = addProxies(added, req.query.replace === '1');
  const r = await checkAll();
  res.json({ ok: true, added: n, invalid, droppedForCap, total: proxies.length, checked: r.checked, summary: summarizePool() });
});

app.delete('/api/proxies', gatewayAuth, (req, res) => {
  const url = req.query.url || (req.body && req.body.url);
  if (url) {
    const before = proxies.length;
    proxies = proxies.filter(p => p.url !== url && redact(p.url) !== url);
    saveStore();
    return res.json({ ok: true, removed: before - proxies.length, total: proxies.length });
  }
  if (req.query.clear === '1') {
    proxies = []; sessions.clear(); saveStore();
    return res.json({ ok: true, cleared: true, total: 0 });
  }
  res.status(400).json({ ok: false, error: 'pass ?url=... or ?clear=1' });
});

app.post('/api/proxies/check', gatewayAuth, async (req, res) => {
  const full = (req.query.full === '1') || req.query.full === 'true';
  const r = await checkAll({ full });
  res.json({ ok: true, ...r, alive: proxies.filter(p => p.alive === true).length });
});

app.get('/api/stats', gatewayAuth, (req, res) => {
  res.json({
    ok: true, requests: totalRequests, errors: totalErrors,
    sessions: sessions.size, upstreams: proxies.length,
    alive: proxies.filter(p => p.alive === true).length,
  });
});

app.delete('/api/sessions/:id', gatewayAuth, (req, res) => {
  const gone = sessions.delete(req.params.id);
  res.json({ ok: true, released: gone });
});

// --- Subscription sources (auto-fetch proxy lists on a timer)
function publicSource(s) {
  const { _timer, ...rest } = s;
  return rest;
}
app.get('/api/sources', gatewayAuth, (req, res) => {
  res.json({ ok: true, count: sources.length, sources: sources.map(publicSource), stats: subStats });
});
app.post('/api/sources', gatewayAuth, async (req, res) => {
  const { urls, url, intervalMs, intervalMin, prune, fetchNow } = req.body || {};
  const list = Array.isArray(urls) ? urls : (url ? [url] : []);
  if (!list.length) return res.status(400).json({ ok: false, error: 'empty (send {url:"https://..."} or {urls:[...]})' });
  const ms = intervalMs || (intervalMin ? Math.round(Number(intervalMin) * 60000) : undefined);
  const created = [];
  try {
    for (const u of list) created.push(publicSource(addSource(String(u), { intervalMs: ms, prune })));
  } catch (e) {
    return res.status(e.status || 400).json({ ok: false, error: e.message });
  }
  let fetches = null;
  if (fetchNow !== false) {
    fetches = [];
    for (const c of created) {
      const s = sources.find(x => x.url === c.url);
      try { fetches.push({ url: c.url, ...(await fetchSubscription(s, { manual: true })) }); }
      catch (e) { fetches.push({ url: c.url, ok: false, error: e.message }); }
    }
  }
  const totalAdded = fetches ? fetches.reduce((a, f) => a + (f.added || 0), 0) : 0;
  res.json({ ok: true, added: created.length, sources: created, total: proxies.length, fetches, totalAdded });
});
app.post('/api/sources/:id/fetch', gatewayAuth, async (req, res) => {
  const s = sources.find(x => x.id === req.params.id || x.url === req.params.id);
  if (!s) return res.status(404).json({ ok: false, error: 'source-not-found' });
  try {
    const r = await fetchSubscription(s, { manual: true });
    res.json({ ok: true, ...r, source: publicSource(s), total: proxies.length });
  } catch (e) {
    res.status(e.status || 502).json({ ok: false, error: e.message, source: publicSource(s) });
  }
});
app.patch('/api/sources/:id', gatewayAuth, (req, res) => {
  const s = sources.find(x => x.id === req.params.id || x.url === req.params.id);
  if (!s) return res.status(404).json({ ok: false, error: 'source-not-found' });
  const { intervalMs, intervalMin, prune } = req.body || {};
  if (intervalMs || intervalMin) s.intervalMs = Math.max(60000, Math.round(Number(intervalMs || intervalMin * 60000)));
  if (prune !== undefined) s.prune = !!prune;
  saveStore(); scheduleSource(s);
  res.json({ ok: true, source: publicSource(s) });
});
app.delete('/api/sources/:id', gatewayAuth, (req, res) => {
  const { deleteProxies } = req.query || {};
  const s = removeSource(req.params.id);
  if (!s) return res.status(404).json({ ok: false, error: 'source-not-found' });
  let removed = 0;
  if (deleteProxies === '1') {
    const before = proxies.length;
    proxies = proxies.filter(p => p.source !== s.id);
    removed = before - proxies.length;
    saveStore();
  }
  res.json({ ok: true, removed: s.url, proxiesRemoved: removed, total: proxies.length, sources: sources.length });
});

// --- Fetch API (the simple way to use the gateway)
async function handleFetch(req, res) {
  const q = req.method === 'GET' ? req.query : { ...req.query, ...(req.body || {}) };
  const target = q.url;
  if (!target) return res.status(400).json({ ok: false, error: 'missing ?url=https://...' });
  const sessionId = q.session ? String(q.session) : null;
  const timeoutMs = Math.min(parseInt(q.timeout || String(REQUEST_TIMEOUT_MS), 10) || REQUEST_TIMEOUT_MS, 120000);
  const retries = Math.min(parseInt(q.retries || String(MAX_RETRIES), 10) || MAX_RETRIES, 10);
  let body = null;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    if (Buffer.isBuffer(req.body)) body = req.body;
    else if (typeof req.body === 'string') body = req.body;
    else if (req.body && Object.keys(req.body).length && !q.url) body = JSON.stringify(req.body);
    else if (q.body) body = q.body;
  }
  try {
    const out = await fetchViaRotator(target, { method: req.method === 'GET' ? 'GET' : (q.method || req.method), headers: forwardHeaders(req.headers), body, sessionId, timeoutMs, retries });
    res.status(out.status);
    for (const [k, v] of Object.entries(out.headers)) { try { res.setHeader(k, v); } catch { /* skip */ } }
    res.setHeader('x-proxy-used', out.proxy);
    res.setHeader('x-proxy-latency-ms', String(out.latencyMs));
    res.send(out.body);
  } catch (e) {
    res.status(e.status || 502).json({ ok: false, error: e.message });
  }
}
function forwardHeaders(h) {
  const o = { ...h };
  for (const k of ['host', 'connection', 'content-length', 'x-api-key', 'proxy-authorization']) delete o[k.toLowerCase()];
  return o;
}
// (fetch routes registered above, before body parsers)

function redact(u) {
  try {
    const x = new URL(u);
    if (x.password) x.password = '***';
    return x.toString();
  } catch { return u; }
}

// ---------------------------------------------------------------- server + CONNECT (https forward proxy)

const server = http.createServer(app);

server.on('connect', async (req, clientSocket, head) => {
  // req.url = "host:port" of the FINAL target
  const target = req.url;
  const m = /^([^:]+):(\d+)$/.exec(target || '');
  if (!m) { clientSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); clientSocket.destroy(); return; }
  const [, destHost, destPortStr] = m;
  const destPort = parseInt(destPortStr, 10);

  if (GATEWAY_KEY) {
    let ok = false;
    const pa = req.headers['proxy-authorization'];
    if (pa) {
      try { ok = Buffer.from(String(pa).split(' ')[1] || '', 'base64').toString().includes(GATEWAY_KEY); } catch { /* no */ }
    }
    if (!ok) {
      clientSocket.write('HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: Basic realm="railgate"\r\n\r\n');
      clientSocket.destroy(); return;
    }
  }

  if (await targetBlocked(`http://${destHost}:${destPort}`)) {
    clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); clientSocket.destroy(); return;
  }

  const p = proxies.length ? pickProxy(null) : null;
  try {
    let upstream;
    if (!p) {
      if (!ALLOW_DIRECT) throw new Error('no-proxies-configured');
      upstream = await openDirect(destHost, destPort);
    } else if (effectiveProto(p) === 'http' || effectiveProto(p) === 'https') {
      try {
        upstream = await openViaHttpProxy(effectiveUrl(p), destHost, destPort);
      } catch (e) {
        // same TLS-mismatch retry: https entry that is actually plain HTTP
        if (p.protocol === 'https' && (p.transport || p.protocol) === 'https' &&
            /ssl|tls|cert|eproto|wrong version|handshake|alert|econnreset/i.test(String((e && e.message) || e))) {
          p.transport = 'http';
          upstream = await openViaHttpProxy(effectiveUrl(p), destHost, destPort);
        } else throw e;
      }
    } else {
      upstream = await openViaSocks(p.url, destHost, destPort);
    }
    if (p) { p.lastUsed = Date.now(); p.success++; saveStore(); }
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) upstream.write(head);
    upstream.pipe(clientSocket); clientSocket.pipe(upstream);
    const done = () => { try { upstream.destroy(); } catch { /* */ } try { clientSocket.destroy(); } catch { /* */ } };
    upstream.on('error', done); clientSocket.on('error', done);
  } catch (e) {
    if (p) markFail(p);
    console.error('[connect]', target, e.message);
    try { clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); } catch { /* */ }
    clientSocket.destroy();
  }
});

// NOTE on node fetch: ProxyAgent extends agent-base's Agent, which only
// plugs into node:http. The built-in undici fetch ignores `dispatcher`
// unless it is an undici Dispatcher — so any dispatcher here is silently
// bypassed and every proxied request goes DIRECT (and a direct hit from
// Railway that fails looks exactly like "fetch failed" on the proxy).
// We therefore dial through the proxy with plain node:http(s) requests and
// correct per-protocol agents (Http/Https/SocksProxyAgent). CONNECT tunnels
// are handled by those agents; `tunnelViaHttpProxy` below is the raw-socket
// path for the server's own CONNECT handler.

function dialTcp(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port, timeout: timeoutMs || REQUEST_TIMEOUT_MS }, () => {
      s.setTimeout(0);
      resolve(s);
    });
    s.once('timeout', () => { s.destroy(new Error('tcp-connect-timeout')); });
    s.once('error', reject);
  });
}

/** Open a TCP tunnel to destHost:destPort THROUGH an http/https upstream. */
function tunnelViaHttpProxy(proxyUrl, destHost, destPort, timeoutMs) {
  return new Promise((resolve, reject) => {
    const pu = new URL(proxyUrl);
    const defPort = pu.protocol === 'https:' ? 443 : 8080;
    const port = parseInt(pu.port, 10) || defPort;
    const onSocket = (s) => {
      let hdr = `CONNECT ${destHost}:${destPort} HTTP/1.1\r\nHost: ${destHost}:${destPort}\r\n`;
      if (pu.username) {
        try {
          hdr += `Proxy-Authorization: Basic ${Buffer.from(`${decodeURIComponent(pu.username)}:${decodeURIComponent(pu.password || '')}`).toString('base64')}\r\n`;
        } catch { /* ignore bad encoding */ }
      }
      hdr += 'Connection: keep-alive\r\n\r\n';
      let buf = '';
      const timer = setTimeout(() => { s.destroy(new Error('proxy-connect-timeout')); }, timeoutMs || REQUEST_TIMEOUT_MS);
      const onData = (chunk) => {
        buf += chunk.toString('utf8');
        if (!buf.includes('\r\n\r\n')) return;
        clearTimeout(timer);
        s.removeListener('data', onData);
        const status = parseInt((buf.split(' ')[1] || '0'), 10);
        if (status >= 200 && status < 300) resolve(s);
        else { s.destroy(); reject(new Error('upstream-connect-' + status)); }
      };
      s.on('data', onData);
      s.once('error', (e) => { clearTimeout(timer); reject(e); });
      s.write(hdr);
    };
    if (pu.protocol === 'https:') {
      const tlsSock = tls.connect({ host: pu.hostname, port, timeout: timeoutMs || REQUEST_TIMEOUT_MS }, () => {
        tlsSock.setTimeout(0);
        onSocket(tlsSock);
      });
      tlsSock.once('timeout', () => tlsSock.destroy(new Error('tls-connect-timeout')));
      tlsSock.once('error', reject);
    } else {
      dialTcp(pu.hostname, port, timeoutMs).then(onSocket, reject);
    }
  });
}

/** statusLine: 'HTTP/1.1 200 OK' + headers map from a raw response head. */
function parseHead(head) {
  const lines = head.split('\r\n');
  const status = parseInt((lines[0].split(' ')[1] || '0'), 10);
  const headers = {};
  for (const ln of lines.slice(1)) {
    const i = ln.indexOf(':');
    if (i > 0) headers[ln.slice(0, i).trim().toLowerCase()] = ln.slice(i + 1).trim();
  }
  return { status, headers };
}

/**
 * GET/POST `target` over an already-tunneled socket (plain or TLS to the
 * destination). Handles 1xx/redirects and chunked + content-length bodies,
 * cap 25MB.
 */
function httpOverSocket(socket, target, { method = 'GET', headers = {}, body = null, timeoutMs = REQUEST_TIMEOUT_MS, tlsToDest = false, destHost = null, maxBody = 25 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(target);
    const host = destHost || u.hostname;
    const port = u.port || (u.protocol === 'https:' ? '443' : '80');
    const pathQ = (u.pathname || '/') + (u.search || '');
    const useTls = tlsToDest || u.protocol === 'https:';
    const doRun = (sock) => {
      const h = { host: u.host, connection: 'close', ...headers };
      delete h['content-length'];
      let payload = null;
      if (method !== 'GET' && method !== 'HEAD' && body != null) {
        payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
        h['content-length'] = String(payload.length);
      }
      let req = `${method} ${pathQ} HTTP/1.1\r\n`;
      for (const [k, v] of Object.entries(h)) req += `${k}: ${v}\r\n`;
      req += '\r\n';
      const timer = setTimeout(() => { try { sock.destroy(new Error('target-timeout')); } catch { /* */ } }, timeoutMs);
      let buf = Buffer.alloc(0);
      let settled = false;
      const done = (err, out) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { sock.destroy(); } catch { /* */ }
        if (err) reject(err);
        else resolve(out);
      };
      const onData = (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length > maxBody + 65536) { sock.removeListener('data', onData); done(new Error('response-too-large')); return; }
        for (;;) {
          const hi = buf.indexOf('\r\n\r\n');
          if (hi < 0) return;
          const { status, headers: rh } = parseHead(buf.slice(0, hi).toString('utf8'));
          if (status >= 100 && status < 200) { buf = buf.slice(hi + 4); continue; }
          if ([301, 302, 303, 307, 308].includes(status) && rh.location) {
            sock.removeListener('data', onData);
            let next;
            try { next = new URL(rh.location, target).toString(); }
            catch { done(new Error('bad-redirect')); return; }
            done(null, { redirect: next, redirectStatus: status });
            return;
          }
          let bodyBuf = null;
          if (String(rh['transfer-encoding'] || '').toLowerCase().includes('chunked')) {
            // minimal chunked parser
            let pos = hi + 4;
            const parts = [];
            for (;;) {
              const le = buf.indexOf('\r\n', pos);
              if (le < 0) return; // need more
              const size = parseInt(buf.slice(pos, le).toString('utf8').trim().split(';')[0], 16);
              if (Number.isNaN(size)) { sock.removeListener('data', onData); done(new Error('bad-chunk')); return; }
              if (buf.length < le + 2 + size + 2) return; // need more
              if (size === 0) { bodyBuf = Buffer.concat(parts); buf = buf.slice(le + 4); break; }
              parts.push(buf.slice(le + 2, le + 2 + size));
              pos = le + 2 + size + 2;
            }
          } else if (rh['content-length'] != null) {
            const len = parseInt(rh['content-length'], 10);
            if (Number.isNaN(len) || len < 0) { sock.removeListener('data', onData); done(new Error('bad-length')); return; }
            if (buf.length < hi + 4 + len) return; // need more
            bodyBuf = buf.slice(hi + 4, hi + 4 + len);
          } else {
            // no length and not chunked: read until close — wait for more/end
            return;
          }
          sock.removeListener('data', onData);
          done(null, { status, headers: rh, body: bodyBuf || Buffer.alloc(0) });
          return;
        }
      };
      sock.on('data', onData);
      sock.once('end', () => {
        // server closed without length: take what we have past headers
        const hi = buf.indexOf('\r\n\r\n');
        if (hi >= 0 && !settled) {
          const { status, headers: rh } = parseHead(buf.slice(0, hi).toString('utf8'));
          done(null, { status, headers: rh, body: buf.slice(hi + 4) });
        } else if (!settled) done(new Error('connection-closed'));
      });
      sock.once('error', (e) => done(e));
      sock.write(req);
      if (payload) sock.write(payload);
    };
    if (useTls) {
      const t = tls.connect({ socket, host, port: parseInt(port, 10), servername: host }, () => doRun(t));
      t.once('error', reject);
    } else doRun(socket);
  });
}

function openViaHttpProxy(proxyUrl, destHost, destPort) {
  return tunnelViaHttpProxy(proxyUrl, destHost, destPort, REQUEST_TIMEOUT_MS);
}

function openDirect(host, port) {
  return dialTcp(host, port, REQUEST_TIMEOUT_MS);
}

async function openViaSocks(proxyUrl, destHost, destPort) {
  const pu = new URL(proxyUrl);
  const type = (pu.protocol === 'socks4:' || pu.protocol === 'socks4a:') ? 4 : 5;
  const { socket } = await SocksClient.createConnection({
    proxy: {
      host: pu.hostname, port: parseInt(pu.port, 10),
      type,
      userId: pu.username ? decodeURIComponent(pu.username) : undefined,
      password: pu.password ? decodeURIComponent(pu.password) : undefined,
    },
    destination: { host: destHost, port: destPort },
    command: 'connect',
    timeout: REQUEST_TIMEOUT_MS,
  });
  return socket;
}

// ---------------------------------------------------------------- boot

loadStore();
// trim any oversized pool carried over from before the cap existed
// (keeps proven-alive first), then seed subscription URLs and schedule.
const bootDropped = enforcePoolCap();
if (bootDropped) {
  console.log(`[store] trimmed ${bootDropped} excess proxies to MAX_POOL=${MAX_POOL}`);
  saveNow();
}
// seed subscription URLs from env (Railway Variables), then schedule everything
for (const u of parseUrlList(SUBSCRIPTION_URLS)) {
  try { addSource(u, {}); } catch (e) { console.error('[sub] bad seed URL:', u, e.message); }
}
rescheduleAllSources();
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[railgate] listening on :${PORT} — ${proxies.length} proxies, ${sources.length} sources loaded` +
    (GATEWAY_KEY ? ' — auth ON' : ' — auth OFF (set GATEWAY_KEY to protect)'));
  if (proxies.length) checkAll();
  // first subscription fetch shortly after boot (staggered, non-blocking)
  sources.forEach((s, i) => setTimeout(() => fetchSubscription(s).catch(() => {}),
    5000 + i * 5000).unref?.());
});

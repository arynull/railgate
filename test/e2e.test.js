'use strict';
// RailGate end-to-end: REAL loopback forward proxies + a REAL origin server.
// Every request must provably exit through the upstream (hit counters) —
// this is the coverage that would have caught the silent-direct bug.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const GATE = Number(process.env.E2E_PORT || 3471);
const UP = GATE + 1;       // plain forward proxy, no auth
const TARGET = GATE + 2;   // origin server
const UPAUTH = GATE + 4;   // forward proxy with basic auth
const BASE = `http://127.0.0.1:${GATE}`;
const TURL = `http://127.0.0.1:${TARGET}/echo`;

function gateReq(method, targetPath, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetPath, BASE);
    const headers = {};
    let payload = null;
    if (body !== undefined) {
      payload = JSON.stringify(body);
      headers['content-type'] = 'application/json';
    }
    const r = http.request(u, { method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString(),
      }));
    });
    r.on('error', reject);
    r.setTimeout(15000, () => r.destroy(new Error('request-timeout')));
    if (payload) r.write(payload);
    r.end();
  });
}

// absolute-URI forward-proxy request through the gate
function forwardGet(absUrl) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port: GATE, method: 'GET', path: absUrl }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString(),
      }));
    });
    r.on('error', reject);
    r.setTimeout(15000, () => r.destroy(new Error('request-timeout')));
    r.end();
  });
}

function connectTunnel(dest) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port: GATE, method: 'CONNECT', path: dest });
    r.on('connect', (res, socket) => resolve({ res, socket }));
    r.on('error', reject);
    r.setTimeout(15000, () => r.destroy(new Error('request-timeout')));
    r.end();
  });
}

function startTarget(port) {
  const srv = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(`TARGET-A path=${req.url}`);
  });
  return new Promise((resolve) => srv.listen(port, '127.0.0.1', () => resolve(srv)));
}

// minimal forward proxy: absolute-URI + CONNECT, optional basic auth
function startUpstream(port, creds) {
  let hits = 0;
  const srv = net.createServer((client) => {
    let buf = Buffer.alloc(0);
    let done = false;
    client.on('data', (chunk) => {
      if (done) return;
      buf = Buffer.concat([buf, chunk]);
      const hi = buf.indexOf('\r\n\r\n');
      if (hi < 0) return;
      done = true;
      const head = buf.slice(0, hi).toString('utf8');
      const rest = buf.slice(hi + 4);
      const lines = head.split('\r\n');
      const [method, dest] = lines[0].split(' ');
      const headers = {};
      for (const ln of lines.slice(1)) {
        const i = ln.indexOf(':');
        if (i > 0) headers[ln.slice(0, i).trim().toLowerCase()] = ln.slice(i + 1).trim();
      }
      if (creds) {
        const want = 'Basic ' + Buffer.from(`${creds.user}:${creds.pass}`).toString('base64');
        if (headers['proxy-authorization'] !== want) {
          client.write('HTTP/1.1 407 Proxy Auth Required\r\nContent-Length: 0\r\n\r\n');
          client.end();
          return;
        }
      }
      hits++;
      const fail = () => {
        try { client.write('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'); } catch { /* */ }
        client.end();
      };
      if (method === 'CONNECT') {
        const [h, p] = dest.split(':');
        const up = net.connect(Number(p), h, () => {
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (rest.length) up.write(rest);
          up.pipe(client);
          client.pipe(up);
        });
        up.on('error', fail);
        client.on('error', () => { try { up.destroy(); } catch { /* */ } });
        return;
      }
      let tu;
      try { tu = new URL(dest); } catch { fail(); return; }
      const up = net.connect(Number(tu.port || '80'), tu.hostname, () => {
        const originForm = `${method} ${(tu.pathname || '/') + (tu.search || '')} HTTP/1.1`;
        const fwd = lines.slice(1).filter((l) => !/^proxy-/i.test(l)).join('\r\n');
        up.write(`${originForm}\r\n${fwd}\r\n\r\n`);
        if (rest.length) up.write(rest);
        up.pipe(client);
      });
      up.on('error', fail);
      client.on('error', () => { try { up.destroy(); } catch { /* */ } });
    });
    client.on('error', () => {});
  });
  return new Promise((resolve) => srv.listen(port, '127.0.0.1', () => resolve({ srv, hits: () => hits })));
}

let child;
let targetSrv;
let up;
let upAuth;

before(async () => {
  targetSrv = await startTarget(TARGET);
  up = await startUpstream(UP);
  upAuth = await startUpstream(UPAUTH, { user: 'u', pass: 'p' });
  child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(GATE),
      DATA_FILE: path.join(os.tmpdir(), `railgate-e2e-${process.pid}.json`),
      CHECK_URL: `http://127.0.0.1:${TARGET}/health`,
      CHECK_TIMEOUT_MS: '4000',
      CHECK_INTERVAL_MS: '600000',
      BLOCK_PRIVATE: 'false',
      ALLOW_DIRECT: 'false', // any silent-direct fallback turns into a 502 here
    },
    stdio: 'ignore',
  });
  const deadline = Date.now() + 20000;
  for (;;) {
    try {
      const r = await gateReq('GET', '/health');
      if (r.status === 200) return;
    } catch { /* not up yet */ }
    if (Date.now() > deadline) throw new Error('gate did not boot in 20s');
    await new Promise((r) => setTimeout(r, 250));
  }
});

after(() => {
  if (child) child.kill();
  for (const s of [targetSrv, up && up.srv, upAuth && upAuth.srv]) {
    try { s && s.close(); } catch { /* */ }
  }
});

test('checker marks a REAL working http upstream alive', async () => {
  const r = await gateReq('POST', '/api/proxies', { proxies: [`http://127.0.0.1:${UP}`], replace: true });
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).added, 1);
  const l = await gateReq('GET', '/api/proxies');
  const j = JSON.parse(l.body);
  assert.equal(j.count, 1);
  assert.equal(j.proxies[0].alive, true);
  assert.equal(j.proxies[0].lastError, null);
  assert.ok(typeof j.proxies[0].latencyMs === 'number');
});

test('fetch exits through the upstream (hit counter proves it)', async () => {
  const before = up.hits();
  const r = await gateReq('GET', '/fetch?url=' + encodeURIComponent(TURL));
  assert.equal(r.status, 200);
  assert.match(r.body, /TARGET-A/);
  assert.match(r.headers['x-proxy-used'] || '', new RegExp(String(UP)));
  assert.ok(up.hits() > before, 'upstream actually served the request');
});

test('forward-proxy absolute-URI mode exits through the upstream', async () => {
  const before = up.hits();
  const r = await forwardGet(TURL);
  assert.equal(r.status, 200);
  assert.match(r.body, /TARGET-A/);
  assert.match(r.headers['x-proxy-used'] || '', new RegExp(String(UP)));
  assert.ok(up.hits() > before);
});

test('CONNECT tunnel exits through the upstream', async () => {
  const { res, socket } = await connectTunnel(`127.0.0.1:${TARGET}`);
  assert.equal(res.statusCode, 200);
  const body = await new Promise((resolve, reject) => {
    const parts = [];
    socket.on('data', (c) => parts.push(c));
    socket.on('end', () => resolve(Buffer.concat(parts).toString()));
    socket.on('error', reject);
    socket.setTimeout(10000, () => socket.destroy(new Error('tunnel-timeout')));
    socket.write(`GET /echo HTTP/1.1\r\nHost: 127.0.0.1:${TARGET}\r\nConnection: close\r\n\r\n`);
  });
  assert.match(body, /TARGET-A/);
});

test('auth upstream: credentials forwarded, alive + serving', async () => {
  const r = await gateReq('POST', '/api/proxies', { proxies: [`http://u:p@127.0.0.1:${UPAUTH}`], replace: true });
  assert.equal(JSON.parse(r.body).added, 1);
  const l = await gateReq('GET', '/api/proxies');
  const j = JSON.parse(l.body);
  assert.equal(j.count, 1);
  assert.equal(j.proxies[0].alive, true);
  const before = upAuth.hits();
  const f = await gateReq('GET', '/fetch?url=' + encodeURIComponent(TURL));
  assert.equal(f.status, 200);
  assert.match(f.body, /TARGET-A/);
  assert.ok(upAuth.hits() > before);
});

test('dead proxy recorded with reason; fetch 502s (no silent direct)', async () => {
  const r = await gateReq('POST', '/api/proxies', { proxies: ['http://127.0.0.1:9'], replace: true });
  assert.equal(JSON.parse(r.body).added, 1);
  const l = await gateReq('GET', '/api/proxies');
  const j = JSON.parse(l.body);
  assert.equal(j.proxies[0].alive, false);
  assert.ok(j.proxies[0].lastError);
  const f = await gateReq('GET', '/fetch?url=' + encodeURIComponent(TURL));
  assert.equal(f.status, 502);
});

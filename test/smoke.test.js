'use strict';
// RailGate smoke tests — boot the real server, hit real HTTP endpoints.
// No external network needed: dead ends are 127.0.0.1 (refused fast),
// the SSRF guard is exercised against localhost targets, and the 502 path
// uses TEST-NET-1 (192.0.2.1) so the request never leaves the dead proxy.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const PORT = process.env.TEST_PORT ? Number(process.env.TEST_PORT) : 3457;
const BASE = `http://127.0.0.1:${PORT}`;

function req(method, targetPath, body) {
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

let child;
before(async () => {
  child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      DATA_FILE: path.join(os.tmpdir(), `railgate-test-${process.pid}.json`),
      CHECK_INTERVAL_MS: '600000',
      CHECK_TIMEOUT_MS: '3000',
    },
    stdio: 'ignore',
  });
  const deadline = Date.now() + 20000;
  for (;;) {
    try {
      const r = await req('GET', '/health');
      if (r.status === 200) return;
    } catch { /* not up yet */ }
    if (Date.now() > deadline) throw new Error('server did not boot in 20s');
    await new Promise((r) => setTimeout(r, 250));
  }
});

after(() => { if (child) child.kill(); });

test('GET /health reports the service', async () => {
  const r = await req('GET', '/health');
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).service, 'railgate');
});

test('GET / serves the pro web panel (i18n + tabs + dialog)', async () => {
  const r = await req('GET', '/');
  assert.equal(r.status, 200);
  assert.match(r.body, /RailGate/);
  assert.match(r.body, /data-i18n/);
  assert.match(r.body, /tailwindcss/);
});

test('invalid proxy lines are rejected, nothing stored', async () => {
  const r = await req('POST', '/api/proxies', { proxies: ['not a proxy!!!', 'ftp://x:21'] });
  assert.equal(r.status, 200);
  const j = JSON.parse(r.body);
  assert.equal(j.added, 0);
  assert.equal(j.invalid.length, 2);
});

test('empty proxy add is a 400', async () => {
  const r = await req('POST', '/api/proxies', {});
  assert.equal(r.status, 400);
});

test('SSRF guard blocks localhost targets', async () => {
  const r = await req('GET', '/fetch?url=' + encodeURIComponent('http://127.0.0.1:9/x'));
  assert.equal(r.status, 403);
});

test('dead upstream is marked down; fetch fails 502 without crashing', async () => {
  let r = await req('POST', '/api/proxies', { proxies: ['http://127.0.0.1:9'], replace: true });
  assert.equal(JSON.parse(r.body).added, 1);

  r = await req('GET', '/api/proxies');
  const list = JSON.parse(r.body);
  assert.equal(list.count, 1);
  assert.equal(list.proxies[0].alive, false);

  r = await req('GET', '/fetch?url=' + encodeURIComponent('http://192.0.2.1/'));
  assert.equal(r.status, 502);

  r = await req('GET', '/health');
  assert.equal(r.status, 200);

  r = await req('DELETE', '/api/proxies?clear=1');
  assert.equal(JSON.parse(r.body).total, 0);
});

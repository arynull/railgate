'use strict';
// RailGate subscription tests — auto-fetch proxy-list URLs on a timer.
// Self-contained: serves a fake proxy list on localhost, points the real
// server at it, and exercises add / refetch / patch / delete.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const PORT = process.env.SUB_TEST_PORT ? Number(process.env.SUB_TEST_PORT) : 3458;
const LIST_PORT = PORT + 40;
const BASE = `http://127.0.0.1:${PORT}`;
const LIST_URL = `http://127.0.0.1:${LIST_PORT}/list.txt`;
const LIST_BODY = '# test list\nhttp://127.0.0.1:9\nsocks5://127.0.0.1:9\nnot-a-proxy!!!\n';

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
        body: Buffer.concat(chunks).toString(),
      }));
    });
    r.on('error', reject);
    r.setTimeout(25000, () => r.destroy(new Error('request-timeout')));
    if (payload) r.write(payload);
    r.end();
  });
}

let child;
let listSrv;
let srcId;

before(async () => {
  listSrv = http.createServer((rq, rs) => {
    if (rq.url === '/list.txt') { rs.writeHead(200, { 'content-type': 'text/plain' }); rs.end(LIST_BODY); }
    else { rs.writeHead(404); rs.end('no'); }
  });
  await new Promise((r) => listSrv.listen(LIST_PORT, '127.0.0.1', r));

  child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      DATA_FILE: path.join(os.tmpdir(), `railgate-subtest-${process.pid}.json`),
      BLOCK_PRIVATE: 'false',
      SUBSCRIPTION_ALLOW_PRIVATE: 'true',
      CHECK_TIMEOUT_MS: '2000',
      CHECK_INTERVAL_MS: '600000',
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

after(() => {
  if (child) child.kill();
  if (listSrv) listSrv.close();
});

test('add subscription source — first fetch merges proxies', async () => {
  const r = await req('POST', '/api/sources', { url: LIST_URL, intervalMin: 10 });
  assert.equal(r.status, 200);
  const j = JSON.parse(r.body);
  assert.equal(j.ok, true);
  assert.equal(j.totalAdded, 2);
  srcId = j.sources[0].id;
  assert.match(srcId, /^sub/);
});

test('source listed with ok status', async () => {
  const r = await req('GET', '/api/sources');
  const j = JSON.parse(r.body);
  assert.equal(j.count, 1);
  assert.equal(j.sources[0].lastStatus, 'ok');
  assert.equal(j.sources[0].lastTotal, 2);
});

test('pool holds the 2 fetched proxies', async () => {
  const r = await req('GET', '/api/proxies');
  assert.equal(JSON.parse(r.body).count, 2);
});

test('manual refetch dedupes to zero new', async () => {
  const r = await req('POST', `/api/sources/${srcId}/fetch`);
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).added, 0);
});

test('non-http subscription URL is rejected', async () => {
  const r = await req('POST', '/api/sources', { url: 'ftp://x/y.txt' });
  assert.equal(r.status, 400);
});

test('patch source interval', async () => {
  const r = await req('PATCH', `/api/sources/${srcId}`, { intervalMin: 60 });
  assert.equal(r.status, 200);
  assert.equal(JSON.parse(r.body).source.intervalMs, 3600000);
});

test('delete source with its proxies', async () => {
  const r = await req('DELETE', `/api/sources/${srcId}?deleteProxies=1`);
  const j = JSON.parse(r.body);
  assert.equal(r.status, 200);
  assert.equal(j.proxiesRemoved, 2);
  assert.equal(j.total, 0);
});

test('panel exposes the Sources tab (EN + FA)', async () => {
  const r = await req('GET', '/');
  assert.equal(r.status, 200);
  assert.match(r.body, /tSubs/);
  assert.match(r.body, /su\.title/);
});

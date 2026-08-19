'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const creds = require('../lib/credentials.js');
const { createProxy } = require('../lib/server.js');

const ROOT = path.join(__dirname, '..');

function buildConfig(overrides = {}) {
  const config = creds.defaultConfig();
  config.listenPort = 0;
  config.sessionSecret = 'test-secret-0123456789abcdef';
  config.users = [creds.makeUser('user1', 'pass1')];
  config.maxAttempts = 5;
  config.lockMs = 60_000;
  return { ...config, ...overrides };
}

function mockBackend() {
  return new Promise((resolve) => {
    const seen = [];
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        seen.push({
          method: req.method, url: req.url, headers: req.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, url: req.url }));
      });
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, seen }));
  });
}

function request(port, options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, ...options }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function login(port) {
  const body = new URLSearchParams({ username: 'user1', password: 'pass1' }).toString();
  const res = await request(port, {
    method: 'POST', path: '/login',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
  }, body);
  return res.headers['set-cookie'][0].split(';')[0].slice(4);
}

test('登录后请求被代理且 Host/Origin 改写为回环权威', async (t) => {
  const backend = await mockBackend();
  t.after(() => new Promise((r) => backend.server.close(r)));
  const proxy = createProxy({
    config: buildConfig({ target: { host: '127.0.0.1', port: backend.port } }),
    dir: ROOT, mode: 'http',
  });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;
  const sid = await login(port);

  const body = '{"hello":"dsh"}';
  const res = await request(port, {
    method: 'POST', path: '/api/describe',
    headers: {
      Cookie: `sid=${sid}`,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      Origin: 'http://192.168.110.168:3081',
    },
  }, body);

  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), { ok: true, url: '/api/describe' });
  assert.equal(backend.seen.length, 1);
  const forwarded = backend.seen[0];
  assert.equal(forwarded.headers.host, `127.0.0.1:${backend.port}`);
  assert.equal(forwarded.headers.origin, `http://127.0.0.1:${backend.port}`);
  assert.equal(forwarded.body, body);
  assert.equal(forwarded.headers.cookie, `sid=${sid}`); // 透传原 Cookie
});

test('未登录的 /api 请求不被代理（302 登录页）', async (t) => {
  const backend = await mockBackend();
  t.after(() => new Promise((r) => backend.server.close(r)));
  const proxy = createProxy({
    config: buildConfig({ target: { host: '127.0.0.1', port: backend.port } }),
    dir: ROOT, mode: 'http',
  });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;

  const res = await request(port, { method: 'POST', path: '/api/describe' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.location, '/login');
  assert.equal(backend.seen.length, 0);
});

test('后端不可达返回 502', async (t) => {
  const proxy = createProxy({
    config: buildConfig({ target: { host: '127.0.0.1', port: 1 } }),
    dir: ROOT, mode: 'http',
  });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;
  const sid = await login(port);

  const res = await request(port, { path: '/', headers: { Cookie: `sid=${sid}` } });
  assert.equal(res.status, 502);
  assert.match(res.body, /502/);
});

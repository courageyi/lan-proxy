'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
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

// 轮询等待条件成立，超时则 reject（避免“挂死等超时”掩盖失败原因）
function waitFor(cond, timeoutMs, what) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const check = () => {
      if (cond()) return resolve();
      if (Date.now() > deadline) return reject(new Error(`等待超时: ${what}`));
      setTimeout(check, 50);
    };
    check();
  });
}

// 不配合的后端：收到请求后从不响应、从不自行清理连接。
// 客户端断开后，若代理不主动销毁后端请求，连接将半开泄漏，
// 表现为 conns 不空、backend.server.close() 挂起。
function noRespondBackend() {
  return new Promise((resolve) => {
    const conns = new Set();
    let resolveSeen;
    const seen = new Promise((r) => { resolveSeen = r; });
    const server = http.createServer((req, res) => {
      resolveSeen();
      req.on('error', () => {});
      res.on('error', () => {});
    });
    server.on('connection', (s) => { conns.add(s); s.on('close', () => conns.delete(s)); });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, conns, seen }));
  });
}

// 慢速流式后端：立即写一块、400ms 后再写一块、800ms 后结束。
// 客户端在首个块到达后断开时响应必然尚未完成；后端不监听 end/close，
// 只靠代理侧拆除来关闭连接。
function slowStreamBackend() {
  return new Promise((resolve) => {
    const conns = new Set();
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.write('first-chunk');
      setTimeout(() => { if (!res.destroyed) res.write('second-chunk'); }, 400);
      setTimeout(() => { if (!res.destroyed) res.end(); }, 800);
      req.on('error', () => {});
      res.on('error', () => {});
    });
    server.on('connection', (s) => { conns.add(s); s.on('close', () => conns.delete(s)); });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, conns }));
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
      Origin: 'http://192.168.1.100:3081',
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

test('客户端在请求中途断开：后端请求被销毁，双方 close 均能完成', { timeout: 15_000 }, async (t) => {
  // 回归：forwardRequest 若不监听 req 的 aborted/close，客户端断开后
  // proxyReq 永远不销毁 → 后端连接半开泄漏，backend.close() 挂起。
  const backend = await noRespondBackend();
  t.after(async () => {
    await Promise.race([
      Promise.all([new Promise((r) => backend.server.close(r)), proxy.close()]),
      new Promise((r) => setTimeout(r, 1500)),
    ]);
  });
  const proxy = createProxy({
    config: buildConfig({ target: { host: '127.0.0.1', port: backend.port } }),
    dir: ROOT, mode: 'http',
  });
  const listener = await proxy.listen();
  const port = listener.address().port;
  const sid = await login(port);

  const req = http.request({
    host: '127.0.0.1', port, method: 'POST', path: '/api/describe',
    headers: { 'Content-Type': 'application/json', 'Content-Length': 8, Cookie: `sid=${sid}` },
  });
  req.on('error', () => {});
  req.write('{"x":1}');
  req.end();

  await backend.seen; // 后端已收到请求（尚未响应）
  req.destroy(); // 客户端中途断开（未等后端响应）

  await waitFor(() => backend.conns.size === 0, 3000, '后端请求连接被代理销毁');
  await Promise.all([
    new Promise((r) => backend.server.close(r)),
    proxy.close(),
  ]);
});

test('客户端在响应中途断开：后端流被拆除，代理与后端 close 均能完成', { timeout: 15_000 }, async (t) => {
  // 回归：forwardRequest 若不监听 res 的 close，客户端在响应中途断开后
  // 后端流永不拆除 → proxy.close()/backend.close() 挂起。
  const backend = await slowStreamBackend();
  t.after(async () => {
    await Promise.race([
      Promise.all([new Promise((r) => backend.server.close(r)), proxy.close()]),
      new Promise((r) => setTimeout(r, 1500)),
    ]);
  });
  const proxy = createProxy({
    config: buildConfig({ target: { host: '127.0.0.1', port: backend.port } }),
    dir: ROOT, mode: 'http',
  });
  const listener = await proxy.listen();
  const port = listener.address().port;
  const sid = await login(port);

  // 原始 socket：收到首个响应块后立即销毁（响应尚未结束）
  const socket = net.connect(port, '127.0.0.1', () => {
    socket.write(`GET /api/stream HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nCookie: sid=${sid}\r\n\r\n`);
  });
  socket.on('data', () => socket.destroy());
  socket.on('error', () => {});
  await new Promise((resolve) => socket.on('close', resolve));

  await waitFor(() => backend.conns.size === 0, 3000, '后端响应连接被代理拆除');
  await Promise.all([
    new Promise((r) => backend.server.close(r)),
    proxy.close(),
  ]);
});

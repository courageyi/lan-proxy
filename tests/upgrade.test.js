'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const creds = require('../lib/credentials.js');
const { createProxy } = require('../lib/server.js');

const ROOT = path.join(__dirname, '..');
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function buildConfig(overrides = {}) {
  const config = creds.defaultConfig();
  config.listenPort = 0;
  config.sessionSecret = 'test-secret-0123456789abcdef';
  config.users = [creds.makeUser('user1', 'pass1')];
  config.maxAttempts = 5;
  config.lockMs = 60_000;
  return { ...config, ...overrides };
}

function wsEchoBackend() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => { res.writeHead(404); res.end(); });
    server.on('upgrade', (req, socket) => {
      const accept = crypto.createHash('sha1')
        .update(req.headers['sec-websocket-key'] + WS_GUID).digest('base64');
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
      socket.on('data', (d) => socket.write(d)); // 原样回显帧
      socket.on('end', () => socket.destroy()); // 对端关闭时同步销毁，否则 server.close() 挂起（http server 默认 allowHalfOpen）
      socket.on('error', () => {});
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

function maskedTextFrame(text) {
  const payload = Buffer.from(text, 'utf8');
  const mask = Buffer.from([1, 2, 3, 4]);
  const frame = Buffer.alloc(6 + payload.length);
  frame[0] = 0x81; // FIN + text
  frame[1] = 0x80 | payload.length; // MASK + len(<126)
  mask.copy(frame, 2);
  for (let i = 0; i < payload.length; i++) frame[6 + i] = payload[i] ^ mask[i % 4];
  return frame;
}

function httpRequest(port, options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, ...options }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function upgrade(port, cookie) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => {
      const key = crypto.randomBytes(16).toString('base64');
      let req =
        `GET /api/events.mux HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n` +
        'Connection: Upgrade\r\nUpgrade: websocket\r\n' +
        `Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${key}\r\n`;
      if (cookie) req += `Cookie: ${cookie}\r\n`;
      req += '\r\n';
      socket.write(req);
    });
    let data = '';
    socket.on('data', (c) => {
      data += c.toString('utf8');
      const idx = data.indexOf('\r\n\r\n');
      if (idx !== -1) {
        const head = data.slice(0, idx);
        const rest = data.slice(idx + 4);
        resolve({ socket, head, rest: Buffer.from(rest, 'utf8') });
      }
    });
    socket.on('error', reject);
  });
}

async function login(port) {
  const body = new URLSearchParams({ username: 'user1', password: 'pass1' }).toString();
  const res = await httpRequest(port, {
    method: 'POST', path: '/login',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
  }, body);
  return res.headers['set-cookie'][0].split(';')[0];
}

test('带 Cookie 的 WebSocket 升级通过并回显数据', async (t) => {
  const backend = await wsEchoBackend();
  t.after(() => new Promise((r) => backend.server.close(r)));
  const proxy = createProxy({
    config: buildConfig({ target: { host: '127.0.0.1', port: backend.port } }),
    dir: ROOT, mode: 'http',
  });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;
  const cookie = await login(port);

  const { socket, head } = await upgrade(port, cookie);
  assert.match(head, /^HTTP\/1\.1 101 Switching Protocols/);
  assert.match(head, /Sec-WebSocket-Accept: /);

  const frame = maskedTextFrame('你好 dsh');
  socket.write(frame);
  const echoed = await new Promise((resolve, reject) => {
    const chunks = [];
    socket.on('data', (c) => chunks.push(c));
    setTimeout(() => resolve(Buffer.concat(chunks)), 300);
    socket.on('error', reject);
  });
  assert.deepEqual(echoed, frame);
  socket.destroy();
});

test('无 Cookie 的 WebSocket 升级被拒绝（403）', async (t) => {
  const backend = await wsEchoBackend();
  t.after(() => new Promise((r) => backend.server.close(r)));
  const proxy = createProxy({
    config: buildConfig({ target: { host: '127.0.0.1', port: backend.port } }),
    dir: ROOT, mode: 'http',
  });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;

  const { head } = await upgrade(port, null);
  assert.match(head, /^HTTP\/1\.1 403 Forbidden/);
});

test('后端以非 101 响应升级请求：响应透传且双方 close 均能完成', { timeout: 10_000 }, async (t) => {
  // 不配合的后端：200 + Content-Length: 0，不发送 Connection: close，也不销毁 socket。
  // 只吞 RST 触发的 'error'（否则 uncaughtException），其余一律不清理。
  const backend = http.createServer((req, res) => { res.writeHead(404); res.end(); });
  backend.on('upgrade', (req, socket) => {
    socket.write('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n');
    socket.on('error', () => {});
  });
  await new Promise((r) => backend.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => backend.close(r)));
  const proxy = createProxy({
    config: buildConfig({ target: { host: '127.0.0.1', port: backend.address().port } }),
    dir: ROOT, mode: 'http',
  });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;
  const cookie = await login(port);

  const { head } = await upgrade(port, cookie);
  assert.match(head, /^HTTP\/1\.1 200 OK/);

  // 若代理未把后端连接彻底关掉（FIN 后半开），backend.close() 会挂起 → 测试超时即失败
  await Promise.all([
    new Promise((r) => backend.close(r)),
    proxy.close(),
  ]);
});

test('升级握手完成前客户端断开不崩溃代理', { timeout: 10_000 }, async (t) => {
  // 后端延迟 400ms 才回 101，制造“请求已受理、101 未到”的握手窗口
  const backend = http.createServer((req, res) => { res.writeHead(404); res.end(); });
  backend.on('upgrade', (req, socket) => {
    const accept = crypto.createHash('sha1')
      .update(req.headers['sec-websocket-key'] + WS_GUID).digest('base64');
    setTimeout(() => {
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
    }, 400);
    socket.on('error', () => {});
    socket.on('end', () => socket.destroy());
  });
  await new Promise((r) => backend.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => backend.close(r)));
  const proxy = createProxy({
    config: buildConfig({ target: { host: '127.0.0.1', port: backend.address().port } }),
    dir: ROOT, mode: 'http',
  });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;
  const cookie = await login(port);

  // 发送有效升级请求，稍等代理完成转发后立即 RST 断开（后端 101 尚未到达）
  const socket = net.connect(port, '127.0.0.1', () => {
    const key = crypto.randomBytes(16).toString('base64');
    socket.write(
      'GET /api/events.mux HTTP/1.1\r\n' +
      `Host: 127.0.0.1:${port}\r\n` +
      'Connection: Upgrade\r\nUpgrade: websocket\r\n' +
      `Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${key}\r\n` +
      `Cookie: ${cookie}\r\n\r\n`);
    setTimeout(() => socket.resetAndDestroy(), 100);
  });
  socket.on('error', () => {}); // 客户端自己 RST 自己的 socket，吞掉可能的报错

  // 等后端 101 的延迟窗口过去，确认代理进程没有因 ECONNRESET 崩溃
  await new Promise((r) => setTimeout(r, 600));

  // 代理必须还活着：普通 HTTP GET /login 应返回 200
  const res = await httpRequest(port, { method: 'GET', path: '/login' });
  assert.equal(res.status, 200);

  await Promise.all([
    new Promise((r) => backend.close(r)),
    proxy.close(),
  ]);
});

test('握手完成后客户端 RST 断开：代理关闭不配合的后端连接，双方 close 均能完成', { timeout: 10_000 }, async (t) => {
  // 不配合的后端：回 101 后不监听 end/close，客户端断开时它不会自己清理
  // （与 echo 后端的 end→destroy 不同——那个处理会掩盖代理侧的泄漏）。
  // 若代理握手后不主动 RST 后端连接（'upgrade' 后 proxyReq.destroy() 已是 no-op），
  // backend.close() 会永远挂起 → 测试超时即失败。
  const backend = http.createServer((req, res) => { res.writeHead(404); res.end(); });
  backend.on('upgrade', (req, socket) => {
    const accept = crypto.createHash('sha1')
      .update(req.headers['sec-websocket-key'] + WS_GUID).digest('base64');
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.on('error', () => {}); // 只吞 RST 的 'error'，绝不自行销毁
  });
  await new Promise((r) => backend.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => backend.close(r)));
  const proxy = createProxy({
    config: buildConfig({ target: { host: '127.0.0.1', port: backend.address().port } }),
    dir: ROOT, mode: 'http',
  });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;
  const cookie = await login(port);

  // 隧道已建立（101 收到）；稍等代理完成 teardown 挂接后客户端 RST 断开
  const { socket, head } = await upgrade(port, cookie);
  assert.match(head, /^HTTP\/1\.1 101 Switching Protocols/);
  await new Promise((r) => setTimeout(r, 50));
  socket.resetAndDestroy();

  // 代理必须把后端连接 RST 掉，否则 backend.close() 挂起 → 测试超时即失败
  await Promise.all([
    new Promise((r) => backend.close(r)),
    proxy.close(),
  ]);
});

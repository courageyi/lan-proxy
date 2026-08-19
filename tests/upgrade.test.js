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

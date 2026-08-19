'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const https = require('node:https');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const creds = require('../lib/credentials.js');
const { createProxy } = require('../lib/server.js');

const ROOT = path.join(__dirname, '..');

function buildConfig() {
  const config = creds.defaultConfig();
  config.listenPort = 0;
  config.sessionSecret = 'test-secret-0123456789abcdef';
  config.users = [creds.makeUser('user1', 'pass1')];
  config.maxAttempts = 5;
  config.lockMs = 60_000;
  return config;
}

function rawHttpGet(port, targetPath) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => {
      socket.write(
        `GET ${targetPath} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`);
    });
    let data = '';
    socket.on('data', (c) => (data += c.toString('utf8')));
    socket.on('end', () => resolve(data));
    socket.on('error', reject);
  });
}

test('https 模式下明文 HTTP 请求被 301 到 HTTPS 同路径', async (t) => {
  const proxy = createProxy({
    config: buildConfig(), dir: ROOT, mode: 'https',
    key: 'dummy-key', cert: 'dummy-cert', // 明文分支不会用到
  });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;

  const raw = await rawHttpGet(port, '/login');
  assert.match(raw, /^HTTP\/1\.1 301 Moved Permanently/);
  assert.match(raw, new RegExp(`Location: https://127\\.0\\.0\\.1:${port}/login`));
});

function findOpenssl() {
  // Git for Windows 自带 openssl；PATH 上没有时回退到固定路径
  const gitPath = 'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe';
  if (fs.existsSync(gitPath)) return gitPath;
  const probe = spawnSync('openssl', ['version'], { stdio: ['ignore', 'ignore', 'ignore'] });
  return probe.status === 0 ? 'openssl' : null;
}

test('https 模式：真实 TLS 握手后 /login 返回 200，明文请求 301', { timeout: 20_000 }, async (t) => {
  // 覆盖 TLS 嗅探分支（ClientHello → TLSSocket 包装 → secureConnection）。
  // 需要真实证书：用系统 openssl 现场生成一次性自签名证书。
  const openssl = findOpenssl();
  if (!openssl) { t.skip('openssl 不可用，跳过 TLS 嗅探测试'); return; }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-proxy-tls-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const keyFile = path.join(dir, 'key.pem');
  const certFile = path.join(dir, 'cert.pem');
  const gen = spawnSync(openssl, [
    'req', '-x509', '-newkey', 'rsa:2048',
    '-keyout', keyFile, '-out', certFile,
    '-days', '1', '-nodes', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
  ], { stdio: ['ignore', 'ignore', 'ignore'] });
  if (gen.status !== 0 || !fs.existsSync(keyFile) || !fs.existsSync(certFile)) {
    t.skip('自签名证书生成失败，跳过 TLS 嗅探测试');
    return;
  }

  const proxy = createProxy({
    config: buildConfig(), dir: ROOT, mode: 'https',
    key: fs.readFileSync(keyFile, 'utf8'),
    cert: fs.readFileSync(certFile, 'utf8'),
  });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;

  // 真实 TLS：HTTPS GET /login → 200
  const tls = await new Promise((resolve, reject) => {
    const req = https.request({
      host: '127.0.0.1', port, path: '/login', rejectUnauthorized: false,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode, body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    req.end();
  });
  assert.equal(tls.status, 200);
  assert.match(tls.body, /<form method="post" action="\/login"/);

  // 明文 HTTP → 301
  const raw = await rawHttpGet(port, '/login');
  assert.match(raw, /^HTTP\/1\.1 301 Moved Permanently/);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const path = require('node:path');
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

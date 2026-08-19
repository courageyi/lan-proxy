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
  config.users = [creds.makeUser('user1', 'pass1'), creds.makeUser('user2', 'pass2')];
  config.maxAttempts = 3;
  config.lockMs = 60_000;
  return { ...config, ...overrides };
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

function postLogin(port, username, password) {
  const body = new URLSearchParams({ username, password }).toString();
  return request(port, {
    method: 'POST', path: '/login',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
  }, body);
}

test('未登录访问 / 重定向到 /login；登录页可访问', async (t) => {
  const proxy = createProxy({ config: buildConfig(), dir: ROOT, mode: 'http' });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;

  const home = await request(port, { path: '/' });
  assert.equal(home.status, 302);
  assert.equal(home.headers.location, '/login');

  const page = await request(port, { path: '/login' });
  assert.equal(page.status, 200);
  assert.match(page.body, /<form method="post" action="\/login"/);
  assert.match(page.body, /DSH 登录/);
});

test('正确密码登录成功并签发会话 Cookie', async (t) => {
  const proxy = createProxy({ config: buildConfig(), dir: ROOT, mode: 'http' });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;

  const res = await postLogin(port, 'user1', 'pass1');
  assert.equal(res.status, 302);
  assert.equal(res.headers.location, '/');
  const cookie = res.headers['set-cookie'][0];
  assert.match(cookie, /^sid=[^;]+; Path=\/; HttpOnly; SameSite=Strict; Secure; Max-Age=\d+$/);
});

test('错误密码返回 401 且登录页带错误提示', async (t) => {
  const proxy = createProxy({ config: buildConfig(), dir: ROOT, mode: 'http' });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;

  const res = await postLogin(port, 'user1', 'wrong');
  assert.equal(res.status, 401);
  assert.match(res.body, /用户名或密码错误/);
});

test('连续失败达到上限后锁定（即使密码正确也 403）', async (t) => {
  const proxy = createProxy({ config: buildConfig(), dir: ROOT, mode: 'http' });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;

  for (let i = 0; i < 3; i++) {
    const res = await postLogin(port, 'user1', 'wrong');
    assert.equal(res.status, 401);
  }
  const locked = await postLogin(port, 'user1', 'pass1');
  assert.equal(locked.status, 403);
  assert.match(locked.body, /尝试次数过多/);
});

test('登出清除会话，之后访问需重新登录', async (t) => {
  const proxy = createProxy({ config: buildConfig(), dir: ROOT, mode: 'http' });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;

  const login = await postLogin(port, 'user2', 'pass2');
  const sid = login.headers['set-cookie'][0].split(';')[0].slice(4);

  const logout = await request(port, {
    method: 'POST', path: '/logout',
    headers: { Cookie: `sid=${sid}` },
  });
  assert.equal(logout.status, 302);
  assert.match(logout.headers['set-cookie'][0], /Max-Age=0/);

  const after = await request(port, { path: '/', headers: { Cookie: `sid=${sid}` } });
  assert.equal(after.status, 302);
  assert.equal(after.headers.location, '/login');
});

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const creds = require('../lib/credentials.js');
const { createAuth } = require('../lib/auth.js');
const { signSession } = require('../lib/session.js');
const { createProxy } = require('../lib/server.js');

const ROOT = path.join(__dirname, '..');

function fakeRes() {
  return { setHeader() {}, writeHead() {}, end() {} };
}

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

test('伪造 sid 的未认证登出不增长 revoked 表，且不影响正常登录使用', { timeout: 15_000 }, async (t) => {
  // 回归：/logout 刻意不做认证门禁，若对任意 sid 一律吊销，
  // 攻击者可灌入任意字符串使 revoked 表无界增长（内存/CPU DoS）。
  const proxy = createProxy({ config: buildConfig(), dir: ROOT, mode: 'http' });
  const listener = await proxy.listen();
  t.after(() => proxy.close());
  const port = listener.address().port;

  for (let i = 0; i < 200; i++) {
    const res = await request(port, {
      method: 'POST', path: '/logout',
      headers: { Cookie: `sid=fake-token-${i}-${'x'.repeat(48)}` },
    });
    assert.equal(res.status, 302);
  }
  assert.equal(proxy.auth.revoked.size, 0); // 伪造令牌全部被拒，未进入 revoked 表

  // 正常登录 + 登出仍工作，且登出确实吊销了真实令牌
  const login = await postLogin(port, 'user1', 'pass1');
  const sid = login.headers['set-cookie'][0].split(';')[0].slice(4);
  const logout = await request(port, { method: 'POST', path: '/logout', headers: { Cookie: `sid=${sid}` } });
  assert.equal(logout.status, 302);
  assert.equal(proxy.auth.revoked.size, 1);
  assert.ok(proxy.auth.revoked.has(sid));

  const after = await request(port, { path: '/', headers: { Cookie: `sid=${sid}` } });
  assert.equal(after.status, 302);
  assert.equal(after.headers.location, '/login');
});

test('revoked 表超过上限时按 FIFO 淘汰最旧条目', () => {
  // 单元级：绕过网络层直接驱动 createAuth；cap 调小以便快速验证淘汰逻辑。
  const config = buildConfig({ revokedCap: 10 });
  const auth = createAuth(config, { dir: ROOT });
  const tokens = [];
  for (let i = 0; i < 25; i++) {
    // 显式传 now 保证 25 个令牌互不相同（Date.now() 毫秒分辨率下紧循环会撞车）
    const token = signSession('user1', config.sessionSecret, config.sessionTtlMs, Date.now() + i * 1000);
    tokens.push(token);
    auth.handleLogout({ headers: { cookie: `sid=${token}` } }, fakeRes());
  }
  assert.equal(auth.revoked.size, 10); // 超出部分被 FIFO 淘汰
  // 最早签发的 15 个已被淘汰，仅保留最新的 10 个
  for (const token of tokens.slice(0, 15)) assert.ok(!auth.revoked.has(token));
  for (const token of tokens.slice(15)) assert.ok(auth.revoked.has(token));
});

test('attempts 表超过上限时淘汰最旧记录（含未锁定记录）', () => {
  const config = buildConfig({ attemptsCap: 5, maxAttempts: 100 });
  const auth = createAuth(config, { dir: ROOT });
  for (let i = 0; i < 12; i++) auth.recordFailure(`192.0.2.${i}`);
  assert.equal(auth.attempts.size, 5); // 12 个 IP 只保留最新的 5 个
});

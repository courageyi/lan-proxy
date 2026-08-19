# LAN 认证代理（lan-proxy）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 DSH Web GUI（`127.0.0.1:3080`）前部署一个带登录认证的局域网 HTTPS 反向代理（监听 `0.0.0.0:3081`），支持 5 个账号登录、会话 Cookie、登录限速、普通 HTTP 与 WebSocket 转发，且不改动、不重启 dsh。

**Architecture:** 纯 Node 标准库实现（零第三方依赖）。代码拆分为按职责聚焦的小模块：`lib/credentials.js`（配置/凭据/scrypt）、`lib/session.js`（HMAC 会话令牌）、`lib/auth.js`（登录/登出/限速/认证门）、`lib/proxy.js`（HTTP+WebSocket 转发、Host/Origin 改写）、`lib/server.js`（组合 + HTTPS/TLS 嗅探 + 明文 301）、`server.js`（CLI：setup/adduser/run）。测试用 Node 内置 `node:test` 运行器，零依赖。代理通过 `http.Server` 手动 `emit('connection'/'secureConnection')` 的方式同时服务明文跳转与 TLS 流量。

**Tech Stack:** Node.js ≥ 20（本机 v24.18.0）、`node:test`、`node:crypto`（scrypt/HMAC）、`node:http/https/net/tls`、PowerShell（仅用于生成自签名证书）。

## Global Constraints

- 零第三方 npm 依赖；只用 Node 内置模块（`node:http`、`node:https`、`node:net`、`node:tls`、`node:crypto`、`node:fs`、`node:path`、`node:child_process`）。
- 不改动、不重启 dsh；dsh 保持监听 `127.0.0.1:3080`。
- 默认监听 `0.0.0.0:3081`，后端目标 `127.0.0.1:3080`，会话有效期 12h，限速 5 次/15 分钟（`config.json` 可覆盖）。
- 初始账号 `user1`–`user5`，密码随机生成（base64url 12 字节），以 scrypt 加盐哈希（64 字节，16 字节盐）存储；明文密码只写入 `credentials.txt`。
- 会话 Cookie：`sid=<payload>.<sig>`，HMAC-SHA256 签名，`HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=<秒>`。
- 转发时改写 `Host` 为 `127.0.0.1:<后端端口>`；若原请求带 `Origin` 则改写为 `http://127.0.0.1:<后端端口>`。
- 明文 HTTP 访问 3081 → 301 到 `https://<host><path>`。
- 界面/日志文案使用中文。
- 秘钥文件（`config.json`、`credentials.txt`、`cert.pem`、`key.pem`）必须加入 `.gitignore`。
- 每个任务结束提交一次 git（仓库根：`D:\DSH\lan-proxy`，已 `git init`）。

---

### Task 1: 项目骨架 + 凭据/配置核心（lib/credentials.js）

**Files:**
- Create: `package.json`
- Create: `.gitignore`
- Create: `login.html`
- Create: `lib/credentials.js`
- Test: `tests/credentials.test.js`

**Interfaces:**
- Produces（后续任务依赖）:
  - `creds.scryptHash(password: string, saltHex: string): string` — 返回 64 字节 scrypt 哈希的 hex
  - `creds.verifyPassword(password: string, user: {salt, hash}): boolean` — 恒定时间比较
  - `creds.makeUser(name: string, password: string): {name, salt, hash}`
  - `creds.randomToken(bytes = 24): string` — base64url 随机串
  - `creds.defaultConfig(): object` — 默认配置（listenPort 3081、target 127.0.0.1:3080、sessionTtlMs 12h、maxAttempts 5、lockMs 15min）
  - `creds.loadConfig(dir): object | null`
  - `creds.saveConfig(dir, config): string` — 返回 config.json 路径
  - `creds.runSetup(dir, userCount = 5): {configPath, credPath, config, rows}` — 生成 config.json + credentials.txt

- [ ] **Step 1: 创建骨架文件**

`package.json`：
```json
{
  "name": "lan-proxy",
  "version": "1.0.0",
  "private": true,
  "description": "DSH 局域网认证反向代理（零依赖）",
  "scripts": {
    "test": "node --test tests/"
  }
}
```

`.gitignore`：
```gitignore
node_modules/
config.json
credentials.txt
cert.pem
key.pem
```

`login.html`（完整内容，登录页；`__ERROR__` 标记由服务端替换为错误提示，无错误时整段被替换为空）：
```html
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DSH 登录</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
         font-family: system-ui, "Microsoft YaHei", sans-serif; background: #0f172a; color: #e2e8f0; }
  .card { width: 320px; padding: 32px 28px; border-radius: 12px; background: #1e293b; box-shadow: 0 8px 30px rgba(0,0,0,.35); }
  h1 { margin: 0 0 4px; font-size: 20px; }
  p.sub { margin: 0 0 20px; color: #94a3b8; font-size: 13px; }
  label { display: block; font-size: 13px; margin: 12px 0 4px; color: #cbd5e1; }
  input { width: 100%; padding: 9px 10px; border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; font-size: 14px; }
  input:focus { outline: 2px solid #3b82f6; border-color: transparent; }
  button { width: 100%; margin-top: 20px; padding: 10px; border: 0; border-radius: 8px; background: #3b82f6; color: #fff; font-size: 15px; cursor: pointer; }
  button:hover { background: #2563eb; }
</style>
</head>
<body>
<div class="card">
  <h1>DSH 登录</h1>
  <p class="sub">请输入账号密码以继续</p>
  <form method="post" action="/login" autocomplete="on">
    <label for="username">用户名</label>
    <input id="username" name="username" autocomplete="username" required autofocus>
    <label for="password">密码</label>
    <input id="password" type="password" name="password" autocomplete="current-password" required>
    <button type="submit">登 录</button>
  </form>
  <p class="error" id="error">__ERROR__</p>
</div>
</body>
</html>
```

- [ ] **Step 2: 写失败测试**

`tests/credentials.test.js`：
```js
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const creds = require('../lib/credentials.js');

test('scryptHash/verifyPassword 往返一致', () => {
  const user = creds.makeUser('alice', 's3cret');
  assert.equal(user.name, 'alice');
  assert.ok(user.salt.length >= 32);
  assert.equal(user.hash.length, 128);
  assert.ok(creds.verifyPassword('s3cret', user));
  assert.ok(!creds.verifyPassword('wrong', user));
});

test('runSetup 生成 5 个账号与凭据文件', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-proxy-'));
  const { configPath, credPath, config, rows } = creds.runSetup(dir, 5);
  assert.equal(config.users.length, 5);
  assert.ok(config.sessionSecret.length >= 32);
  const onDisk = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.equal(onDisk.users.length, 5);
  const text = fs.readFileSync(credPath, 'utf8');
  for (const row of rows) {
    const [name, password] = row.split('\t');
    const user = config.users.find((u) => u.name === name);
    assert.ok(user, `缺少用户 ${name}`);
    assert.ok(creds.verifyPassword(password, user));
    assert.ok(text.includes(`${name}\t${password}`));
  }
  assert.ok(rows.every((r) => r.startsWith('user') && r.includes('\t')));
});

test('loadConfig 读取并合并默认值', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-proxy-'));
  creds.runSetup(dir, 2);
  const loaded = creds.loadConfig(dir);
  assert.ok(loaded);
  assert.equal(loaded.listenPort, 3081);
  assert.equal(loaded.users.length, 2);
});

test('loadConfig 文件缺失返回 null', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-proxy-'));
  assert.equal(creds.loadConfig(dir), null);
});
```

- [ ] **Step 3: 运行测试确认失败**

Run: `node --test tests/credentials.test.js`
Expected: FAIL — `Cannot find module '../lib/credentials.js'`

- [ ] **Step 4: 实现 lib/credentials.js**

`lib/credentials.js`（完整内容）：
```js
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SCRYPT_KEYLEN = 64;

function scryptHash(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  return crypto.scryptSync(String(password), salt, SCRYPT_KEYLEN).toString('hex');
}

function verifyPassword(password, user) {
  const expected = Buffer.from(user.hash, 'hex');
  const actual = crypto.scryptSync(String(password), Buffer.from(user.salt, 'hex'), SCRYPT_KEYLEN);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function makeUser(name, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { name, salt, hash: scryptHash(password, salt) };
}

function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function defaultConfig() {
  return {
    listenPort: 3081,
    target: { host: '127.0.0.1', port: 3080 },
    sessionTtlMs: 12 * 60 * 60 * 1000,
    maxAttempts: 5,
    lockMs: 15 * 60 * 1000,
  };
}

function loadConfig(dir) {
  const p = path.join(dir, 'config.json');
  if (!fs.existsSync(p)) return null;
  const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
  return { ...defaultConfig(), ...raw };
}

function saveConfig(dir, config) {
  const p = path.join(dir, 'config.json');
  fs.writeFileSync(p, JSON.stringify(config, null, 2) + '\n', 'utf8');
  return p;
}

function runSetup(dir, userCount = 5) {
  const config = defaultConfig();
  config.sessionSecret = randomToken(32);
  const users = [];
  const rows = [];
  for (let i = 1; i <= userCount; i++) {
    const name = `user${i}`;
    const password = randomToken(12);
    users.push(makeUser(name, password));
    rows.push(`${name}\t${password}`);
  }
  config.users = users;
  const configPath = saveConfig(dir, config);
  const credPath = path.join(dir, 'credentials.txt');
  const header =
    'DSH LAN 代理账号凭据（妥善保管；用后可删除本文件）\n' +
    `访问地址: https://<本机局域网IP>:${config.listenPort}\n\n`;
  fs.writeFileSync(credPath, header + rows.join('\n') + '\n', 'utf8');
  return { configPath, credPath, config, rows };
}

module.exports = {
  SCRYPT_KEYLEN, scryptHash, verifyPassword, makeUser, randomToken,
  defaultConfig, loadConfig, saveConfig, runSetup,
};
```

- [ ] **Step 5: 运行测试确认通过**

Run: `node --test tests/credentials.test.js`
Expected: PASS — 4 tests, 0 failures

- [ ] **Step 6: 提交**

```bash
git add package.json .gitignore login.html lib/credentials.js tests/credentials.test.js
git commit -m "feat: 项目骨架 + 凭据/配置核心（scrypt、setup 生成 5 账号）"
```

---

### Task 2: 会话令牌（lib/session.js）

**Files:**
- Create: `lib/session.js`
- Test: `tests/session.test.js`

**Interfaces:**
- Consumes: 无（纯 crypto）
- Produces（后续任务依赖）:
  - `signSession(userName: string, secret: string, ttlMs: number, now?: number): string` — 返回 `base64url(JSON{u,exp}).base64url(HMAC-SHA256)`
  - `verifySession(token: string, secret: string, now?: number): string | null` — 校验通过返回用户名，否则 `null`

- [ ] **Step 1: 写失败测试**

`tests/session.test.js`：
```js
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { signSession, verifySession } = require('../lib/session.js');

const SECRET = 'test-secret';
const TTL = 60_000;

test('sign/verify 往返成功', () => {
  const token = signSession('user1', SECRET, TTL);
  assert.equal(verifySession(token, SECRET), 'user1');
});

test('篡改 token 被拒绝', () => {
  const token = signSession('user1', SECRET, TTL);
  const [payload, sig] = token.split('.');
  assert.equal(verifySession(`${payload}x.${sig}`, SECRET), null);
  assert.equal(verifySession(`${payload}.${sig}x`, SECRET), null);
});

test('错误密钥被拒绝', () => {
  const token = signSession('user1', SECRET, TTL);
  assert.equal(verifySession(token, 'other-secret'), null);
});

test('过期 token 被拒绝', () => {
  const token = signSession('user1', SECRET, TTL, 1_000_000);
  assert.equal(verifySession(token, SECRET, 1_000_000 + TTL + 1), null);
});

test('畸形 token 被拒绝', () => {
  assert.equal(verifySession('', SECRET), null);
  assert.equal(verifySession('abc', SECRET), null);
  assert.equal(verifySession('..', SECRET), null);
  assert.equal(verifySession(null, SECRET), null);
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `node --test tests/session.test.js`
Expected: FAIL — `Cannot find module '../lib/session.js'`

- [ ] **Step 3: 实现 lib/session.js**

`lib/session.js`（完整内容）：
```js
'use strict';

const crypto = require('node:crypto');

function signSession(userName, secret, ttlMs, now = Date.now()) {
  const payload = Buffer.from(JSON.stringify({ u: userName, exp: now + ttlMs })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifySession(token, secret, now = Date.now()) {
  if (typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot <= 0 || dot === token.length - 1) return null;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof data.u !== 'string' || typeof data.exp !== 'number') return null;
    if (data.exp <= now) return null;
    return data.u;
  } catch {
    return null;
  }
}

module.exports = { signSession, verifySession };
```

- [ ] **Step 4: 运行测试确认通过**

Run: `node --test tests/session.test.js`
Expected: PASS — 5 tests, 0 failures

- [ ] **Step 5: 提交**

```bash
git add lib/session.js tests/session.test.js
git commit -m "feat: HMAC 签名会话令牌（sign/verify/过期/防篡改）"
```

---

### Task 3: 认证层（登录/登出/限速/认证门）

**Files:**
- Create: `lib/auth.js`
- Test: `tests/auth.test.js`

**Interfaces:**
- Consumes: `credentials.verifyPassword`、`session.signSession/verifySession`（Task 1/2 的签名）
- Produces（Task 4-6 依赖）:
  - `createAuth(config, ctx: {dir, logger?}): auth`，其中
    - `auth.hasValidSession(req): boolean`
    - `auth.handleLogin(req, res): void`（含限速与 scrypt 校验，成功 302 `/` 并 Set-Cookie，失败 401 登录页，锁定 403）
    - `auth.handleLogout(req, res): void`（清 Cookie 302 `/login`）
    - `auth.redirectToLogin(res): void`（302 `/login`）
    - `auth.loginHtml(errorMessage: string): string`
    - `auth.attempts: Map<ip, {fail, lockedUntil}>`（测试断言用）

- [ ] **Step 1: 写失败测试**

`tests/auth.test.js`：
```js
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
```

注意：Task 3 的测试引用了 `lib/server.js` 的 `createProxy`（Task 6 才完成 HTTPS 包装），因此 Task 3 需要先写一个最小 `lib/server.js`（仅 http 模式），Task 6 再扩展为 HTTPS 模式。

- [ ] **Step 2: 运行测试确认失败**

Run: `node --test tests/auth.test.js`
Expected: FAIL — `Cannot find module '../lib/server.js'`

- [ ] **Step 3: 实现 lib/auth.js 与最小 lib/server.js**

`lib/auth.js`（完整内容）：
```js
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { verifyPassword } = require('./credentials.js');
const { signSession, verifySession } = require('./session.js');

function createAuth(config, ctx) {
  const log = ctx.logger || ((line) => console.log(line));
  const attempts = new Map(); // ip -> { fail, lockedUntil }

  function clientIp(req) {
    return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : 'unknown';
  }

  function cookieSid(req) {
    const header = req.headers.cookie;
    if (!header) return null;
    for (const part of header.split(';')) {
      const eq = part.indexOf('=');
      if (eq === -1) continue;
      if (part.slice(0, eq).trim() === 'sid') return part.slice(eq + 1).trim();
    }
    return null;
  }

  function hasValidSession(req) {
    const token = cookieSid(req);
    return token !== null && verifySession(token, config.sessionSecret) !== null;
  }

  function isLocked(ip) {
    const rec = attempts.get(ip);
    if (!rec) return false;
    if (rec.lockedUntil > Date.now()) return true;
    attempts.delete(ip);
    return false;
  }

  function recordFailure(ip) {
    const now = Date.now();
    let rec = attempts.get(ip);
    if (!rec || rec.lockedUntil <= now) rec = { fail: 0, lockedUntil: 0 };
    rec.fail += 1;
    if (rec.fail >= config.maxAttempts) rec.lockedUntil = now + config.lockMs;
    attempts.set(ip, rec);
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  function loginHtml(errorMessage) {
    const raw = fs.readFileSync(path.join(ctx.dir, 'login.html'), 'utf8');
    const msg = errorMessage
      ? `<p class="error" id="error">${escapeHtml(errorMessage)}</p>`
      : '';
    return raw.replace('<p class="error" id="error">__ERROR__</p>', msg);
  }

  function setSessionCookie(res, userName) {
    const token = signSession(userName, config.sessionSecret, config.sessionTtlMs);
    const maxAge = Math.floor(config.sessionTtlMs / 1000);
    res.setHeader('Set-Cookie',
      `sid=${token}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=${maxAge}`);
    return token;
  }

  function clearSessionCookie(res) {
    res.setHeader('Set-Cookie', 'sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  }

  function readBody(req, limit = 65536) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on('data', (c) => {
        size += c.length;
        if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }

  function handleLogin(req, res) {
    const ip = clientIp(req);
    if (isLocked(ip)) {
      res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(loginHtml('尝试次数过多，请稍后再试。'));
      return;
    }
    readBody(req)
      .then((body) => {
        const params = new URLSearchParams(body);
        const name = params.get('username') || '';
        const password = params.get('password') || '';
        const user = config.users.find((u) => u.name === name);
        if (user && verifyPassword(password, user)) {
          attempts.delete(ip);
          setSessionCookie(res, user.name);
          res.writeHead(302, { Location: '/' });
          res.end();
          log(`login ok: ${user.name} from ${ip}`);
          return;
        }
        recordFailure(ip);
        log(`login fail: ${name || '(empty)'} from ${ip}`);
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(loginHtml('用户名或密码错误。'));
      })
      .catch(() => {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('bad request');
      });
  }

  function handleLogout(req, res) {
    clearSessionCookie(res);
    res.writeHead(302, { Location: '/login' });
    res.end();
  }

  function redirectToLogin(res) {
    res.writeHead(302, { Location: '/login' });
    res.end();
  }

  return {
    attempts, clientIp, cookieSid, hasValidSession, isLocked, recordFailure,
    loginHtml, setSessionCookie, clearSessionCookie, readBody,
    handleLogin, handleLogout, redirectToLogin,
  };
}

module.exports = { createAuth };
```

`lib/server.js`（最小版本，仅 http 模式；Task 6 追加 HTTPS 分支）：
```js
'use strict';

const http = require('node:http');
const { createAuth } = require('./auth.js');

function createProxy(options) {
  const { config, dir, mode = 'https' } = options;
  const log = options.logger || ((line) => console.log(line));
  const auth = createAuth(config, { dir, logger: log });

  function handleRequest(req, res) {
    const url = req.url || '/';
    try {
      if (req.method === 'GET' && url === '/login') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(auth.loginHtml(''));
        return;
      }
      if (req.method === 'POST' && url === '/login') {
        auth.handleLogin(req, res);
        return;
      }
      if (req.method === 'POST' && url === '/logout') {
        auth.handleLogout(req, res);
        return;
      }
      if (!auth.hasValidSession(req)) {
        auth.redirectToLogin(res);
        return;
      }
      // Task 4 在此接入 forwardRequest
      res.writeHead(501, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('not implemented');
    } catch (err) {
      log(`request error: ${err.stack || err.message}`);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('internal error');
      } else {
        res.destroy();
      }
    }
  }

  const handler = http.createServer(handleRequest);

  function listen() {
    return new Promise((resolve, reject) => {
      const listener = handler.listen(config.listenPort, '0.0.0.0', () => resolve(listener));
      listener.on('error', reject);
    });
  }

  function close() {
    return new Promise((resolve) => handler.close(() => resolve()));
  }

  return { listen, close, auth };
}

module.exports = { createProxy };
```

- [ ] **Step 4: 运行测试确认通过**

Run: `node --test tests/auth.test.js`
Expected: PASS — 5 tests, 0 failures

- [ ] **Step 5: 提交**

```bash
git add lib/auth.js lib/server.js tests/auth.test.js
git commit -m "feat: 登录/登出/限速/认证门（含最小 http 模式 server）"
```

---

### Task 4: 反向代理（HTTP 转发 + Host/Origin 改写 + 502）

**Files:**
- Create: `lib/proxy.js`
- Modify: `lib/server.js`（认证通过后调用 `forwardRequest`）
- Test: `tests/proxy.test.js`

**Interfaces:**
- Consumes: `createProxy`（Task 3）；本任务新增 `proxy.forwardRequest(req, res, config, logger)`
- Produces（Task 5 依赖）: `proxy.rewriteHeaders(headers, config)`、`proxy.proxyRequestHeaders(headers, config)`、`proxy.cleanResponseHeaders(headers)`

- [ ] **Step 1: 写失败测试**

`tests/proxy.test.js`：
```js
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
```

- [ ] **Step 2: 运行测试确认失败**

Run: `node --test tests/proxy.test.js`
Expected: FAIL — 认证通过后返回 501 `not implemented`（代理未实现）

- [ ] **Step 3: 实现 lib/proxy.js 并接入 server.js**

`lib/proxy.js`（完整内容）：
```js
'use strict';

const http = require('node:http');

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'trailers', 'transfer-encoding', 'upgrade',
]);

function authorityOf(config) {
  return `${config.target.host}:${config.target.port}`;
}

function rewriteHeaders(headers, config) {
  const out = { ...headers };
  const authority = authorityOf(config);
  out.host = authority;
  if (out.origin) out.origin = `http://${authority}`;
  return out;
}

function proxyRequestHeaders(headers, config) {
  const out = {};
  for (const [k, v] of Object.entries(rewriteHeaders(headers, config))) {
    if (!HOP_BY_HOP.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

function cleanResponseHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!HOP_BY_HOP.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

function forwardRequest(req, res, config, logger) {
  const proxyReq = http.request({
    host: config.target.host,
    port: config.target.port,
    method: req.method,
    path: req.url || '/',
    headers: proxyRequestHeaders(req.headers, config),
  }, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, cleanResponseHeaders(proxyRes.headers));
    proxyRes.pipe(res);
    logger(`${req.method} ${req.url} -> ${proxyRes.statusCode}`);
  });
  proxyReq.on('error', (err) => {
    logger(`proxy error: ${err.message} ${req.method} ${req.url}`);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('后端服务不可用（502）。');
    } else {
      res.destroy();
    }
  });
  req.pipe(proxyReq);
}

module.exports = {
  authorityOf, rewriteHeaders, proxyRequestHeaders, cleanResponseHeaders, forwardRequest,
};
```

修改 `lib/server.js`：把认证通过后的占位分支替换为转发调用，并引入 `proxy.js`：
```js
// 文件顶部 require 区新增一行：
const { forwardRequest } = require('./proxy.js');

// handleRequest 中把
//   res.writeHead(501, { 'Content-Type': 'text/plain; charset=utf-8' });
//   res.end('not implemented');
// 替换为
  forwardRequest(req, res, config, log);
```

- [ ] **Step 4: 运行测试确认通过**

Run: `node --test tests/proxy.test.js`
Expected: PASS — 3 tests, 0 failures
（同时重跑：`node --test tests/auth.test.js` 仍全绿）

- [ ] **Step 5: 提交**

```bash
git add lib/proxy.js lib/server.js tests/proxy.test.js
git commit -m "feat: HTTP 反向代理（Host/Origin 改写、hop-by-hop 清洗、502）"
```

---

### Task 5: WebSocket 隧道

**Files:**
- Modify: `lib/proxy.js`（追加 `forwardUpgrade`）
- Modify: `lib/server.js`（挂 `upgrade` 事件，认证后转发，未认证 403）
- Test: `tests/upgrade.test.js`

**Interfaces:**
- Consumes: `proxy.rewriteHeaders`（Task 4）
- Produces: `proxy.forwardUpgrade(req, socket, head, config, logger)` — 完成 101 握手并双向管道

- [ ] **Step 1: 写失败测试**

`tests/upgrade.test.js`：
```js
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
```

注意：`upgrade()` 里 resolve 时 `socket.on('data')` 已经绑定了监听器，回显测试里再加一个 `data` 监听器会同时收到数据（两个监听器都会触发，没问题）。为避免时序问题，回显测试用 `setTimeout` 聚合并比较完整帧。

- [ ] **Step 2: 运行测试确认失败**

Run: `node --test tests/upgrade.test.js`
Expected: FAIL — 第一个用例升级请求到达代理后无 101（服务器无 upgrade 处理），连接被挂起或直接失败

- [ ] **Step 3: 实现 forwardUpgrade 并挂接 upgrade 事件**

在 `lib/proxy.js` 末尾追加（文件完整内容在 Task 4 基础上新增以下函数并加入导出）：
```js
function forwardUpgrade(req, socket, head, config, logger) {
  const proxyReq = http.request({
    host: config.target.host,
    port: config.target.port,
    method: 'GET',
    path: req.url || '/',
    headers: rewriteHeaders(req.headers, config), // 保留 connection/upgrade/sec-websocket-*
  });
  proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
    const lines = ['HTTP/1.1 101 Switching Protocols'];
    for (const [k, v] of Object.entries(proxyRes.headers)) {
      if (Array.isArray(v)) for (const item of v) lines.push(`${k}: ${item}`);
      else lines.push(`${k}: ${v}`);
    }
    socket.write(lines.join('\r\n') + '\r\n\r\n');
    if (proxyHead && proxyHead.length) socket.write(proxyHead);
    proxySocket.pipe(socket);
    socket.pipe(proxySocket);
    socket.on('error', () => proxySocket.destroy());
    proxySocket.on('error', () => socket.destroy());
    logger(`upgrade ok: ${req.url}`);
  });
  proxyReq.on('response', () => { socket.destroy(); });
  proxyReq.on('error', (err) => {
    logger(`upgrade error: ${err.message} ${req.url}`);
    socket.destroy();
  });
  if (head && head.length) proxyReq.write(head);
  proxyReq.end();
}
```
导出列表改为：
```js
module.exports = {
  authorityOf, rewriteHeaders, proxyRequestHeaders, cleanResponseHeaders,
  forwardRequest, forwardUpgrade,
};
```

修改 `lib/server.js`：在 `handleRequest` 定义后新增 `handleUpgrade` 并挂到 handler 上：
```js
  function handleUpgrade(req, socket, head) {
    if (!auth.hasValidSession(req)) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    forwardUpgrade(req, socket, head, config, log);
  }

  const handler = http.createServer(handleRequest);
  handler.on('upgrade', handleUpgrade);
```
并把 `lib/server.js` 顶部的 require 改为：
```js
const { forwardRequest, forwardUpgrade } = require('./proxy.js');
```

- [ ] **Step 4: 运行测试确认通过**

Run: `node --test tests/upgrade.test.js`
Expected: PASS — 2 tests, 0 failures
（同时重跑 `node --test tests/` 全量，确认 14 个测试全绿）

- [ ] **Step 5: 提交**

```bash
git add lib/proxy.js lib/server.js tests/upgrade.test.js
git commit -m "feat: WebSocket 升级隧道（认证门 + 101 握手 + 双向管道）"
```

---

### Task 6: HTTPS 包装（TLS 嗅探 + 明文 301）+ 证书生成

**Files:**
- Modify: `lib/server.js`（https 模式：net 嗅探 → TLSSocket → `secureConnection`；明文 → 301）
- Create: `certgen.ps1`
- Test: `tests/server.test.js`
- Manual: 用真实证书验证 TLS 握手

**Interfaces:**
- Consumes: Task 3-5 的 `handleRequest`/`handleUpgrade`
- Produces: `createProxy({config, dir, mode: 'https', key, cert, logger?})` — `listen()` 解析出 net.Server（`listener.address().port` 可用）

- [ ] **Step 1: 写失败测试（明文 HTTP 301）**

`tests/server.test.js`：
```js
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
```

- [ ] **Step 2: 运行测试确认失败**

Run: `node --test tests/server.test.js`
Expected: FAIL — 当前 `createProxy` 只支持 http 模式，`mode: 'https'` 回退到 http 监听返回 200 而非 301

- [ ] **Step 3: 实现 https 模式并创建 certgen.ps1**

替换 `lib/server.js` 的 `listen`/`close` 部分（完整文件最终版如下）：
```js
'use strict';

const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');
const { createAuth } = require('./auth.js');
const { forwardRequest, forwardUpgrade } = require('./proxy.js');

function createProxy(options) {
  const { config, dir, mode = 'https' } = options;
  const log = options.logger || ((line) => console.log(line));
  const auth = createAuth(config, { dir, logger: log });

  function handleRequest(req, res) {
    const url = req.url || '/';
    try {
      if (req.method === 'GET' && url === '/login') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(auth.loginHtml(''));
        return;
      }
      if (req.method === 'POST' && url === '/login') {
        auth.handleLogin(req, res);
        return;
      }
      if (req.method === 'POST' && url === '/logout') {
        auth.handleLogout(req, res);
        return;
      }
      if (!auth.hasValidSession(req)) {
        auth.redirectToLogin(res);
        return;
      }
      forwardRequest(req, res, config, log);
    } catch (err) {
      log(`request error: ${err.stack || err.message}`);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('internal error');
      } else {
        res.destroy();
      }
    }
  }

  function handleUpgrade(req, socket, head) {
    if (!auth.hasValidSession(req)) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    forwardUpgrade(req, socket, head, config, log);
  }

  const handler = http.createServer(handleRequest);
  handler.on('upgrade', handleUpgrade);

  let listener = null;

  function listen() {
    return new Promise((resolve, reject) => {
      if (mode === 'http') {
        listener = handler.listen(config.listenPort, '0.0.0.0', () => resolve(listener));
        listener.on('error', reject);
        return;
      }
      const secureContext = tls.createSecureContext({ key: options.key, cert: options.cert });
      // https.Server 内部把 secureConnection -> http connectionListener 接好；
      // 我们手动发出 secureConnection 事件，跳过它自己的 listen()。
      const tlsServer = https.createServer({ key: options.key, cert: options.cert }, handleRequest);
      tlsServer.on('upgrade', handleUpgrade);
      const httpRedirect = http.createServer((req, res) => {
        res.writeHead(301, { Location: `https://${req.headers.host}${req.url || '/'}` });
        res.end();
      });
      httpRedirect.on('upgrade', (req, socket) => {
        socket.write(
          `HTTP/1.1 301 Moved Permanently\r\nLocation: wss://${req.headers.host}${req.url || '/'}\r\nConnection: close\r\n\r\n`);
        socket.destroy();
      });
      listener = net.createServer((socket) => {
        socket.once('data', (chunk) => {
          socket.pause();
          socket.unshift(chunk);
          if (chunk.length > 0 && chunk[0] === 0x16) {
            // TLS ClientHello：包一层 TLSSocket，握手完成后交给 https 层
            const tlsSocket = new tls.TLSSocket(socket, { isServer: true, secureContext });
            tlsSocket.on('error', () => {});
            tlsSocket.on('secure', () => tlsServer.emit('secureConnection', tlsSocket));
            socket.resume();
          } else {
            // 明文 HTTP：301 到 HTTPS
            httpRedirect.emit('connection', socket);
            socket.resume();
          }
        });
        socket.on('error', () => {});
      });
      listener.listen(config.listenPort, '0.0.0.0', () => resolve(listener));
      listener.on('error', reject);
    });
  }

  function close() {
    return new Promise((resolve) => {
      if (listener) listener.close(() => resolve());
      else resolve();
    });
  }

  return { listen, close, auth };
}

module.exports = { createProxy };
```

`certgen.ps1`（完整内容，自签名证书有效期 1 年，导出 cert.pem/key.pem）：
```powershell
# 生成自签名证书 cert.pem / key.pem（有效期 1 年）
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$dns = @('192.168.110.168', 'localhost', '127.0.0.1')
$cert = New-SelfSignedCertificate -Subject 'CN=192.168.110.168' -DnsName $dns `
  -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 2048 `
  -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(1)
try {
  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
  [System.IO.File]::WriteAllText((Join-Path $dir 'cert.pem'), $cert.ExportCertificatePem())
  [System.IO.File]::WriteAllText((Join-Path $dir 'key.pem'), $rsa.ExportPkcs8PrivateKeyPem())
  Write-Host "已生成 cert.pem / key.pem，有效期至 $($cert.NotAfter.ToString('yyyy-MM-dd'))"
} finally {
  Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `node --test tests/server.test.js`
Expected: PASS — 1 test, 0 failures

- [ ] **Step 5: 手动验证 TLS 握手（真实证书）**

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File certgen.ps1
node -e "const c=require('./lib/server.js'),creds=require('./lib/credentials.js'),fs=require('fs');const dir=process.cwd();const cfg=creds.defaultConfig();cfg.listenPort=0;cfg.sessionSecret='x'.repeat(64);cfg.users=[creds.makeUser('u','p')];const p=c.createProxy({config:cfg,dir,mode:'https',key:fs.readFileSync('key.pem'),cert:fs.readFileSync('cert.pem')});p.listen().then(l=>{console.log('PORT='+l.address().port);})"
```
Expected: 输出 `PORT=<随机端口>`。随后在另一个终端：
```bash
curl -k -s -o NUL -w "%{http_code}" https://127.0.0.1:<PORT>/login
```
Expected: `200`（登录页可达，TLS 握手正常）。

- [ ] **Step 6: 提交**

```bash
git add lib/server.js certgen.ps1 tests/server.test.js
git commit -m "feat: HTTPS 包装（TLS 嗅探 + 明文 301）+ 自签名证书生成脚本"
```

---

### Task 7: CLI 与部署（setup/adduser/run + 防火墙 + 真实端到端）

**Files:**
- Create: `server.js`
- Test: `tests/cli.test.js`
- Deploy: 运行 setup、生成证书、启动真实服务、验证端到端、防火墙放行

**Interfaces:**
- Consumes: `creds.runSetup/loadConfig/saveConfig/makeUser/randomToken`、`createProxy`（Task 6）
- Produces: 可执行 CLI（`node server.js setup|adduser|run`）

- [ ] **Step 1: 写失败测试**

`tests/cli.test.js`：
```js
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const creds = require('../lib/credentials.js');

const SERVER = path.join(__dirname, '..', 'server.js');

function runCli(args, dir) {
  return spawnSync(process.execPath, [SERVER, ...args], {
    encoding: 'utf8',
    env: { ...process.env, LAN_PROXY_DIR: dir },
  });
}

test('setup 创建 config.json 与 credentials.txt（5 账号）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-proxy-cli-'));
  const res = runCli(['setup', '5'], dir);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /user1/);
  const config = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
  assert.equal(config.users.length, 5);
  assert.ok(config.sessionSecret);
  const text = fs.readFileSync(path.join(dir, 'credentials.txt'), 'utf8');
  for (const u of config.users) {
    const line = text.split('\n').find((l) => l.startsWith(`${u.name}\t`));
    assert.ok(line, `凭据文件缺少 ${u.name}`);
    const password = line.split('\t')[1];
    assert.ok(creds.verifyPassword(password, u));
  }
});

test('adduser 追加账号并可验证密码', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-proxy-cli-'));
  runCli(['setup', '1'], dir);
  const res = runCli(['adduser', 'bob', 'secret123'], dir);
  assert.equal(res.status, 0, res.stderr);
  const config = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
  assert.equal(config.users.length, 2);
  const bob = config.users.find((u) => u.name === 'bob');
  assert.ok(bob);
  assert.ok(creds.verifyPassword('secret123', bob));
});

test('重复 adduser 拒绝（退出码 2）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-proxy-cli-'));
  runCli(['setup', '1'], dir);
  const res = runCli(['adduser', 'user1', 'x'], dir);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /用户已存在/);
});

test('缺少 config 时 run 报错提示先 setup（退出码 1）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lan-proxy-cli-'));
  const res = runCli(['run'], dir);
  assert.equal(res.status, 1);
  assert.match(res.stderr, /setup/);
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `node --test tests/cli.test.js`
Expected: FAIL — `Cannot find module '../server.js'`

- [ ] **Step 3: 实现 server.js（CLI）**

`server.js`（完整内容）：
```js
#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const creds = require('./lib/credentials.js');

const ROOT = process.env.LAN_PROXY_DIR || __dirname;
const CERT = path.join(ROOT, 'cert.pem');
const KEY = path.join(ROOT, 'key.pem');
const command = process.argv[2] || 'run';

function exit(msg, code) {
  console.error(msg);
  process.exit(code);
}

if (command === 'setup') {
  const count = Number(process.argv[3]) || 5;
  const { configPath, credPath, rows } = creds.runSetup(ROOT, count);
  console.log(`配置已写入: ${configPath}`);
  console.log(`凭据已写入: ${credPath}`);
  console.log('\n================ 账号凭据 ================');
  for (const row of rows) console.log(row);
  console.log('==========================================\n');
  console.log('请妥善保管以上凭据；分发后建议删除 credentials.txt。');
  if (!fs.existsSync(CERT) || !fs.existsSync(KEY)) {
    console.log('\n证书缺失，请运行: powershell -NoProfile -ExecutionPolicy Bypass -File certgen.ps1');
  }
  process.exit(0);
}

if (command === 'adduser') {
  const name = process.argv[3];
  const password = process.argv[4] || creds.randomToken(12);
  if (!name) exit('用法: node server.js adduser <用户名> [密码]', 2);
  const config = creds.loadConfig(ROOT);
  if (!config) exit('请先运行: node server.js setup', 2);
  if (config.users.some((u) => u.name === name)) exit(`用户已存在: ${name}`, 2);
  config.users.push(creds.makeUser(name, password));
  creds.saveConfig(ROOT, config);
  fs.appendFileSync(path.join(ROOT, 'credentials.txt'), `${name}\t${password}\n`, 'utf8');
  console.log(`已添加用户 ${name}，密码: ${password}`);
  process.exit(0);
}

if (command !== 'run') exit(`未知命令: ${command}（支持 setup / adduser / run）`, 2);

const config = creds.loadConfig(ROOT);
if (!config) exit('缺少 config.json，请先运行: node server.js setup', 1);
if (!fs.existsSync(CERT) || !fs.existsSync(KEY)) {
  exit('缺少 cert.pem/key.pem，请先运行: powershell -NoProfile -ExecutionPolicy Bypass -File certgen.ps1', 1);
}

const { createProxy } = require('./lib/server.js');
const proxy = createProxy({
  config,
  dir: ROOT,
  mode: 'https',
  key: fs.readFileSync(KEY),
  cert: fs.readFileSync(CERT),
});
proxy.listen()
  .then((listener) => {
    const port = listener.address().port;
    console.log(`lan-proxy 已启动: https://<局域网IP>:${port} -> http://${config.target.host}:${config.target.port}`);
    console.log(`本机自测: curl -k https://127.0.0.1:${port}/login`);
  })
  .catch((err) => exit(`启动失败: ${err.message}`, 1));
```

- [ ] **Step 4: 运行测试确认通过**

Run: `node --test tests/cli.test.js`
Expected: PASS — 4 tests, 0 failures
（全量回归：`node --test tests/` 应 19 个测试全绿）

- [ ] **Step 5: 部署——生成配置与证书**

```bash
node server.js setup 5
powershell -NoProfile -ExecutionPolicy Bypass -File certgen.ps1
```
Expected: setup 打印 5 组 `userN\t<密码>`；certgen 打印 `已生成 cert.pem / key.pem`。
（把 setup 打印的凭据转交用户；`credentials.txt` 已落盘可分发。）

- [ ] **Step 6: 部署——启动真实代理（后台）**

```bash
node server.js
```
在后台运行（managed background job）。Expected 启动日志：`lan-proxy 已启动: https://<局域网IP>:3081 -> http://127.0.0.1:3080`

- [ ] **Step 7: 部署——端到端验证（对本机 3081 实测真实 dsh）**

```bash
# 1) 登录页可达
curl -k -s -o NUL -w "%{http_code}" https://127.0.0.1:3081/login
# Expected: 200

# 2) 未登录访问 / → 302
curl -k -s -o NUL -w "%{http_code}" https://127.0.0.1:3081/
# Expected: 302

# 3) 登录拿 Cookie 后访问 / → dsh 首页（200，且内容来自 dsh）
curl -k -s -c cookies.txt -d "username=user1&password=<密码>" https://127.0.0.1:3081/login -o NUL -w "%{http_code}"
curl -k -s -b cookies.txt https://127.0.0.1:3081/ -o home.html -w "%{http_code}"
# Expected: 302 然后 200；home.html 为 dsh 前端 HTML

# 4) 带 Cookie 访问 /api → 非 403（信任围栏通过）
curl -k -s -b cookies.txt -X POST https://127.0.0.1:3081/api/describe -o NUL -w "%{http_code}"
# Expected: 非 403（400/404/500 均可，说明围栏放行）

# 5) 明文 HTTP → 301
curl -s -o NUL -w "%{http_code}" http://127.0.0.1:3081/login
# Expected: 301

# 6) WebSocket 升级（用 node 脚本带 Cookie 探测，期望 101）
node -e "const c=require('node:crypto'),net=require('node:net'),fs=require('fs');const cookie=fs.readFileSync('cookies.txt','utf8').split('\\n').find(l=>l.includes('sid'))?.split(/\\s+/)[6];const s=net.connect(3081,'127.0.0.1',()=>{s.write('GET /api/events.host HTTP/1.1\r\nHost: 127.0.0.1:3081\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+c.randomBytes(16).toString('base64')+'\r\nCookie: sid='+cookie+'\r\n\r\n');});let d='';s.on('data',x=>{d+=x;if(d.includes('101')){console.log('WS 101 OK');s.destroy();process.exit(0);}});setTimeout(()=>{console.log('WS FAIL:',d.slice(0,80));process.exit(1);},3000);"
# Expected: WS 101 OK
```

- [ ] **Step 8: 部署——防火墙放行入站 TCP 3081**

```bash
netsh advfirewall firewall add rule name="DSH LAN Proxy 3081" dir=in action=allow protocol=TCP localport=3081
```
Expected: `Ok.`（若提示需要管理员权限，则以管理员身份运行 PowerShell 执行同一条命令，或运行：
`Start-Process powershell -Verb RunAs -ArgumentList 'netsh advfirewall firewall add rule name="DSH LAN Proxy 3081" dir=in action=allow protocol=TCP localport=3081'`）

- [ ] **Step 9: 交付说明**

向用户交付：
- 局域网访问地址：`https://192.168.110.168:3081`（本机局域网 IP；证书自签名，浏览器首次提示"不受信任"点继续）
- 账号：`user1`–`user5`，密码见 `D:\DSH\lan-proxy\credentials.txt`（分发后建议删除该文件）
- 本机仍可直接访问 `http://127.0.0.1:3080`（无需登录，不受影响）
- 维护命令：`node server.js adduser <用户名> [密码]`；停止暴露：结束 `node server.js` 进程并删除防火墙规则

- [ ] **Step 10: 提交**

```bash
git add server.js tests/cli.test.js
git commit -m "feat: CLI（setup/adduser/run）与部署验证"
```
（config.json / credentials.txt / cert.pem / key.pem 已被 .gitignore 排除，不会入库。）

---

## Self-Review（计划自检）

**规格覆盖核对：**
- 5 账号 + credentials.txt → Task 1（runSetup）✓
- 本机 127.0.0.1:3080 不受影响 → Task 7 Step 9（不修改 dsh，仅代理层）✓
- 自签名 HTTPS → Task 6（certgen.ps1 + TLS 嗅探）✓
- 登录页 → Task 1（login.html）+ Task 3（/login 端点）✓
- 会话 Cookie 12h HMAC → Task 2 + Task 3（setSessionCookie）✓
- 限速 5 次/15 分钟 → Task 3（默认配置 + 测试用 3 次覆盖）✓
- WebSocket → Task 5 ✓
- Host/Origin 改写 → Task 4 ✓
- 明文 HTTP 301 → Task 6 ✓
- 后端不可达 502 → Task 4 ✓
- 防火墙放行 → Task 7 Step 8 ✓
- CLI（setup/adduser/run）→ Task 7 ✓
- 规格测试计划 1-8 项 → Task 3/4/5/6/7 测试与验证步骤逐项对应 ✓

**占位符扫描：** 无 TBD/TODO/"后续实现"；所有代码块完整。

**类型/名称一致性：** `createAuth`、`hasValidSession`、`handleLogin`、`loginHtml`、`forwardRequest`、`forwardUpgrade`、`rewriteHeaders`、`proxyRequestHeaders`、`cleanResponseHeaders`、`runSetup`、`loadConfig`、`makeUser`、`verifyPassword`、`randomToken`、`defaultConfig` 在各任务中签名一致；测试断言与实现返回值一致（如 `listen()` 均 resolve 监听器，`listener.address().port` 取端口）。

**已知风险与对策：**
- Task 6 的 TLS 嗅探依赖 Node 内部 `https.Server` 的 `secureConnection` 事件路径（tls.Server 在握手完成后发出），采用 `tlsSocket.on('secure')` 后手动 emit，规避对 `http.Server` 直接喂 TLSSocket 的兼容性风险；Step 5 手动验证兜底。若手动验证失败，回退方案：仅 HTTPS（用户显式输入 `https://`），删除明文 301 分支并更新测试。
- 回显 WS 测试用 `setTimeout(300ms)` 聚合帧，避免监听器竞争；若偶发，可在 resolve 后先移除临时监听器再断言。

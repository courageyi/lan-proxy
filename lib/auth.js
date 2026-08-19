'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { verifyPassword } = require('./credentials.js');
const { signSession, verifySession } = require('./session.js');

function createAuth(config, ctx) {
  const log = ctx.logger || ((line) => console.log(line));
  const attempts = new Map(); // ip -> { fail, lockedUntil }
  const revoked = new Map(); // token -> addedAt（登出后吊销，防旧 sid 复用）

  // FIFO 淘汰：Map 保持插入序，超限时删除最旧条目。O(1) 均摊（仅在超限时触发）。
  function capMap(map, cap) {
    while (map.size > cap) map.delete(map.keys().next().value);
  }

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
    if (token === null || revoked.has(token)) return false;
    return verifySession(token, config.sessionSecret) !== null;
  }

  function isLocked(ip) {
    const rec = attempts.get(ip);
    if (!rec) return false;
    if (rec.lockedUntil > Date.now()) return true;
    if (rec.lockedUntil > 0) attempts.delete(ip); // 锁已过期，清理记录
    return false;
  }

  function recordFailure(ip) {
    const now = Date.now();
    let rec = attempts.get(ip);
    // 无记录，或锁已过期需要重新计数；未锁定过的记录（lockedUntil === 0）保留累计次数
    if (!rec || (rec.lockedUntil > 0 && rec.lockedUntil <= now)) rec = { fail: 0, lockedUntil: 0 };
    rec.fail += 1;
    if (rec.fail >= config.maxAttempts) rec.lockedUntil = now + config.lockMs;
    attempts.set(ip, rec);
    // 容量上限：超限时淘汰最旧记录（含 lockedUntil === 0 的未锁定记录），
    // 防止大量不同来源 IP 的失败记录无界增长。
    capMap(attempts, config.attemptsCap);
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
    const token = cookieSid(req);
    if (token && verifySession(token, config.sessionSecret) !== null) {
      // 只吊销有效令牌：伪造/无效 sid 直接忽略，防止 revoked 表被无界灌入。
      // 过期条目由 FIFO 上限自然淘汰（verifySession 本身也会拒绝过期令牌），
      // 不再需要每次登出做全表 O(n) 扫描。
      revoked.set(token, Date.now());
      capMap(revoked, config.revokedCap);
    }
    clearSessionCookie(res);
    res.writeHead(302, { Location: '/login' });
    res.end();
  }

  function redirectToLogin(res) {
    res.writeHead(302, { Location: '/login' });
    res.end();
  }

  return {
    attempts, revoked, clientIp, cookieSid, hasValidSession, isLocked, recordFailure,
    loginHtml, setSessionCookie, clearSessionCookie, readBody,
    handleLogin, handleLogout, redirectToLogin,
  };
}

module.exports = { createAuth };

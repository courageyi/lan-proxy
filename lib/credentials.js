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

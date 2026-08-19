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

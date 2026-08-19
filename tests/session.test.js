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

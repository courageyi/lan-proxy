'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const creds = require('../lib/credentials.js');

const SERVER = path.join(__dirname, '..', 'server.js');

// 沙箱限制：子进程 piped stdio 会触发 EPERM（见 task-7 报告），
// 故用文件描述符捕获 stdout/stderr（不经过管道），语义与
// spawnSync(..., { encoding: 'utf8' }) 完全一致。
function runCli(args, dir) {
  const outFile = path.join(dir, 'cli.out');
  const errFile = path.join(dir, 'cli.err');
  const outFd = fs.openSync(outFile, 'w');
  const errFd = fs.openSync(errFile, 'w');
  let res;
  try {
    res = spawnSync(process.execPath, [SERVER, ...args], {
      env: { ...process.env, LAN_PROXY_DIR: dir },
      stdio: ['ignore', outFd, errFd],
    });
  } finally {
    fs.closeSync(outFd);
    fs.closeSync(errFd);
  }
  return {
    status: res.status,
    stdout: fs.readFileSync(outFile, 'utf8'),
    stderr: fs.readFileSync(errFile, 'utf8'),
  };
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

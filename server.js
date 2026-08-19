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

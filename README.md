# lan-proxy — DSH 局域网认证代理

> LAN authentication proxy for the DeepSeek Harness Web GUI. Zero-dependency Node.js reverse proxy that puts a login page in front of `http://127.0.0.1:3080` and exposes it over the LAN on HTTPS.

给 DSH Web GUI（`127.0.0.1:3080`）加一层**登录认证**，通过 **HTTPS** 安全暴露到局域网（默认 `0.0.0.0:3081`），局域网内其他设备登录后即可使用。**不改动、不重启 dsh 本体**。

## 功能特性

- 🔐 **登录认证**：账号密码（scrypt 加盐哈希存储，绝不存明文）
- 🍪 **会话 Cookie**：HMAC-SHA256 签名令牌，`HttpOnly; SameSite=Strict; Secure`，默认 12 小时
- 🛡️ **登录限速**：同一 IP 连续失败 5 次锁定 15 分钟
- 🚪 **登出吊销**：登出后旧会话立即失效（有界吊销表，防内存膨胀）
- 🔒 **HTTPS**：自签名证书；明文 HTTP 访问自动 301 跳转 HTTPS
- 🔁 **双向代理**：普通 HTTP + WebSocket（`events.mux` / `events.host`）完整转发
- 🧱 **信任围栏兼容**：转发时改写 `Host`/`Origin` 为回环权威，通过 dsh 的浏览器信任围栏
- 🧹 **健壮性**：连接断开（任何时刻、任一方向）全路径清理，不泄漏、不崩溃
- 📦 **零第三方依赖**：仅 Node.js 内置模块（`http`/`https`/`net`/`tls`/`crypto`）
- 🖥️ **CLI**：`setup` / `adduser` / `run` 三个命令

## 环境要求

- **Node.js ≥ 18.3**（推荐 20+，实测 v24.18.0）
- **Windows**（证书生成脚本；macOS/Linux 可手动用 openssl 生成 cert.pem/key.pem）
- 证书生成：**Git for Windows 自带 openssl** 或 PowerShell 7+（`New-SelfSignedCertificate`）

## 快速开始

```powershell
# 1) 生成配置与 5 个账号（密码写入 credentials.txt）
node server.js setup 5

# 2) 生成自签名证书 cert.pem / key.pem
powershell -NoProfile -ExecutionPolicy Bypass -File certgen.ps1

# 3) 启动代理（默认 0.0.0.0:3081 → 127.0.0.1:3080）
node server.js

# 4) 放行防火墙入站端口（需管理员 PowerShell）
netsh advfirewall firewall add rule name="DSH LAN Proxy 3081" dir=in action=allow protocol=TCP localport=3081
```

启动后局域网设备访问 **`https://<本机局域网IP>:3081`**：

1. 浏览器首次提示"证书不受信任"（自签名）→ 点 **高级 → 继续访问**
2. 用 `credentials.txt` 中的账号密码登录（如 `user1`）
3. 登录后即可使用 DSH 智能体界面

> 本机仍可直接访问 `http://127.0.0.1:3080`（回环访问无需登录，不受影响）。

## CLI 命令

| 命令 | 说明 |
|------|------|
| `node server.js setup [数量]` | 生成 `config.json` + `credentials.txt`，默认 5 个账号 `user1`~`userN`，随机强密码 |
| `node server.js adduser <用户名> [密码]` | 追加账号（不提供密码则随机生成） |
| `node server.js` | 启动代理（要求 `config.json` 与证书已就绪） |

## 配置（config.json）

```jsonc
{
  "listenPort": 3081,                // 监听端口（0.0.0.0）
  "target": { "host": "127.0.0.1", "port": 3080 },  // 后端 dsh
  "sessionTtlMs": 43200000,          // 会话有效期（12 小时）
  "maxAttempts": 5,                  // 登录失败次数上限
  "lockMs": 900000,                  // 锁定时长（15 分钟）
  "sessionSecret": "<随机 hex>",      // 会话签名密钥（setup 生成）
  "revokedCap": 10000,               // 吊销表上限
  "attemptsCap": 10000,              // 限速记录上限
  "users": [{ "name": "user1", "salt": "<hex>", "hash": "<hex>" }]  // scrypt 加盐哈希
}
```

## 开机自启

仓库内置两个启动器（`autostart/`），复制到启动文件夹即可登录后自动启动：

```powershell
$startup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Copy-Item autostart\dsh-web-launch.vbs   $startup   # 10 秒后启动 pnpm dsh web（GUI）
Copy-Item autostart\lan-proxy-launch.vbs $startup   # 20 秒后启动本代理
```

- 隐藏窗口运行，日志写入 `logs/`
- 需要**开机未登录也启动**时，用管理员 PowerShell 建计划任务（`schtasks /create /sc onstart /ru SYSTEM ...`）
- 手动启动用 `start-lan-proxy.bat`（双击即可，关窗即停）

## 开发与测试

```powershell
npm test                 # 运行全部测试（34 个用例）
# 或指定文件：node --test tests/proxy.test.js
```

测试覆盖：凭据/scrypt、会话令牌、登录/登出/限速、HTTP 代理（Host/Origin 改写、502）、WebSocket 隧道（101/403/断开清理）、HTTPS 嗅探与明文 301、CLI 全命令。

## 项目结构

```
lan-proxy/
├── server.js            # CLI 入口（setup / adduser / run）
├── lib/
│   ├── credentials.js   # 配置读写、scrypt 密码哈希、账号生成
│   ├── session.js       # HMAC 签名会话令牌（签发/校验/过期）
│   ├── auth.js          # 登录/登出/限速/认证门/吊销
│   ├── proxy.js         # HTTP+WebSocket 转发、Host/Origin 改写、断开清理
│   └── server.js        # HTTPS（TLS 嗅探）+ 明文 301 + 路由组合
├── login.html           # 登录页
├── certgen.ps1          # 自签名证书生成（openssl 优先）
├── start-lan-proxy.bat  # 手动启动脚本
├── autostart/           # 开机自启 VBS 启动器
├── tests/               # 7 个测试文件 / 34 个用例
└── docs/superpowers/    # 设计文档与实现计划
```

## 安全说明（必读）

- ⚠️ **登录密码是唯一安全屏障**：代理背后是一个能执行任意命令的智能体，暴露即等同开放远程执行权限
- 仅建议在**可信局域网**使用；分发账号后建议删除 `credentials.txt`
- 流量经 TLS 加密，但证书为自签名（首次访问有浏览器提示）
- 停止暴露：结束代理进程 + 删除防火墙规则
  ```
  netsh advfirewall firewall delete rule name="DSH LAN Proxy 3081"
  ```
- 限速按真实来源 IP 计算，不信任 `X-Forwarded-For`

## License

Private / 内部使用。

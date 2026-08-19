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
      // Task 4 在此接入 forwardRequest
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
    try {
      if (!auth.hasValidSession(req)) {
        socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }
      forwardUpgrade(req, socket, head, config, log);
    } catch (err) {
      // 与 handleRequest 同级的保护：forwardUpgrade 内的同步抛错
      // （如 http.request 对非法配置抛 TypeError）不能变成 uncaughtException
      // 杀死整个代理进程。
      log(`upgrade error: ${err.stack || err.message}`);
      socket.destroy();
    }
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
      // https.Server 内部把 secureConnection -> http connectionListener 接好；
      // 我们手动发出 secureConnection 事件，跳过它自己的 listen()。
      // 注意：不把 key/cert 传给 https.createServer（它的握手路径不会被用到），
      // secureContext 只在嗅探到 TLS ClientHello 时懒创建 —— 明文 301 分支
      // 完全不触碰证书（测试传入 dummy 证书也能跑）。
      const tlsServer = https.createServer({}, handleRequest);
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
      let secureContext = null;
      listener = net.createServer((socket) => {
        socket.once('data', (chunk) => {
          socket.pause();
          socket.unshift(chunk);
          if (chunk.length > 0 && chunk[0] === 0x16) {
            // TLS ClientHello：包一层 TLSSocket，握手完成后交给 https 层。
            // 注意：这里不能对父 socket 调 resume() —— TLSSocket 已接管底层
            // handle（TLSWrap 成为流的所有者），initRead 会通过
            // _handle.receive() 把 unshift 回的 ClientHello 喂给 TLS 状态机；
            // 若此刻 resume()，父 socket 会对已被接管的 handle 再次 readStart，
            // 握手会卡死（实测 Node v24 必现）。
            try {
              if (!secureContext) {
                secureContext = tls.createSecureContext({ key: options.key, cert: options.cert });
              }
              const tlsSocket = new tls.TLSSocket(socket, { isServer: true, secureContext });
              tlsSocket.on('error', () => {});
              tlsSocket.on('secure', () => tlsServer.emit('secureConnection', tlsSocket));
            } catch (err) {
              log(`tls setup error: ${err.message}`);
              socket.destroy();
              return;
            }
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

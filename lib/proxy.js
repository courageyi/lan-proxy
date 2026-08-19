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

function forwardUpgrade(req, socket, head, config, logger) {
  const proxyReq = http.request({
    host: config.target.host,
    port: config.target.port,
    method: 'GET',
    path: req.url || '/',
    headers: rewriteHeaders(req.headers, config), // 保留 connection/upgrade/sec-websocket-*
  });
  // 统一拆除：任一端出错/结束/关闭即销毁双方连接。destroy() 幂等，重复触发无害；
  // proxyReq.destroy() 不触发 request 的 'error'。
  // 必须在发起请求之前就挂到客户端 socket 上：否则后端 101 到达前的窗口期内，
  // 客户端 RST 断开会触发 uncaughtException（read ECONNRESET）导致进程崩溃，
  // 并泄漏在途的后端连接。
  const teardown = () => { socket.destroy(); proxyReq.destroy(); };
  socket.on('error', teardown);
  socket.on('end', teardown);
  socket.on('close', teardown);
  proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
    const lines = ['HTTP/1.1 101 Switching Protocols'];
    // 用 rawHeaders 保留后端原始大小写（如 Sec-WebSocket-Accept），并天然支持多值头
    for (let i = 0; i < proxyRes.rawHeaders.length; i += 2) {
      lines.push(`${proxyRes.rawHeaders[i]}: ${proxyRes.rawHeaders[i + 1]}`);
    }
    socket.write(lines.join('\r\n') + '\r\n\r\n');
    if (proxyHead && proxyHead.length) socket.write(proxyHead);
    proxySocket.pipe(socket);
    socket.pipe(proxySocket);
    // 客户端 socket 的拆除监听已在发起请求前挂好，这里只需挂到 proxySocket：
    // 任一端断开后整体拆除隧道，避免后端连接半开泄漏导致 server.close() 挂起。
    proxySocket.on('error', teardown);
    proxySocket.on('end', teardown);
    proxySocket.on('close', teardown);
    logger(`upgrade ok: ${req.url}`);
  });
  proxyReq.on('response', (proxyRes) => {
    // 非 101：把后端响应原样转发给客户端，然后整体拆除。
    // 用 resetAndDestroy 发 RST 关闭后端连接：普通 destroy 只发 FIN，
    // 后端（http server 默认 allowHalfOpen）收到 FIN 后 socket 半开，
    // 会让 backend.server.close() 永远挂起。
    const lines = [`HTTP/1.1 ${proxyRes.statusCode} ${proxyRes.statusMessage || ''}`];
    for (let i = 0; i < proxyRes.rawHeaders.length; i += 2) {
      lines.push(`${proxyRes.rawHeaders[i]}: ${proxyRes.rawHeaders[i + 1]}`);
    }
    socket.write(lines.join('\r\n') + '\r\n\r\n');
    proxyRes.pipe(socket);
    proxyRes.on('end', () => {
      socket.destroy();
      const sock = proxyReq.socket;
      if (sock && typeof sock.resetAndDestroy === 'function') sock.resetAndDestroy();
      else proxyReq.destroy();
    });
  });
  proxyReq.on('error', (err) => {
    logger(`upgrade error: ${err.message} ${req.url}`);
    socket.destroy();
  });
  if (head && head.length) proxyReq.write(head);
  proxyReq.end();
}

module.exports = {
  authorityOf, rewriteHeaders, proxyRequestHeaders, cleanResponseHeaders,
  forwardRequest, forwardUpgrade,
};

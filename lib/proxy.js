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
  let proxyRes = null;
  const proxyReq = http.request({
    host: config.target.host,
    port: config.target.port,
    method: req.method,
    path: req.url || '/',
    headers: proxyRequestHeaders(req.headers, config),
  }, (proxyResponse) => {
    proxyRes = proxyResponse;
    // 后端流中途断开（后端/网络故障）：客户端连接一并拆除，避免悬挂。
    // destroy() 幂等，重复触发无害。
    proxyRes.on('aborted', () => {
      logger(`backend response aborted: ${req.method} ${req.url}`);
      if (!res.destroyed) res.destroy();
    });
    proxyRes.on('error', (err) => {
      logger(`backend response error: ${err.message} ${req.method} ${req.url}`);
      if (!res.destroyed) res.destroy();
    });
    if (res.destroyed) { proxyReq.destroy(); proxyRes.destroy(); return; } // 客户端已断开
    try {
      res.writeHead(proxyRes.statusCode, cleanResponseHeaders(proxyRes.headers));
      proxyRes.pipe(res);
      logger(`${req.method} ${req.url} -> ${proxyRes.statusCode}`);
    } catch (err) {
      logger(`proxy response error: ${err.message} ${req.method} ${req.url}`);
      proxyReq.destroy();
      proxyRes.destroy();
    }
  });
  proxyReq.on('error', (err) => {
    logger(`proxy error: ${err.message} ${req.method} ${req.url}`);
    if (res.destroyed) return; // 客户端已断开：无需也无法回 502
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('后端服务不可用（502）。');
    } else {
      res.destroy();
    }
  });
  // 客户端断开拆除：任一端关闭即销毁后端请求/响应，防连接半开泄漏
  // （destroy() 对已销毁对象是 no-op，handler 可安全重复触发）。
  // 注意：服务端 IncomingMessage 的 'close' 在请求体读完（正常完成）时也会触发，
  // 故用 req.complete 区分“正常读完”与“客户端中途断开”，否则会把在途的
  // proxyReq 误杀（后端响应未回就断开连接 → socket hang up）。
  req.on('aborted', () => proxyReq.destroy());
  req.on('close', () => { if (!req.complete) proxyReq.destroy(); });
  req.on('error', () => proxyReq.destroy()); // 客户端 RST 等连接错误同样视为断开
  res.on('close', () => {
    if (res.writableEnded) return; // 正常完成，无可清理
    proxyReq.destroy();
    if (proxyRes) proxyRes.destroy();
  });
  res.on('error', () => {
    proxyReq.destroy(); // 写向已断开客户端失败：后端流一并拆除
    if (proxyRes) proxyRes.destroy();
  });
  // 防御性超时：后端连接建立后 60s 无活动即整体拆除，防卡死的后端挂住所有请求
  proxyReq.setTimeout(60_000, () => {
    logger(`proxy timeout: ${req.method} ${req.url}`);
    proxyReq.destroy();
    if (proxyRes) proxyRes.destroy();
    if (!res.destroyed) res.destroy();
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
  // 统一拆除：任一端出错/结束/关闭即销毁双方连接。destroy() 幂等，重复触发无害。
  // 注意：'upgrade' 事件发出后 Node 即置 req.destroyed = true，此后 proxyReq.destroy()
  // 永久失效（no-op），所以 teardown 必须直接持有后端 socket（backendSocket），
  // 用 resetAndDestroy() 发 RST 彻底关闭；否则客户端断开后后端连接半开泄漏，
  // server.close() 永远挂起。proxyReq.destroy() 还可能在途请求上触发
  // 'socket hang up' 的 'error'，由下方 'error' 处理器接管记录，无害。
  // 必须在发起请求之前就挂到客户端 socket 上：否则后端 101 到达前的窗口期内，
  // 客户端 RST 断开会触发 uncaughtException（read ECONNRESET）导致进程崩溃，
  // 并泄漏在途的后端连接。
  let backendSocket = null;
  const teardown = () => {
    socket.destroy();
    const target = backendSocket || proxyReq.socket || proxyReq;
    if (target && typeof target.resetAndDestroy === 'function') target.resetAndDestroy();
    else if (target) target.destroy();
  };
  socket.on('error', teardown);
  socket.on('end', teardown);
  socket.on('close', teardown);
  proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
    backendSocket = proxySocket; // 先捕获：此后 teardown 直接以 RST 关闭后端连接
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

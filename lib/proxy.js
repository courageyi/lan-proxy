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
    // 任一端出错/结束/关闭即整体拆除隧道：
    // 客户端断开后若只靠 pipe 的 end->end()，后端连接会半开泄漏，
    // 导致后端 server.close() 与代理 server.close() 永远挂起。
    const teardown = () => { socket.destroy(); proxySocket.destroy(); };
    socket.on('error', teardown);
    proxySocket.on('error', teardown);
    socket.on('end', teardown);
    proxySocket.on('end', teardown);
    socket.on('close', teardown);
    proxySocket.on('close', teardown);
    logger(`upgrade ok: ${req.url}`);
  });
  proxyReq.on('response', () => {
    socket.destroy();
    proxyReq.destroy();
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

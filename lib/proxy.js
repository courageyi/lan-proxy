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

module.exports = {
  authorityOf, rewriteHeaders, proxyRequestHeaders, cleanResponseHeaders, forwardRequest,
};

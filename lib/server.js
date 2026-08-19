'use strict';

const http = require('node:http');
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
    if (!auth.hasValidSession(req)) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    forwardUpgrade(req, socket, head, config, log);
  }

  const handler = http.createServer(handleRequest);
  handler.on('upgrade', handleUpgrade);

  function listen() {
    return new Promise((resolve, reject) => {
      const listener = handler.listen(config.listenPort, '0.0.0.0', () => resolve(listener));
      listener.on('error', reject);
    });
  }

  function close() {
    return new Promise((resolve) => handler.close(() => resolve()));
  }

  return { listen, close, auth };
}

module.exports = { createProxy };

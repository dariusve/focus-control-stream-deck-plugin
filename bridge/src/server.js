'use strict';

const http = require('node:http');
const { URL } = require('node:url');
const { FocusriteAdapter } = require('./focusriteAdapter');

const PORT = Number(process.env.BRIDGE_PORT || 9123);
const HOST = process.env.BRIDGE_HOST || '127.0.0.1';
const SIMULATE = String(process.env.SIMULATE ?? 'true').toLowerCase() !== 'false';

const adapter = new FocusriteAdapter({ simulate: SIMULATE });

function getCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    ...getCorsHeaders(),
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function sendNoContent(res, statusCode = 204) {
  res.writeHead(statusCode, {
    ...getCorsHeaders(),
    'Content-Length': '0'
  });
  res.end();
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1_000_000) {
        reject(new Error('Request body too large'));
      }
    });
    req.on('end', () => {
      if (!data) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function routeNotFound(req, res) {
  sendJson(res, 404, {
    ok: false,
    error: 'Not Found',
    method: req.method,
    path: req.url
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || `${HOST}:${PORT}`}`);

  if (req.method === 'OPTIONS') {
    sendNoContent(res);
    return;
  }

  if (req.method === 'GET' && url.pathname === '/health') {
    sendJson(res, 200, {
      ok: true,
      service: 'focusrite-bridge',
      simulate: SIMULATE,
      timestamp: new Date().toISOString()
    });
    return;
  }

  if (req.method === 'POST' && url.pathname.startsWith('/api/v1/focusrite/air/')) {
    try {
      const body = await readBody(req);
      const channel = Number(body.channel || 1);

      let result;
      if (url.pathname.endsWith('/toggle')) {
        result = await adapter.toggleAir({ channel });
      } else if (url.pathname.endsWith('/status')) {
        result = await adapter.getAirStatus({ channel });
      } else if (url.pathname.endsWith('/mode')) {
        result = await adapter.setAirMode({ channel, mode: Number(body.mode || 0) });
      } else if (url.pathname.endsWith('/enable')) {
        result = await adapter.enableAir({ channel });
      } else if (url.pathname.endsWith('/disable')) {
        result = await adapter.disableAir({ channel });
      } else {
        routeNotFound(req, res);
        return;
      }

      sendJson(res, result.ok ? 200 : 501, result);
      return;
    } catch (error) {
      sendJson(res, 400, {
        ok: false,
        error: error.message
      });
      return;
    }
  }

  routeNotFound(req, res);
});

server.listen(PORT, HOST, () => {
  console.log(`[focusrite-bridge] Listening on http://${HOST}:${PORT}`);
  console.log(`[focusrite-bridge] Simulation mode: ${SIMULATE ? 'ON' : 'OFF'}`);
});

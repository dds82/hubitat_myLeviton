'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');

const LISTEN_PORT = parseInt(process.env.PORT || '8088', 10);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || 'my.leviton.com';
const LOG_DIR = process.env.LOG_DIR || '/logs';

fs.mkdirSync(LOG_DIR, { recursive: true });

let wsConnCounter = 0;
let httpReqCounter = 0;

// --- Redaction & Logging Helpers ---

function fingerprintSecret(value) {
  if (typeof value !== 'string' || value.length === 0) return '[REDACTED]';
  const hash = crypto.createHash('sha256').update(value).digest('hex').slice(0, 8);
  return `[REDACTED:sha256:${hash}:len=${value.length}]`;
}

function redactObject(obj) {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(redactObject);
  if (typeof obj !== 'object') return obj;

  const out = {};
  for (const [key, val] of Object.entries(obj)) {
    const lower = key.toLowerCase();
    if (lower === 'password' || lower === 'authorization') {
      out[key] = fingerprintSecret(String(val));
    } else if (lower === 'token' && typeof val === 'object' && val !== null) {
      out[key] = redactObject(val);
    } else if (lower === 'id' && typeof val === 'string' && val.length >= 32) {
      // Leviton session tokens are long strings stored in the "id" field of login/challenge objects
      out[key] = fingerprintSecret(val);
    } else {
      out[key] = redactObject(val);
    }
  }
  return out;
}

function redactHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const lower = k.toLowerCase();
    if (lower === 'authorization' || lower === 'cookie' || lower === 'set-cookie') {
      out[k] = Array.isArray(v) ? v.map(fingerprintSecret) : fingerprintSecret(String(v));
    } else {
      out[k] = v;
    }
  }
  return out;
}

function parseAndRedactBody(rawText) {
  if (!rawText) return null;
  try {
    const parsed = JSON.parse(rawText);
    return redactObject(parsed);
  } catch {
    if (rawText.includes('password=')) {
      const params = new URLSearchParams(rawText);
      if (params.has('password')) {
        params.set('password', fingerprintSecret(params.get('password')));
      }
      return params.toString();
    }
    return rawText.length > 2000 ? `${rawText.slice(0, 2000)}...[truncated]` : rawText;
  }
}

function logEvent(record) {
  const now = new Date();
  const entry = { ts: now.toISOString(), ...record };
  const line = JSON.stringify(entry);

  // Daily rotated JSONL file
  const dateStr = entry.ts.slice(0, 10);
  const logFile = path.join(LOG_DIR, `leviton-proxy-${dateStr}.jsonl`);
  fs.appendFile(logFile, line + '\n', (err) => {
    if (err) console.error('Failed to write log:', err.message);
  });

  // Compact console summary for `docker compose logs -f`
  const tag = entry.conn_id || entry.req_id || 'sys';
  const dir = entry.dir ? ` [${entry.dir}]` : '';
  const extra =
    entry.status !== undefined
      ? ` status=${entry.status}`
      : entry.code !== undefined
      ? ` code=${entry.code} reason="${entry.reason || ''}"`
      : '';
  console.log(`${entry.ts} ${tag} ${entry.event}${dir}${extra}`);
}

function isValidCloseCode(code) {
  return (
    typeof code === 'number' &&
    ((code >= 1000 && code <= 1003) ||
      (code >= 1007 && code <= 1014) ||
      (code >= 3000 && code <= 4999))
  );
}

// --- HTTP REST Proxy ---

const server = http.createServer((clientReq, clientRes) => {
  const reqId = `http-${++httpReqCounter}`;
  const startedAt = Date.now();
  const reqChunks = [];

  clientReq.on('data', (chunk) => reqChunks.push(chunk));
  clientReq.on('end', () => {
    const reqBodyBuf = Buffer.concat(reqChunks);
    const reqBodyStr = reqBodyBuf.toString('utf8');

    const forwardHeaders = { ...clientReq.headers, host: UPSTREAM_HOST };
    // Request uncompressed responses so the proxy can cleanly parse & redact JSON
    delete forwardHeaders['accept-encoding'];

    logEvent({
      req_id: reqId,
      event: 'http_req',
      dir: 'hubitat->leviton',
      method: clientReq.method,
      path: clientReq.url,
      headers: redactHeaders(clientReq.headers),
      body: parseAndRedactBody(reqBodyStr),
    });

    const upstreamReq = https.request(
      {
        hostname: UPSTREAM_HOST,
        port: 443,
        path: clientReq.url,
        method: clientReq.method,
        headers: forwardHeaders,
        timeout: 20000,
      },
      (upstreamRes) => {
        const resChunks = [];
        upstreamRes.on('data', (chunk) => resChunks.push(chunk));
        upstreamRes.on('end', () => {
          const resBodyBuf = Buffer.concat(resChunks);
          const resBodyStr = resBodyBuf.toString('utf8');
          const durationMs = Date.now() - startedAt;

          logEvent({
            req_id: reqId,
            event: 'http_res',
            dir: 'leviton->hubitat',
            method: clientReq.method,
            path: clientReq.url,
            status: upstreamRes.statusCode,
            duration_ms: durationMs,
            headers: redactHeaders(upstreamRes.headers),
            body: parseAndRedactBody(resBodyStr),
          });

          const replyHeaders = { ...upstreamRes.headers };
          delete replyHeaders['transfer-encoding'];
          replyHeaders['content-length'] = Buffer.byteLength(resBodyBuf);

          clientRes.writeHead(upstreamRes.statusCode || 502, replyHeaders);
          clientRes.end(resBodyBuf);
        });
      }
    );

    upstreamReq.on('timeout', () => {
      upstreamReq.destroy(new Error('Upstream HTTP request timed out after 20000ms'));
    });

    upstreamReq.on('error', (err) => {
      logEvent({
        req_id: reqId,
        event: 'http_error',
        dir: 'leviton->hubitat',
        method: clientReq.method,
        path: clientReq.url,
        duration_ms: Date.now() - startedAt,
        error: err.message,
        code: err.code || null,
      });
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'content-type': 'application/json' });
      }
      clientRes.end(JSON.stringify({ proxy_error: err.message }));
    });

    if (reqBodyBuf.length > 0) {
      upstreamReq.write(reqBodyBuf);
    }
    upstreamReq.end();
  });
});

// --- WebSocket Proxy (autoPong: false for transparent Ping/Pong logging) ---

const wss = new WebSocketServer({
  noServer: true,
  autoPong: false,
  perMessageDeflate: false,
});

server.on('upgrade', (req, socket, head) => {
  const connId = `ws-${++wsConnCounter}`;
  const connectedAt = Date.now();
  let lastActivityAt = connectedAt;
  let closed = false;

  const timing = () => {
    const now = Date.now();
    const res = { uptime_ms: now - connectedAt, idle_ms: now - lastActivityAt };
    lastActivityAt = now;
    return res;
  };

  logEvent({
    conn_id: connId,
    event: 'ws_upgrade_req',
    dir: 'hubitat->leviton',
    path: req.url,
    remote_addr: req.socket.remoteAddress,
    headers: redactHeaders(req.headers),
  });

  // Preserve non-hop-by-hop headers (e.g., Origin, User-Agent) from Hubitat
  const forwardHeaders = {};
  const skip = new Set([
    'host',
    'connection',
    'upgrade',
    'sec-websocket-key',
    'sec-websocket-version',
    'sec-websocket-extensions',
    'sec-websocket-protocol',
  ]);
  for (const [k, v] of Object.entries(req.headers)) {
    if (!skip.has(k.toLowerCase())) {
      forwardHeaders[k] = v;
    }
  }

  const upstreamUrl = `wss://${UPSTREAM_HOST}${req.url}`;

  wss.handleUpgrade(req, socket, head, (clientWs) => {
    const pendingToUpstream = [];

    const upstreamWs = new WebSocket(upstreamUrl, {
      headers: forwardHeaders,
      autoPong: false,
      perMessageDeflate: false,
      handshakeTimeout: 15000,
    });

    upstreamWs.on('upgrade', (res) => {
      logEvent({
        conn_id: connId,
        event: 'ws_upgrade_res',
        dir: 'leviton->hubitat',
        status: res.statusCode,
        headers: redactHeaders(res.headers),
        ...timing(),
      });
    });

    upstreamWs.on('unexpected-response', (_req, res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        logEvent({
          conn_id: connId,
          event: 'ws_unexpected_response',
          dir: 'leviton->hubitat',
          status: res.statusCode,
          headers: redactHeaders(res.headers),
          body: parseAndRedactBody(Buffer.concat(chunks).toString('utf8')),
          ...timing(),
        });
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.close(1011, `Upstream HTTP ${res.statusCode}`);
        }
      });
    });

    upstreamWs.on('open', () => {
      logEvent({
        conn_id: connId,
        event: 'ws_upstream_open',
        dir: 'leviton->hubitat',
        ...timing(),
      });
      while (pendingToUpstream.length > 0) {
        const fn = pendingToUpstream.shift();
        fn();
      }
    });

    const sendOrQueueUpstream = (fn) => {
      if (upstreamWs.readyState === WebSocket.OPEN) {
        fn();
      } else if (upstreamWs.readyState === WebSocket.CONNECTING) {
        pendingToUpstream.push(fn);
      }
    };

    // --- Hubitat -> Leviton frames ---

    clientWs.on('message', (data, isBinary) => {
      const text = isBinary ? data.toString('hex') : data.toString('utf8');
      logEvent({
        conn_id: connId,
        event: 'ws_message',
        dir: 'hubitat->leviton',
        binary: isBinary,
        bytes: data.length,
        payload: isBinary ? text : parseAndRedactBody(text),
        ...timing(),
      });
      sendOrQueueUpstream(() => upstreamWs.send(data, { binary: isBinary }));
    });

    clientWs.on('ping', (data) => {
      logEvent({
        conn_id: connId,
        event: 'ws_ping',
        dir: 'hubitat->leviton',
        payload_hex: data.toString('hex'),
        ...timing(),
      });
      sendOrQueueUpstream(() => upstreamWs.ping(data));
    });

    clientWs.on('pong', (data) => {
      logEvent({
        conn_id: connId,
        event: 'ws_pong',
        dir: 'hubitat->leviton',
        payload_hex: data.toString('hex'),
        ...timing(),
      });
      sendOrQueueUpstream(() => upstreamWs.pong(data));
    });

    clientWs.on('close', (code, reasonBuf) => {
      const reason = reasonBuf ? reasonBuf.toString('utf8') : '';
      const initiator = !closed;
      closed = true;
      logEvent({
        conn_id: connId,
        event: 'ws_close',
        dir: 'hubitat->leviton',
        initiator,
        code,
        reason,
        ...timing(),
      });
      if (upstreamWs.readyState === WebSocket.OPEN || upstreamWs.readyState === WebSocket.CONNECTING) {
        if (isValidCloseCode(code)) {
          upstreamWs.close(code, reason);
        } else {
          upstreamWs.terminate();
        }
      }
    });

    clientWs.on('error', (err) => {
      logEvent({
        conn_id: connId,
        event: 'ws_error',
        dir: 'hubitat->leviton',
        error: err.message,
        code: err.code || null,
        ...timing(),
      });
    });

    // --- Leviton -> Hubitat frames ---

    upstreamWs.on('message', (data, isBinary) => {
      const text = isBinary ? data.toString('hex') : data.toString('utf8');
      logEvent({
        conn_id: connId,
        event: 'ws_message',
        dir: 'leviton->hubitat',
        binary: isBinary,
        bytes: data.length,
        payload: isBinary ? text : parseAndRedactBody(text),
        ...timing(),
      });
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(data, { binary: isBinary });
      }
    });

    upstreamWs.on('ping', (data) => {
      logEvent({
        conn_id: connId,
        event: 'ws_ping',
        dir: 'leviton->hubitat',
        payload_hex: data.toString('hex'),
        ...timing(),
      });
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.ping(data);
      }
    });

    upstreamWs.on('pong', (data) => {
      logEvent({
        conn_id: connId,
        event: 'ws_pong',
        dir: 'leviton->hubitat',
        payload_hex: data.toString('hex'),
        ...timing(),
      });
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.pong(data);
      }
    });

    upstreamWs.on('close', (code, reasonBuf) => {
      const reason = reasonBuf ? reasonBuf.toString('utf8') : '';
      const initiator = !closed;
      closed = true;
      logEvent({
        conn_id: connId,
        event: 'ws_close',
        dir: 'leviton->hubitat',
        initiator,
        code,
        reason,
        ...timing(),
      });
      if (clientWs.readyState === WebSocket.OPEN) {
        if (isValidCloseCode(code)) {
          clientWs.close(code, reason);
        } else {
          clientWs.terminate();
        }
      }
    });

    upstreamWs.on('error', (err) => {
      logEvent({
        conn_id: connId,
        event: 'ws_error',
        dir: 'leviton->hubitat',
        error: err.message,
        code: err.code || null,
        ...timing(),
      });
    });
  });
});

server.listen(LISTEN_PORT, '0.0.0.0', () => {
  logEvent({
    event: 'proxy_started',
    listen_port: LISTEN_PORT,
    upstream_host: UPSTREAM_HOST,
    log_dir: LOG_DIR,
  });
});
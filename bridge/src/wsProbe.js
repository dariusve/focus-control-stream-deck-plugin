'use strict';

const url = process.env.FOCUSRITE_WS_URL || 'ws://127.0.0.1:58322';
const authMode = String(process.env.FOCUSRITE_WS_AUTH_MODE || 'none').toLowerCase();
const clientKey = process.env.FOCUSRITE_CLIENT_KEY || '';
const sendRaw = process.env.FOCUSRITE_WS_SEND_RAW || '';
const sendJson = process.env.FOCUSRITE_WS_SEND_JSON || '';
const sendHex = process.env.FOCUSRITE_WS_SEND_HEX || '';
const subscribeRaw = process.env.FOCUSRITE_WS_SUBSCRIBE_RAW || '';
const closeAfterMs = Number(process.env.FOCUSRITE_WS_CLOSE_AFTER_MS || 15000);

function toHex(buf) {
  return Buffer.from(buf).toString('hex');
}

function formatPreview(value) {
  const text = String(value);
  return text.length > 220 ? `${text.slice(0, 220)}...` : text;
}

function sendAuth(ws) {
  if (!clientKey || authMode === 'none') {
    return;
  }

  let payload = null;
  if (authMode === 'raw') {
    payload = clientKey;
  } else if (authMode === 'json') {
    payload = JSON.stringify({ clientKey });
  } else if (authMode === 'xml') {
    payload = `<client-details client-key="${clientKey}"/>`;
  }

  if (payload) {
    console.log(`[ws-probe] -> auth (${authMode}): ${formatPreview(payload)}`);
    ws.send(payload);
  }
}

function sendOptionalFrames(ws) {
  if (subscribeRaw) {
    console.log(`[ws-probe] -> subscribe raw: ${formatPreview(subscribeRaw)}`);
    ws.send(subscribeRaw);
  }

  if (sendRaw) {
    console.log(`[ws-probe] -> send raw: ${formatPreview(sendRaw)}`);
    ws.send(sendRaw);
  }

  if (sendJson) {
    let payload = null;
    try {
      payload = JSON.parse(sendJson);
    } catch (error) {
      console.error(`[ws-probe] invalid FOCUSRITE_WS_SEND_JSON: ${error.message}`);
      return;
    }
    console.log(`[ws-probe] -> send json: ${formatPreview(JSON.stringify(payload))}`);
    ws.send(JSON.stringify(payload));
  }

  if (sendHex) {
    const normalized = sendHex.replace(/[^0-9a-fA-F]/g, '');
    if (normalized.length === 0 || normalized.length % 2 !== 0) {
      console.error('[ws-probe] invalid FOCUSRITE_WS_SEND_HEX (must be even-length hex)');
      return;
    }
    const payload = Buffer.from(normalized, 'hex');
    console.log(`[ws-probe] -> send hex (${payload.length} bytes): ${normalized.slice(0, 220)}${normalized.length > 220 ? '...' : ''}`);
    ws.send(payload);
  }
}

async function main() {
  if (typeof WebSocket === 'undefined') {
    throw new Error('Global WebSocket is not available in this Node runtime.');
  }

  console.log(`[ws-probe] connecting to ${url}`);
  const ws = new WebSocket(url);

  ws.binaryType = 'arraybuffer';

  ws.onopen = () => {
    console.log('[ws-probe] connected');
    sendAuth(ws);
    sendOptionalFrames(ws);
  };

  ws.onmessage = (event) => {
    if (typeof event.data === 'string') {
      console.log(`[ws-probe] <- text: ${formatPreview(event.data)}`);
      return;
    }

    const hex = toHex(event.data);
    console.log(`[ws-probe] <- binary (${hex.length / 2} bytes): ${hex.slice(0, 320)}${hex.length > 320 ? '...' : ''}`);
  };

  ws.onerror = (event) => {
    console.error('[ws-probe] socket error', event?.message || '');
  };

  ws.onclose = (event) => {
    console.log(`[ws-probe] closed code=${event.code} reason=${event.reason || ''}`);
  };

  setTimeout(() => {
    if (ws.readyState === ws.OPEN) {
      console.log('[ws-probe] closing after timeout');
      ws.close(1000, 'probe complete');
    }
  }, closeAfterMs);
}

main().catch((error) => {
  console.error(`[ws-probe] failed: ${error.message}`);
  process.exit(1);
});

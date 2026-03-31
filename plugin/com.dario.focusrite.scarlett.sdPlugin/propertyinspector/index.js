'use strict';

let websocket = null;
let actionContext = null;
let actionUuid = null;
const VALID_COMMANDS = new Set(['toggle', 'enable', 'disable']);

const els = {
  bridgeHost: document.getElementById('bridgeHost'),
  bridgePort: document.getElementById('bridgePort'),
  command: document.getElementById('command'),
  channel: document.getElementById('channel')
};

function connectElgatoStreamDeckSocket(inPort, inUUID, inRegisterEvent, inInfo, inActionInfo) {
  const actionInfo = JSON.parse(inActionInfo);
  actionContext = actionInfo.context;
  actionUuid = actionInfo.action;

  websocket = new WebSocket(`ws://127.0.0.1:${inPort}`);
  websocket.onopen = () => {
    send({ event: inRegisterEvent, uuid: inUUID });
    send({
      action: actionUuid,
      event: 'getSettings',
      context: actionContext
    });
  };

  websocket.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.event === 'didReceiveSettings') {
      applySettings(msg.payload?.settings || {});
    }
  };

  Object.values(els).forEach((el) => {
    el.addEventListener('change', pushSettings);
  });
}

function applySettings(settings) {
  if (settings.bridgeHost) els.bridgeHost.value = settings.bridgeHost;
  if (settings.bridgePort) els.bridgePort.value = settings.bridgePort;
  if (settings.command) els.command.value = settings.command;
  if (settings.channel) els.channel.value = settings.channel;
}

function gatherSettings() {
  const host = els.bridgeHost.value.trim() || '127.0.0.1';
  const port = normalizePositiveInt(els.bridgePort.value, 9123);
  const command = normalizeCommand(els.command.value);
  const channel = normalizePositiveInt(els.channel.value, 1);

  els.bridgeHost.value = host;
  els.bridgePort.value = String(port);
  els.command.value = command;
  els.channel.value = String(channel);

  return {
    bridgeHost: host,
    bridgePort: port,
    command,
    channel
  };
}

function pushSettings() {
  const payload = gatherSettings();

  send({
    action: actionUuid,
    event: 'setSettings',
    context: actionContext,
    payload
  });

  send({
    action: actionUuid,
    event: 'sendToPlugin',
    context: actionContext,
    payload
  });
}

function send(payload) {
  if (websocket && websocket.readyState === 1) {
    websocket.send(JSON.stringify(payload));
  }
}

function normalizePositiveInt(value, fallback) {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) {
    return fallback;
  }
  return Math.floor(num);
}

function normalizeCommand(value) {
  const command = String(value || '').trim().toLowerCase();
  return VALID_COMMANDS.has(command) ? command : 'toggle';
}

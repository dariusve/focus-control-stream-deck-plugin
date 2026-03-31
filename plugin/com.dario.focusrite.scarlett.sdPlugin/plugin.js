'use strict';

var websocket = null;
var KEY_ACTION_UUID = 'com.dario.focusrite.scarlett.toggleair';
var DIAL_ACTION_UUID = 'com.dario.focusrite.scarlett.airdial';
var LOG_FILE_PATH = '/tmp/focusrite-streamdeck-plugin.log';
var WebSocketCtor = null;
var DEFAULT_SETTINGS = {
  bridgeHost: '127.0.0.1',
  bridgePort: 9123,
  command: 'toggle',
  channel: 1
};
var VALID_COMMANDS = ['toggle', 'enable', 'disable'];
var BRIDGE_TIMEOUT_MS = 8000;
var PENDING_STATE_WINDOW_MS = 2500;
var contexts = new Map();
var pendingStatusByKey = new Map();
var statusPollTimer = null;

function connectElgatoStreamDeckSocket(inPort, inPluginUUID, inRegisterEvent, inInfo, inActionInfo) {
  logInfo('connecting to Stream Deck websocket on port ' + inPort);
  websocket = newWebSocket('ws://127.0.0.1:' + inPort);

  websocket.onopen = function () {
    logInfo('websocket connected, registering plugin');
    send({
      event: inRegisterEvent,
      uuid: inPluginUUID
    });
  };

  websocket.onerror = function (event) {
    logError('websocket error ' + describeError(event));
  };

  websocket.onclose = function (event) {
    logWarn(
      'websocket closed code=' +
        (event && event.code) +
        ' reason=' +
        ((event && event.reason) || '')
    );
  };

  websocket.onmessage = function (event) {
    var msg = safeJsonParse(event && event.data);
    if (!msg || !msg.event) {
      return;
    }

    try {
      if (msg.event === 'willAppear') {
        var appearSettings = mergeSettings(getNested(msg, ['payload', 'settings']));
        logInfo(
          'willAppear action=' +
            msg.action +
            ' controller=' +
            (getNested(msg, ['payload', 'controller']) || 'n/a') +
            ' context=' +
            msg.context
        );
        setContextMeta(msg.context, {
          action: msg.action,
          controller: getNested(msg, ['payload', 'controller']) || null,
          settings: appearSettings
        });
        ensureStatusPolling();
        sendSettings(msg.context, appearSettings);
        refreshMatchingContexts(appearSettings);
        return;
      }

      if (msg.event === 'willDisappear') {
        contexts.delete(msg.context);
        ensureStatusPolling();
        return;
      }

      if (msg.event === 'didReceiveSettings') {
        var didSettings = mergeSettings(getNested(msg, ['payload', 'settings']));
        setContextMeta(msg.context, {
          action: msg.action,
          settings: didSettings
        });
        refreshMatchingContexts(didSettings);
        return;
      }

      if (msg.event === 'sendToPlugin') {
        var piSettings = mergeSettings(msg.payload || {});
        setContextMeta(msg.context, {
          action: msg.action,
          settings: piSettings
        });
        sendSettings(msg.context, piSettings);
        refreshMatchingContexts(piSettings);
        return;
      }

      if (msg.event === 'keyDown' && msg.action === KEY_ACTION_UUID) {
        handleKeyDown(msg).catch(function () {
          showAlert(msg.context);
        });
        return;
      }

      if (msg.event === 'dialDown' && msg.action === DIAL_ACTION_UUID) {
        handleDialCycle(msg).catch(function () {
          showAlert(msg.context);
        });
        return;
      }

      if (msg.event === 'dialRotate' && msg.action === DIAL_ACTION_UUID) {
        handleDialRotate(msg).catch(function () {
          showAlert(msg.context);
        });
        return;
      }

      if (msg.event === 'touchTap' && msg.action === DIAL_ACTION_UUID) {
        refreshAirState(msg.context, getContextSettings(msg.context, getNested(msg, ['payload', 'settings'])));
        return;
      }
    } catch (error) {
      showAlert(msg.context);
    }
  };
}

async function handleKeyDown(msg) {
  var settings = getContextSettings(msg.context, getNested(msg, ['payload', 'settings']));
  setContextMeta(msg.context, {
    action: msg.action,
    settings: settings
  });
  var predictedMode = getNextCycledMode(settings);
  applyPredictedState(settings, predictedMode);
  logInfo(
    'keyDown context=' +
      msg.context +
      ' channel=' +
      settings.channel +
      ' command=' +
      settings.command
  );

  try {
    var result = await callBridge(settings);
    if (result && result.ok) {
      clearPendingState(settings);
      logInfo(
        'keyDown result context=' +
          msg.context +
          ' mode=' +
          normalizeAirMode(result) +
          ' enabled=' +
          String(result.airEnabled)
      );
      applyAirState(msg.context, result);
      refreshMatchingContexts(settings);
      showOk(msg.context);
    } else {
      clearPendingState(settings);
      logError('bridge returned non-ok result ' + describeError(result));
      setTitle(msg.context, deriveErrorTitle(result && (result.error || result.message)));
      showAlert(msg.context);
    }
  } catch (error) {
    clearPendingState(settings);
    logError('keyDown failed ' + describeError(error));
    setTitle(msg.context, deriveErrorTitle(error));
    showAlert(msg.context);
  }
}

async function handleDialCycle(msg) {
  var settings = getContextSettings(msg.context, getNested(msg, ['payload', 'settings']));
  setContextMeta(msg.context, {
    action: msg.action,
    settings: settings
  });
  var status = await callBridgeStatus(settings);
  var nextMode = normalizeAirMode(status) >= 2 ? 0 : normalizeAirMode(status) + 1;
  applyPredictedState(settings, nextMode);
  logInfo(
    'dialDown context=' +
      msg.context +
      ' channel=' +
      settings.channel +
      ' current=' +
      normalizeAirMode(status) +
      ' next=' +
      nextMode
  );
  var result = await callBridgeMode(settings, nextMode);
  if (result && result.ok) {
    clearPendingState(settings);
    logInfo(
      'dialDown result context=' +
        msg.context +
        ' mode=' +
        normalizeAirMode(result) +
        ' enabled=' +
        String(result.airEnabled)
    );
    applyAirState(msg.context, result);
    refreshMatchingContexts(settings);
    showOk(msg.context);
    return;
  }
  clearPendingState(settings);
  throw new Error(result && (result.error || result.message) || 'Dial cycle failed');
}

async function handleDialRotate(msg) {
  var settings = getContextSettings(msg.context, getNested(msg, ['payload', 'settings']));
  setContextMeta(msg.context, {
    action: msg.action,
    settings: settings
  });
  var status = await callBridgeStatus(settings);
  var currentMode = normalizeAirMode(status);
  var ticks = Number(getNested(msg, ['payload', 'ticks']) || 0);
  if (!ticks) {
    applyAirState(msg.context, status);
    return;
  }
  var nextMode = (currentMode + (ticks > 0 ? 1 : -1) + 3) % 3;
  applyPredictedState(settings, nextMode);
  logInfo(
    'dialRotate context=' +
      msg.context +
      ' channel=' +
      settings.channel +
      ' ticks=' +
      ticks +
      ' current=' +
      currentMode +
      ' next=' +
      nextMode
  );
  var result = await callBridgeMode(settings, nextMode);
  if (result && result.ok) {
    clearPendingState(settings);
    logInfo(
      'dialRotate result context=' +
        msg.context +
        ' mode=' +
        normalizeAirMode(result) +
        ' enabled=' +
        String(result.airEnabled)
    );
    applyAirState(msg.context, result);
    refreshMatchingContexts(settings);
    showOk(msg.context);
    return;
  }
  clearPendingState(settings);
  throw new Error(result && (result.error || result.message) || 'Dial rotation failed');
}

async function refreshAirState(context, settings) {
  try {
    var result = await callBridgeStatus(settings);
    if (result && result.ok) {
      if (shouldHoldPendingState(settings, result)) {
        return;
      }
      applyAirState(context, result);
    } else {
      setTitle(context, 'AIR');
    }
  } catch (error) {
    logWarn('refreshAirState failed ' + describeError(error));
    setTitle(context, 'AIR');
  }
}

function applyAirState(context, result) {
  updateContextStatus(context, result);
  var meta = contexts.get(context) || {};
  if (meta.action === DIAL_ACTION_UUID || meta.controller === 'Encoder') {
    setFeedback(context, {
      title: 'AIR',
      value: formatAirValue(result)
    });
    setTriggerDescription(context, {
      push: 'Cycle AIR',
      rotate: 'Adjust AIR',
      touch: 'Refresh AIR'
    });
    return;
  }

  setTitle(context, formatAirTitle(result));
}

function applyPredictedState(settings, mode) {
  var predicted = buildAirResult(mode);
  setPendingState(settings, predicted);
  var targets = getMatchingContexts(settings);
  for (var i = 0; i < targets.length; i += 1) {
    applyAirState(targets[i], predicted);
  }
}

async function refreshMatchingContexts(settings) {
  var targets = getMatchingContexts(settings);
  if (targets.length === 0) {
    return;
  }

  try {
    var result = await callBridgeStatus(settings);
    if (!result || !result.ok) {
      return;
    }
    if (shouldHoldPendingState(settings, result)) {
      return;
    }
    for (var i = 0; i < targets.length; i += 1) {
      applyAirState(targets[i], result);
    }
  } catch (error) {
    logWarn('refreshMatchingContexts failed ' + describeError(error));
  }
}

function formatAirTitle(result) {
  var mode = Number(result && result.airMode);
  if (Number.isFinite(mode)) {
    if (mode <= 0) {
      return 'AIR OFF';
    }
    if (mode === 1) {
      return 'PRES';
    }
    return 'P+D';
  }
  return result && result.airEnabled ? 'PRES' : 'AIR OFF';
}

function formatAirValue(result) {
  var mode = Number(result && result.airMode);
  if (!Number.isFinite(mode) || mode <= 0) {
    return 'OFF';
  }
  if (mode === 1) {
    return 'PRES';
  }
  return 'P+D';
}

function mergeSettings(input) {
  var source = input || {};
  return {
    bridgeHost: normalizeBridgeHost(source.bridgeHost),
    bridgePort: normalizePositiveInt(source.bridgePort, DEFAULT_SETTINGS.bridgePort),
    command: normalizeCommand(source.command),
    channel: normalizePositiveInt(source.channel, DEFAULT_SETTINGS.channel)
  };
}

function sendSettings(context, settings) {
  send({
    action: getContextAction(context),
    event: 'setSettings',
    context: context,
    payload: settings
  });
}

function setTitle(context, title) {
  send({
    event: 'setTitle',
    context: context,
    payload: {
      title: title,
      target: 0
    }
  });
}

function showOk(context) {
  send({
    event: 'showOk',
    context: context
  });
}

function showAlert(context) {
  send({
    event: 'showAlert',
    context: context
  });
}

async function callBridge(settings) {
  return callBridgeAction(settings, settings.command);
}

async function callBridgeStatus(settings) {
  return callBridgeAction(settings, 'status');
}

async function callBridgeMode(settings, mode) {
  return callBridgeAction(settings, 'mode', { mode: mode });
}

async function callBridgeAction(settings, action, extraPayload) {
  var endpoint = '/api/v1/focusrite/air/' + action;
  var url = 'http://' + settings.bridgeHost + ':' + settings.bridgePort + endpoint;
  var payload = Object.assign({ channel: settings.channel }, extraPayload || {});
  var attempts = buildBridgeAttempts(url, payload);
  var failures = [];

  for (var i = 0; i < attempts.length; i += 1) {
    var attempt = attempts[i];
    try {
      return await attempt.run();
    } catch (error) {
      var reason = '[' + attempt.name + '] ' + describeError(error);
      failures.push(reason);
      logWarn('bridge transport failed ' + reason);
    }
  }

  throw new Error(
    failures.length > 0
      ? failures.join(' | ')
      : 'No supported HTTP transport is available in this Stream Deck runtime.'
  );
}

async function callBridgeViaFetch(url, payload) {
  var requestBody = JSON.stringify(payload);
  var timeoutId = null;
  var options = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: requestBody
  };

  if (typeof AbortController !== 'undefined') {
    var controller = new AbortController();
    options.signal = controller.signal;
    timeoutId = setTimeout(function () {
      controller.abort();
    }, BRIDGE_TIMEOUT_MS);
  }

  try {
    var res = await fetch(url, options);
    var raw = await res.text();

    if (!res.ok) {
      throw new Error(formatBridgeError(res.status, raw));
    }

    return safeJsonParse(raw) || { ok: true, airEnabled: false };
  } catch (error) {
    if (error && error.name === 'AbortError') {
      throw new Error('Bridge timeout');
    }
    throw error;
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  }
}

function canUseNodeTransport() {
  return typeof require === 'function';
}

function buildBridgeAttempts(url, payload) {
  var attempts = [];

  if (canUseNodeTransport()) {
    attempts.push({
      name: 'node-http',
      run: function () {
        return callBridgeViaNodeHttp(url, payload);
      }
    });
  }

  if (typeof XMLHttpRequest !== 'undefined') {
    attempts.push({
      name: 'xhr',
      run: function () {
        return callBridgeViaXhr(url, payload);
      }
    });
  }

  if (typeof fetch === 'function') {
    attempts.push({
      name: 'fetch',
      run: function () {
        return callBridgeViaFetch(url, payload);
      }
    });
  }

  return attempts;
}

function callBridgeViaXhr(url, payload) {
  var requestBody = JSON.stringify(payload);
  return new Promise(function (resolve, reject) {
    try {
      var req = new XMLHttpRequest();
      req.open('POST', url, true);
      req.setRequestHeader('Content-Type', 'application/json');
      req.timeout = BRIDGE_TIMEOUT_MS;

      req.onreadystatechange = function () {
        if (req.readyState !== 4) {
          return;
        }

        if (req.status >= 200 && req.status < 300) {
          var parsed = safeJsonParse(req.responseText);
          resolve(parsed || { ok: true, airEnabled: false });
        } else {
          reject(new Error(formatBridgeError(req.status, req.responseText)));
        }
      };

      req.ontimeout = function () {
        reject(new Error('Bridge timeout'));
      };
      req.onerror = function () {
        reject(new Error('Bridge unavailable'));
      };
      req.send(requestBody);
    } catch (error) {
      reject(error);
    }
  });
}

function callBridgeViaNodeHttp(url, payload) {
  var requestBody = JSON.stringify(payload);
  var URLCtor = typeof URL !== 'undefined' ? URL : require('url').URL;
  var parsed = new URLCtor(url);
  var isHttps = parsed.protocol === 'https:';
  var transport = loadNodeTransport(isHttps ? 'https' : 'http');
  var port = parsed.port ? Number(parsed.port) : (isHttps ? 443 : 80);
  var headers = { 'Content-Type': 'application/json' };
  if (typeof Buffer !== 'undefined') {
    headers['Content-Length'] = Buffer.byteLength(requestBody);
  }

  return new Promise(function (resolve, reject) {
    var req = transport.request(
      {
        hostname: parsed.hostname,
        port: port,
        path: parsed.pathname + parsed.search,
        method: 'POST',
        headers: headers,
        timeout: BRIDGE_TIMEOUT_MS
      },
      function (res) {
        var raw = '';
        res.on('data', function (chunk) {
          raw += chunk;
        });
        res.on('end', function () {
          var code = Number(res.statusCode || 0);
          if (code < 200 || code >= 300) {
            reject(new Error(formatBridgeError(code, raw)));
            return;
          }
          var parsedBody = safeJsonParse(raw);
          resolve(parsedBody || { ok: true, airEnabled: false });
        });
      }
    );

    req.on('timeout', function () {
      req.destroy(new Error('Bridge timeout'));
    });
    req.on('error', reject);
    req.write(requestBody);
    req.end();
  });
}

function loadNodeTransport(protocol) {
  try {
    return require('node:' + protocol);
  } catch (_) {
    return require(protocol);
  }
}

function normalizeBridgeHost(value) {
  var host = String(value || '').trim();
  return host || DEFAULT_SETTINGS.bridgeHost;
}

function normalizePositiveInt(value, fallback) {
  var num = Number(value);
  if (!Number.isFinite(num) || num <= 0) {
    return fallback;
  }
  return Math.floor(num);
}

function normalizeCommand(value) {
  var command = String(value || '').trim().toLowerCase();
  return VALID_COMMANDS.indexOf(command) >= 0 ? command : DEFAULT_SETTINGS.command;
}

function formatBridgeError(statusCode, rawBody) {
  var parsed = safeJsonParse(rawBody);
  var suffix = '';
  if (parsed && parsed.error) {
    suffix = ': ' + parsed.error;
  } else {
    var text = String(rawBody || '').trim();
    if (text) {
      suffix = ': ' + text.slice(0, 200);
    }
  }
  return 'Bridge error ' + statusCode + suffix;
}

function normalizeAirMode(result) {
  var mode = Number(result && result.airMode);
  if (!Number.isFinite(mode) || mode <= 0) {
    return 0;
  }
  return mode === 2 ? 2 : 1;
}

function buildAirResult(mode) {
  var normalizedMode = mode === 2 ? 2 : mode > 0 ? 1 : 0;
  return {
    ok: true,
    airEnabled: normalizedMode > 0,
    airMode: normalizedMode
  };
}

function getNextCycledMode(settings) {
  var current = getSharedKnownMode(settings);
  return current >= 2 ? 0 : current + 1;
}

function getSharedKnownMode(settings) {
  var targets = getMatchingContexts(settings);
  for (var i = 0; i < targets.length; i += 1) {
    var meta = contexts.get(targets[i]);
    if (meta && meta.result) {
      return normalizeAirMode(meta.result);
    }
  }
  return 0;
}

function getContextAction(context) {
  var meta = contexts.get(context);
  return meta && meta.action ? meta.action : KEY_ACTION_UUID;
}

function getMatchingContexts(settings) {
  var target = mergeSettings(settings);
  var matches = [];
  contexts.forEach(function (meta, context) {
    var candidate = mergeSettings(meta && meta.settings);
    if (
      candidate.bridgeHost === target.bridgeHost &&
      candidate.bridgePort === target.bridgePort &&
      candidate.channel === target.channel
    ) {
      matches.push(context);
    }
  });
  return matches;
}

function makeSettingsKey(settings) {
  var normalized = mergeSettings(settings);
  return normalized.bridgeHost + ':' + normalized.bridgePort + ':' + normalized.channel;
}

function setPendingState(settings, result) {
  pendingStatusByKey.set(makeSettingsKey(settings), {
    result: result,
    expiresAt: Date.now() + PENDING_STATE_WINDOW_MS
  });
}

function clearPendingState(settings) {
  pendingStatusByKey.delete(makeSettingsKey(settings));
}

function getPendingState(settings) {
  var key = makeSettingsKey(settings);
  var pending = pendingStatusByKey.get(key);
  if (!pending) {
    return null;
  }
  if (pending.expiresAt <= Date.now()) {
    pendingStatusByKey.delete(key);
    return null;
  }
  return pending;
}

function shouldHoldPendingState(settings, result) {
  var pending = getPendingState(settings);
  if (!pending) {
    return false;
  }
  if (normalizeAirMode(result) === normalizeAirMode(pending.result)) {
    clearPendingState(settings);
    return false;
  }
  return true;
}

function getContextSettings(context, fallback) {
  var meta = contexts.get(context);
  return mergeSettings(fallback || (meta && meta.settings));
}

function setContextMeta(context, nextMeta) {
  var current = contexts.get(context) || {};
  contexts.set(context, {
    action: nextMeta.action || current.action || KEY_ACTION_UUID,
    controller: nextMeta.controller || current.controller || null,
    settings: nextMeta.settings ? mergeSettings(nextMeta.settings) : current.settings || mergeSettings(),
    result: nextMeta.result || current.result || null
  });
}

function updateContextStatus(context, result) {
  var current = contexts.get(context) || {};
  contexts.set(context, {
    action: current.action || KEY_ACTION_UUID,
    controller: current.controller || null,
    settings: current.settings || mergeSettings(),
    result: result || null
  });
}

function ensureStatusPolling() {
  if (statusPollTimer) {
    clearInterval(statusPollTimer);
    statusPollTimer = null;
  }

  if (contexts.size === 0) {
    return;
  }

  statusPollTimer = setInterval(function () {
    var uniqueByKey = new Map();
    contexts.forEach(function (meta) {
      var settings = mergeSettings(meta && meta.settings);
      var key = settings.bridgeHost + ':' + settings.bridgePort + ':' + settings.channel;
      if (!uniqueByKey.has(key)) {
        uniqueByKey.set(key, settings);
      }
    });

    uniqueByKey.forEach(function (settings) {
      refreshMatchingContexts(settings);
    });
  }, 1000);
}

function describeError(error) {
  if (!error) {
    return 'Unknown error';
  }
  if (typeof error === 'string') {
    return error;
  }
  if (error.stack) {
    return error.stack;
  }
  if (error.message) {
    return error.message;
  }
  try {
    return JSON.stringify(error);
  } catch (_) {
    // Fall through.
  }
  return String(error);
}

function deriveErrorTitle(error) {
  var text = String(describeError(error) || '').toUpperCase();
  if (text.indexOf('TIMEOUT') >= 0) {
    return 'TIMEOUT';
  }
  if (text.indexOf('UNAVAILABLE') >= 0 || text.indexOf('ECONNREFUSED') >= 0) {
    return 'NO BRG';
  }
  if (text.indexOf('404') >= 0) {
    return '404';
  }
  if (text.indexOf('400') >= 0) {
    return '400';
  }
  if (text.indexOf('501') >= 0) {
    return '501';
  }
  return 'ERR';
}

function safeJsonParse(value) {
  if (typeof value !== 'string') {
    return null;
  }
  try {
    return JSON.parse(value);
  } catch (_) {
    return null;
  }
}

function getNested(obj, path) {
  var current = obj;
  for (var i = 0; i < path.length; i += 1) {
    if (!current || typeof current !== 'object' || !(path[i] in current)) {
      return null;
    }
    current = current[path[i]];
  }
  return current;
}

function send(json) {
  if (websocket && websocket.readyState === 1) {
    websocket.send(JSON.stringify(json));
  }
}

function setFeedback(context, payload) {
  send({
    event: 'setFeedback',
    context: context,
    payload: payload
  });
}

function setTriggerDescription(context, payload) {
  send({
    event: 'setTriggerDescription',
    context: context,
    payload: payload
  });
}

function getArgValue(name) {
  if (typeof process === 'undefined' || !process || !Array.isArray(process.argv)) {
    return '';
  }

  for (var i = 0; i < process.argv.length - 1; i += 1) {
    if (process.argv[i] === name) {
      return process.argv[i + 1] || '';
    }
  }

  return '';
}

function bootstrapFromProcessArgs() {
  var port = getArgValue('-port');
  var pluginUUID = getArgValue('-pluginUUID');
  var registerEvent = getArgValue('-registerEvent');
  var info = getArgValue('-info');
  var actionInfo = getArgValue('-actionInfo');

  if (!port || !pluginUUID || !registerEvent) {
    logWarn('missing startup args; waiting for legacy callback');
    return;
  }

  logInfo('bootstrapping from process args');
  connectElgatoStreamDeckSocket(port, pluginUUID, registerEvent, info, actionInfo);
}

function appendLogLine(level, message) {
  var line = new Date().toISOString() + ' [' + level + '] ' + message + '\n';
  if (typeof console !== 'undefined' && console && typeof console.log === 'function') {
    console.log('[focusrite-plugin]', '[' + level + ']', message);
  }
  if (typeof require !== 'function') {
    return;
  }
  try {
    var fs = require('node:fs');
    fs.appendFileSync(LOG_FILE_PATH, line, 'utf8');
  } catch (_) {
    // Best-effort logging only.
  }
}

function resolveWebSocketCtor() {
  if (WebSocketCtor) {
    return WebSocketCtor;
  }

  if (typeof require === 'function') {
    try {
      var wsModule = require('ws');
      if (typeof wsModule === 'function') {
        WebSocketCtor = wsModule;
        logInfo('using ws fallback');
        return WebSocketCtor;
      }
      if (wsModule && typeof wsModule.WebSocket === 'function') {
        WebSocketCtor = wsModule.WebSocket;
        logInfo('using ws.WebSocket fallback');
        return WebSocketCtor;
      }
    } catch (error) {
      logWarn('ws module unavailable: ' + describeError(error));
    }

    try {
      var undici = require('undici');
      if (undici && typeof undici.WebSocket === 'function') {
        WebSocketCtor = undici.WebSocket;
        logInfo('using undici.WebSocket fallback');
        return WebSocketCtor;
      }
    } catch (error) {
      logWarn('undici.WebSocket unavailable: ' + describeError(error));
    }
  }

  if (typeof WebSocket === 'function') {
    WebSocketCtor = WebSocket;
    logInfo('using global WebSocket');
    return WebSocketCtor;
  }

  throw new Error('No WebSocket client is available in this Stream Deck runtime.');
}

function newWebSocket(url) {
  var Ctor = resolveWebSocketCtor();
  return new Ctor(url);
}

function logInfo(message) {
  appendLogLine('INFO', message);
}

function logWarn(message) {
  appendLogLine('WARN', message);
}

function logError(message) {
  appendLogLine('ERROR', message);
}

if (typeof process !== 'undefined' && process && typeof process.on === 'function') {
  process.on('uncaughtException', function (error) {
    logError('uncaughtException ' + describeError(error));
  });
  process.on('unhandledRejection', function (error) {
    logError('unhandledRejection ' + describeError(error));
  });
}

bootstrapFromProcessArgs();

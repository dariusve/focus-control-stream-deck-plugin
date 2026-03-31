'use strict';

const crypto = require('node:crypto');
const dgram = require('node:dgram');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const sodium = require('libsodium-wrappers');
const {
  KEEPALIVE_PACKET_HEX,
  SOLO4TH_GEN_BOOTSTRAP_HEX
} = require('./secureBootstrap');

const DISCOVERY_PORTS = [30096, 30097, 30098];
const DISCOVERY_PAYLOAD = '<client-discovery app="SAFFIRE-CONTROL" version="4"/>';
const KEEP_ALIVE_PAYLOAD = '<keep-alive/>';
const DEFAULT_CANDIDATE_PORTS = [50000, 5000, 7000, 58322, 58323];
const DEFAULT_SECURE_AIR_ITEMS = new Map([[1, { airOnItemId: 0x1023, airModeItemId: 0x1024 }]]);
const TRANSPORT_MODES = new Set(['auto', 'secure', 'legacy']);
const SECURE_BOOTSTRAP_MODES = new Set(['none', 'known']);
const SECURE_AIR_MODE_WRITE_ENCODINGS = new Set(['little', 'big']);
const DEFAULT_SECURE_RECORD_PLAINTEXT_BYTES = 1283;

function parseAirItemIds(raw) {
  const map = new Map([[1, 23]]);
  if (!raw) {
    return map;
  }

  // Format: "1:23,2:24"
  raw.split(',').forEach((pair) => {
    const [ch, id] = pair.split(':').map((value) => Number(value.trim()));
    if (Number.isFinite(ch) && Number.isFinite(id) && ch > 0 && id > 0) {
      map.set(ch, id);
    }
  });

  return map;
}

function parseFlexibleInt(value) {
  const raw = String(value || '').trim();
  if (!raw) {
    return NaN;
  }
  if (raw.startsWith('0x') || raw.startsWith('0X')) {
    return Number.parseInt(raw.slice(2), 16);
  }
  return Number.parseInt(raw, 10);
}

function parseSecureAirItemIds(raw) {
  const map = new Map(DEFAULT_SECURE_AIR_ITEMS);
  if (!raw) {
    return map;
  }

  // Format: "1:0x1023:0x1024,2:0x2023:0x2024"
  raw.split(',').forEach((entry) => {
    const [channelRaw, onRaw, modeRaw] = String(entry)
      .split(':')
      .map((part) => String(part).trim());

    const channel = parseFlexibleInt(channelRaw);
    const airOnItemId = parseFlexibleInt(onRaw);
    const airModeItemId = parseFlexibleInt(modeRaw);
    if (
      Number.isFinite(channel) &&
      Number.isFinite(airOnItemId) &&
      Number.isFinite(airModeItemId) &&
      channel > 0 &&
      airOnItemId > 0 &&
      airModeItemId > 0
    ) {
      map.set(channel, { airOnItemId, airModeItemId });
    }
  });

  return map;
}

function encodePacket(xml) {
  return `Length=${xml.length.toString(16).padStart(6, '0')} ${xml}`;
}

function parsePortList(raw, defaults = []) {
  if (!raw) {
    return [...defaults];
  }

  const ports = raw
    .split(',')
    .map((p) => Number(String(p).trim()))
    .filter((p) => Number.isFinite(p) && p > 0 && p <= 65535);

  return ports.length > 0 ? ports : [...defaults];
}

function normalizeHex32(raw) {
  const value = String(raw || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  return value.length === 64 ? value : '';
}

function parseXmlAttr(xml, regex) {
  const match = xml.match(regex);
  return match ? match[1] : '';
}

function readControl2Settings(settingsPathOverride) {
  const candidatePath =
    settingsPathOverride ||
    path.join(
      process.env.HOME || '',
      'Library',
      'Application Support',
      'Focusrite',
      'Focusrite Control 2',
      'settings.xml'
    );

  if (!candidatePath || !fs.existsSync(candidatePath)) {
    return {
      settingsPath: candidatePath,
      remoteConnectionKey: '',
      remoteClientPublicKey: '',
      securePort: 58322,
      insecurePort: 58323
    };
  }

  try {
    const xml = fs.readFileSync(candidatePath, 'utf8');
    return {
      settingsPath: candidatePath,
      remoteConnectionKey: normalizeHex32(
        parseXmlAttr(xml, /<RemoteConnection\s+key="([0-9a-fA-F]{64})"/)
      ),
      remoteClientPublicKey: normalizeHex32(
        parseXmlAttr(xml, /<RemoteClient\s+publicKey="([0-9a-fA-F]{64})"/)
      ),
      securePort: 58322,
      insecurePort: 58323
    };
  } catch {
    return {
      settingsPath: candidatePath,
      remoteConnectionKey: '',
      remoteClientPublicKey: '',
      securePort: 58322,
      insecurePort: 58323
    };
  }
}

function ensureTimeout(promise, timeoutMs, message) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(message));
    }, timeoutMs);

    promise
      .then((result) => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch((error) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}

class FocusriteAdapter {
  constructor(options = {}) {
    this.simulate = options.simulate ?? true;
    this.transportMode = String(
      options.transportMode || process.env.FOCUSRITE_TRANSPORT || 'auto'
    ).toLowerCase();
    if (!TRANSPORT_MODES.has(this.transportMode)) {
      this.transportMode = 'auto';
    }

    // Legacy transport settings (Focusrite ControlServer XML over TCP)
    this.deviceId = String(options.deviceId || process.env.FOCUSRITE_DEVICE_ID || '1');
    this.clientKey = String(
      options.clientKey || process.env.FOCUSRITE_CLIENT_KEY || crypto.randomUUID()
    );
    this.serverHost = options.serverHost || process.env.FOCUSRITE_SERVER_HOST || '127.0.0.1';
    this.discoveryHost =
      options.discoveryHost || process.env.FOCUSRITE_DISCOVERY_HOST || '255.255.255.255';
    this.discoveryTimeoutMs = Number(
      options.discoveryTimeoutMs || process.env.FOCUSRITE_DISCOVERY_TIMEOUT_MS || 5000
    );
    this.discoveryIntervalMs = Number(
      options.discoveryIntervalMs || process.env.FOCUSRITE_DISCOVERY_INTERVAL_MS || 700
    );
    this.forcedServerPort = Number(options.serverPort || process.env.FOCUSRITE_SERVER_PORT || 0);
    this.serverPortCandidates = parsePortList(
      options.serverPortCandidates || process.env.FOCUSRITE_SERVER_PORT_CANDIDATES,
      DEFAULT_CANDIDATE_PORTS
    );
    this.connectTimeoutMs = Number(
      options.connectTimeoutMs || process.env.FOCUSRITE_CONNECT_TIMEOUT_MS || 1200
    );
    this.probeTimeoutMs = Number(
      options.probeTimeoutMs || process.env.FOCUSRITE_PROBE_TIMEOUT_MS || 1200
    );
    if (options.airItemIds instanceof Map) {
      this.airItemIds = new Map(options.airItemIds);
    } else {
      this.airItemIds = parseAirItemIds(options.airItemIds || process.env.FOCUSRITE_AIR_ITEM_IDS);
    }

    // Secure transport settings (Focusrite Control 2 AES70 secure websocket)
    const control2Settings = readControl2Settings(options.settingsPath);
    this.control2SettingsPath = control2Settings.settingsPath;
    this.remoteConnectionKeyHex = normalizeHex32(
      options.remoteConnectionKey ||
        process.env.FOCUSRITE_REMOTE_KEY ||
        control2Settings.remoteConnectionKey
    );
    this.remoteClientPublicKeyHex = normalizeHex32(
      options.remoteClientPublicKey ||
        process.env.FOCUSRITE_REMOTE_CLIENT_PUBLIC_KEY ||
        control2Settings.remoteClientPublicKey
    );
    this.secureWsHost =
      options.secureWsHost || process.env.FOCUSRITE_SECURE_WS_HOST || '127.0.0.1';
    this.secureWsPort = Number(
      options.secureWsPort ||
        process.env.FOCUSRITE_SECURE_WS_PORT ||
        control2Settings.securePort ||
        58322
    );
    this.secureHandshakeTimeoutMs = Number(
      options.secureHandshakeTimeoutMs ||
        process.env.FOCUSRITE_SECURE_HANDSHAKE_TIMEOUT_MS ||
        3500
    );
    this.secureRequestTimeoutMs = Number(
      options.secureRequestTimeoutMs || process.env.FOCUSRITE_SECURE_REQUEST_TIMEOUT_MS || 2800
    );
    this.secureBootstrapRequestTimeoutMs = Number(
      options.secureBootstrapRequestTimeoutMs ||
        process.env.FOCUSRITE_SECURE_BOOTSTRAP_REQUEST_TIMEOUT_MS ||
        6000
    );
    this.secureStateConfirmTimeoutMs = Number(
      options.secureStateConfirmTimeoutMs ||
        process.env.FOCUSRITE_SECURE_STATE_CONFIRM_TIMEOUT_MS ||
        700
    );
    this.secureStatusProbeTimeoutMs = Number(
      options.secureStatusProbeTimeoutMs ||
        process.env.FOCUSRITE_SECURE_STATUS_PROBE_TIMEOUT_MS ||
        900
    );
    this.statusRefreshIntervalMs = Number(
      options.statusRefreshIntervalMs ||
        process.env.FOCUSRITE_STATUS_REFRESH_INTERVAL_MS ||
        750
    );
    this.secureKeepAliveBurst = Number(
      options.secureKeepAliveBurst || process.env.FOCUSRITE_SECURE_KEEPALIVE_BURST || 1
    );
    this.secureRecordPlaintextBytes = Number(
      options.secureRecordPlaintextBytes ||
        process.env.FOCUSRITE_SECURE_RECORD_PLAINTEXT_BYTES ||
        DEFAULT_SECURE_RECORD_PLAINTEXT_BYTES
    );
    this.secureCommandTimeoutMs = Number(
      options.secureCommandTimeoutMs || process.env.FOCUSRITE_SECURE_COMMAND_TIMEOUT_MS || 12000
    );
    this.secureRequireStateConfirm =
      String(
        options.secureRequireStateConfirm ??
          process.env.FOCUSRITE_SECURE_REQUIRE_STATE_CONFIRM ??
          'false'
      ).toLowerCase() === 'true';
    this.secureAirModeWriteEncoding = String(
      options.secureAirModeWriteEncoding ||
        process.env.FOCUSRITE_SECURE_AIR_MODE_WRITE_ENCODING ||
        'little'
    ).toLowerCase();
    if (!SECURE_AIR_MODE_WRITE_ENCODINGS.has(this.secureAirModeWriteEncoding)) {
      this.secureAirModeWriteEncoding = 'little';
    }
    this.secureResetSessionEachCommand =
      String(
        options.secureResetSessionEachCommand ??
          process.env.FOCUSRITE_SECURE_RESET_SESSION_EACH_COMMAND ??
          'false'
      ).toLowerCase() !== 'false';
    this.secureBootstrapMode = String(
      options.secureBootstrapMode || process.env.FOCUSRITE_SECURE_BOOTSTRAP || 'known'
    ).toLowerCase();
    if (!SECURE_BOOTSTRAP_MODES.has(this.secureBootstrapMode)) {
      this.secureBootstrapMode = 'known';
    }
    this.secureBootstrapFallback =
      String(
        options.secureBootstrapFallback ??
          process.env.FOCUSRITE_SECURE_BOOTSTRAP_FALLBACK ??
          'true'
      ).toLowerCase() !== 'false';
    this.secureAirItems = parseSecureAirItemIds(
      options.secureAirItems || process.env.FOCUSRITE_SECURE_AIR_ITEMS
    );

    this.debug = String(options.debug ?? process.env.FOCUSRITE_DEBUG ?? 'false').toLowerCase() === 'true';

    this.airStateByChannel = new Map();
    this.airModeByChannel = new Map();
    this.airStatusRefreshAtByChannel = new Map();

    // Legacy session state
    this.session = null;
    this.socketBuffer = '';

    // Secure session state
    this.secureSession = null;
    this.secureSessionPromise = null;
    this.secureCommandQueue = Promise.resolve();
    this.secureSendQueue = Promise.resolve();
    this.nextSecureRequestId = 0x300;
    this.airStateWaitersByChannel = new Map();
    this.airModeWaitersByChannel = new Map();
    this.secureRequestMetaById = new Map();
    this.secureEnumOptionsByItemId = new Map();

    this._debug(
      `transport=${this.transportMode} secureConfigured=${this._hasSecureConfig()} bootstrap=${this.secureBootstrapMode} requireStateConfirm=${this.secureRequireStateConfirm} modeWriteEncoding=${this.secureAirModeWriteEncoding} keepAliveBurst=${this.secureKeepAliveBurst} resetPerCommand=${this.secureResetSessionEachCommand} commandTimeoutMs=${this.secureCommandTimeoutMs} settingsPath=${this.control2SettingsPath || 'n/a'}`
    );
  }

  async toggleAir({ channel = 1 } = {}) {
    return this._setAir({ channel, command: 'toggle' });
  }

  async enableAir({ channel = 1 } = {}) {
    return this._setAir({ channel, command: 'enable' });
  }

  async disableAir({ channel = 1 } = {}) {
    return this._setAir({ channel, command: 'disable' });
  }

  async setAirMode({ channel = 1, mode = 0 } = {}) {
    return this._setAir({ channel, command: 'set', mode });
  }

  async getAirStatus({ channel = 1 } = {}) {
    await this._refreshAirStatusIfNeeded({ channel });
    return this._buildAirStatusResult({ channel });
  }

  _buildAirStatusResult({ channel, message } = {}) {
    const hasSecureChannel = this.secureAirItems.has(channel);
    const statusKnown = this._hasKnownAirStatus(channel);
    const enabled = statusKnown && this.airStateByChannel.get(channel) === true;
    const mode = statusKnown ? (hasSecureChannel ? this._getSecureAirMode(channel) : enabled ? 1 : 0) : null;

    return {
      ok: true,
      simulated: this.simulate,
      channel,
      statusKnown,
      airEnabled: enabled,
      airMode: mode,
      airLabel: statusKnown ? this._airModeLabel(mode) : 'AIR',
      message: message || (statusKnown ? 'Current AIR status.' : 'Waiting for Focusrite Control status.')
    };
  }

  _hasKnownAirStatus(channel) {
    if (!this.airStateByChannel.has(channel)) {
      return false;
    }

    if (!this.secureAirItems.has(channel)) {
      return true;
    }

    if (this.airStateByChannel.get(channel) !== true) {
      return true;
    }

    return this.airModeByChannel.has(channel);
  }

  _shouldRefreshAirStatus(channel) {
    const lastRefreshAt = this.airStatusRefreshAtByChannel.get(channel) || 0;
    return Date.now() - lastRefreshAt >= this.statusRefreshIntervalMs;
  }

  _markAirStatusRefresh(channel) {
    this.airStatusRefreshAtByChannel.set(channel, Date.now());
  }

  _getSecureAirMode(channel) {
    const enabled = this.airStateByChannel.get(channel) === true;
    if (!enabled) {
      return 0;
    }
    const mode = this.airModeByChannel.get(channel);
    if (mode === 2) {
      return 2;
    }
    return 1;
  }

  _nextSecureAirMode(channel) {
    const current = this._getSecureAirMode(channel);
    if (current <= 0) {
      return 1;
    }
    if (current === 1) {
      return 2;
    }
    return 0;
  }

  _resolveSecureTargetMode({ channel, command, mode }) {
    if (command === 'set') {
      return mode === 2 ? 2 : mode > 0 ? 1 : 0;
    }
    if (command === 'disable') {
      return 0;
    }
    if (command === 'enable') {
      return 1;
    }
    return this._nextSecureAirMode(channel);
  }

  _airModeLabel(mode) {
    if (mode === 2) {
      return 'AIR 2';
    }
    if (mode === 1) {
      return 'AIR 1';
    }
    return 'AIR OFF';
  }

  async _refreshAirStatusIfNeeded({ channel }) {
    if (this.simulate || !this._shouldRefreshAirStatus(channel)) {
      return;
    }

    this._markAirStatusRefresh(channel);

    const hasLegacyChannel = this.airItemIds.has(channel);
    const hasSecureChannel = this.secureAirItems.has(channel);
    const allowSecure = this.transportMode === 'auto' || this.transportMode === 'secure';
    const allowLegacy = this.transportMode === 'auto' || this.transportMode === 'legacy';

    if (allowSecure && hasSecureChannel) {
      try {
        await this._runSecureCommand(async () => {
          await ensureTimeout(
            this._probeAirStatusSecure({ channel }),
            this.secureCommandTimeoutMs,
            `Timed out while syncing AIR status for channel ${channel}.`
          );
        });
      } catch (error) {
        this._debug(`secure AIR status sync failed: ${error.message}`);
      }
    }

    if (!this._hasKnownAirStatus(channel) && allowLegacy && hasLegacyChannel) {
      try {
        await this._primeLegacyStatus();
      } catch (error) {
        this._debug(`legacy AIR status sync failed: ${error.message}`);
      }
    }

  }

  async _primeLegacyStatus() {
    await this._ensureSession();
    await new Promise((resolve) => {
      setTimeout(resolve, Math.max(120, Math.min(this.probeTimeoutMs, 600)));
    });
  }

  async _setAir({ channel, command, mode }) {
    const hasLegacyChannel = this.airItemIds.has(channel);
    const hasSecureChannel = this.secureAirItems.has(channel);
    const allowSecure = this.transportMode === 'auto' || this.transportMode === 'secure';
    let targetSecureMode = hasSecureChannel
      ? this._resolveSecureTargetMode({ channel, command, mode })
      : null;
    let targetEnabled =
      targetSecureMode == null
        ? command === 'disable'
          ? false
          : command === 'enable'
            ? true
            : command === 'set'
              ? Number(mode) > 0
            : !this.airStateByChannel.get(channel)
        : targetSecureMode > 0;

    if (!hasSecureChannel && command === 'set' && Number(mode) > 1) {
      return {
        ok: false,
        simulated: this.simulate,
        channel,
        airEnabled: true,
        airMode: 1,
        command,
        message: 'Legacy AIR transport does not support Presence & Drive mode.'
      };
    }

    if (!hasLegacyChannel && !hasSecureChannel) {
      return {
        ok: false,
        simulated: this.simulate,
        channel,
        airEnabled: targetEnabled,
        command,
        message:
          `No AIR channel mapping found for channel ${channel}. ` +
          'Configure FOCUSRITE_AIR_ITEM_IDS (legacy) or FOCUSRITE_SECURE_AIR_ITEMS (secure).'
      };
    }

    if (this.simulate) {
      this.airStateByChannel.set(channel, targetEnabled);
      this._markAirStatusRefresh(channel);
      if (targetSecureMode != null) {
        this.airModeByChannel.set(channel, targetSecureMode);
        this._markAirStatusRefresh(channel);
      }
      return {
        ok: true,
        simulated: true,
        channel,
        airEnabled: targetEnabled,
        airMode: targetSecureMode == null ? undefined : targetSecureMode,
        airLabel: targetSecureMode == null ? undefined : this._airModeLabel(targetSecureMode),
        command,
        message: 'Simulation mode is ON. No hardware command was sent.'
      };
    }

    const errors = [];

    if (allowSecure && hasSecureChannel) {
      try {
        await this._runSecureCommand(async () => {
          const resolvedMode = this._resolveSecureTargetMode({ channel, command, mode });
          await ensureTimeout(
            this._setAirSecure({ channel, mode: resolvedMode }),
            this.secureCommandTimeoutMs,
            `Timed out applying secure AIR command for channel ${channel}.`
          );
        });
        targetSecureMode = this._getSecureAirMode(channel);
        targetEnabled = targetSecureMode > 0;
        return {
          ok: true,
          simulated: false,
          channel,
          airEnabled: targetEnabled,
          airMode: targetSecureMode,
          airLabel: this._airModeLabel(targetSecureMode),
          command,
          message:
            `Sent AIR command via Focusrite Control 2 secure websocket ` +
            `(item 0x${this.secureAirItems.get(channel).airOnItemId.toString(16)}).`
        };
      } catch (error) {
        errors.push(`secure transport failed: ${error.message}`);
        this._debug(`secure transport failed: ${error.message}`);
        if (this.transportMode === 'secure') {
          return {
            ok: false,
            simulated: false,
            channel,
            airEnabled: targetEnabled,
            command,
            message: error.message
          };
        }
      }
    }

    const allowLegacy = this.transportMode === 'auto' || this.transportMode === 'legacy';
    if (allowLegacy && hasLegacyChannel) {
      try {
        await this._setAirLegacy({ channel, enabled: targetEnabled });
        this.airStateByChannel.set(channel, targetEnabled);
        this._markAirStatusRefresh(channel);
        return {
          ok: true,
          simulated: false,
          channel,
          airEnabled: targetEnabled,
          command,
          message: `Sent AIR command via legacy Focusrite ControlServer.`
        };
      } catch (error) {
        errors.push(`legacy transport failed: ${error.message}`);
        this._debug(`legacy transport failed: ${error.message}`);
      }
    }

    return {
      ok: false,
      simulated: false,
      channel,
      airEnabled: targetEnabled,
      command,
      message:
        errors.join(' | ') ||
        'No usable Focusrite transport was available for this command.'
    };
  }

  async _setAirLegacy({ channel, enabled }) {
    const itemId = this.airItemIds.get(channel);
    if (!itemId) {
      throw new Error(
        `No legacy AIR item id configured for channel ${channel}. Set FOCUSRITE_AIR_ITEM_IDS, e.g. "1:23".`
      );
    }

    await this._ensureSession();
    const value = enabled ? 'true' : 'false';
    const xml = `<set devid="${this.deviceId}"><item id="${itemId}" value="${value}"/></set>`;
    this._debug(`legacy send AIR channel=${channel} item=${itemId} value=${value}`);
    await this._sendXml(xml);
  }

  _hasSecureConfig() {
    return this.remoteConnectionKeyHex.length === 64 && this.remoteClientPublicKeyHex.length === 64;
  }

  _nextSecureRequestId() {
    this.nextSecureRequestId += 1;
    if (this.nextSecureRequestId > 0x7fffffff) {
      this.nextSecureRequestId = 0x300;
    }
    return this.nextSecureRequestId;
  }

  _buildSecureSetPacket({ requestId, itemId, op, valueBytes }) {
    const bodyLength = 0x10 + valueBytes.length;
    const parts = [
      Buffer.from([0x3b, 0x00, 0x01]),
      Buffer.alloc(4),
      Buffer.from([0x01, 0x00, 0x01]),
      Buffer.alloc(4),
      Buffer.alloc(4),
      Buffer.alloc(4),
      Buffer.alloc(2),
      Buffer.from([0x00, 0x02]),
      Buffer.from(valueBytes)
    ];

    parts[3].writeUInt32BE(bodyLength, 0);
    parts[4].writeUInt32BE(requestId, 0);
    parts[5].writeUInt32BE(itemId, 0);
    parts[6].writeUInt16BE(op, 0);

    const packet = Buffer.concat(parts);
    packet.writeUInt32BE(packet.length - 1, 3);
    return packet;
  }

  _extractSecureClearPackets(buffer) {
    const packets = [];
    let offset = 0;

    while (offset < buffer.length && buffer[offset] !== 0x3b) {
      offset += 1;
    }

    while (offset + 7 <= buffer.length) {
      if (buffer[offset] !== 0x3b) {
        break;
      }
      const payloadLength = buffer.readUInt32BE(offset + 3);
      const packetLength = payloadLength + 1;
      if (packetLength <= 0 || packetLength > 0x20000) {
        offset += 1;
        continue;
      }
      if (offset + packetLength > buffer.length) {
        break;
      }
      packets.push(buffer.subarray(offset, offset + packetLength));
      offset += packetLength;
    }

    return {
      packets,
      remainder: buffer.subarray(offset)
    };
  }

  _ingestSecureClearMessage(session, message) {
    const nextBuffer =
      session.clearPacketBuffer.length > 0
        ? Buffer.concat([session.clearPacketBuffer, message])
        : Buffer.from(message);
    const parsed = this._extractSecureClearPackets(nextBuffer);
    session.clearPacketBuffer = parsed.remainder;
    return parsed.packets;
  }

  _extractSecureResponse(packet) {
    if (packet.length < 18) {
      return null;
    }

    const type = packet[7];
    if (type !== 0x03) {
      return null;
    }

    const requestId = packet.readUInt32BE(14);
    const hasStatus = packet.length === 20;
    const status = hasStatus ? packet.readUInt16BE(18) : null;
    return { requestId, status, hasStatus };
  }

  _extractSecureType1Entries(packet) {
    if (packet.length < 14 || packet[7] !== 0x01) {
      return [];
    }

    let offset = 8;
    const count = packet.readUInt16BE(offset);
    offset += 2;

    const entries = [];
    for (let i = 0; i < count; i += 1) {
      if (offset + 4 > packet.length) {
        break;
      }

      const entryLength = packet.readUInt32BE(offset);
      const entryEnd = offset + entryLength;
      offset += 4;
      if (entryLength < 14 || entryEnd > packet.length) {
        break;
      }

      const requestId = packet.readUInt32BE(offset);
      offset += 4;
      const itemId = packet.readUInt32BE(offset);
      offset += 4;
      const op = packet.readUInt16BE(offset);
      offset += 2;

      entries.push({
        requestId,
        itemId,
        op,
        valueBytes: packet.subarray(offset, entryEnd)
      });
      offset = entryEnd;
    }

    return entries;
  }

  _extractSecureType3Entries(packet) {
    if (packet.length < 14 || packet[7] !== 0x03) {
      return [];
    }

    let offset = 8;
    const count = packet.readUInt16BE(offset);
    offset += 2;

    const entries = [];
    for (let i = 0; i < count; i += 1) {
      if (offset + 4 > packet.length) {
        break;
      }

      const entryLength = packet.readUInt32BE(offset);
      const entryEnd = offset + entryLength;
      offset += 4;
      if (entryLength < 10 || entryEnd > packet.length) {
        break;
      }

      const requestId = packet.readUInt32BE(offset);
      offset += 4;
      const status = packet.readUInt16BE(offset);
      offset += 2;

      entries.push({
        requestId,
        status,
        valueBytes: packet.subarray(offset, entryEnd)
      });
      offset = entryEnd;
    }

    return entries;
  }

  _registerSecureRequestPacket(packet) {
    const entries = this._extractSecureType1Entries(packet);
    for (const entry of entries) {
      this.secureRequestMetaById.set(entry.requestId, {
        itemId: entry.itemId,
        op: entry.op,
        valueBytes: Buffer.from(entry.valueBytes)
      });
    }
  }

  _parseSecureEnumOptions(valueBytes) {
    if (!valueBytes || valueBytes.length < 2) {
      return [];
    }

    let offset = 0;
    const count = valueBytes.readUInt16BE(offset);
    offset += 2;

    const values = [];
    for (let i = 0; i < count; i += 1) {
      if (offset + 2 > valueBytes.length) {
        break;
      }
      const size = valueBytes.readUInt16BE(offset);
      offset += 2;
      if (offset + size > valueBytes.length) {
        break;
      }
      values.push(valueBytes.subarray(offset, offset + size).toString('utf8'));
      offset += size;
    }

    return values;
  }

  _decodeSecureAirOnResponse(valueBytes) {
    if (!valueBytes || valueBytes.length === 0) {
      return null;
    }

    const raw = valueBytes[valueBytes.length - 1];
    if (raw === 0x00) {
      return false;
    }
    if (raw === 0x01) {
      return true;
    }

    return null;
  }

  _decodeSecureAirModeResponse({ request, status, valueBytes }) {
    if (!request || !valueBytes || valueBytes.length === 0) {
      return null;
    }

    if (request.op !== 0x0004) {
      return null;
    }

    const selectorHex = request.valueBytes.toString('hex');
    if (selectorHex === '000500') {
      const options = this._parseSecureEnumOptions(valueBytes);
      if (options.length > 0) {
        this.secureEnumOptionsByItemId.set(request.itemId, options);
      }
      return null;
    }

    if (selectorHex === '000100') {
      if (status !== 3 || valueBytes.length < 2) {
        return null;
      }
      const enumIndex = valueBytes.readUInt16BE(0);
      if (enumIndex === 0) {
        return 1;
      }
      if (enumIndex === 1) {
        return 2;
      }
      return null;
    }

    if (selectorHex !== '000900') {
      return null;
    }

    return null;
  }

  _observeSecureResponsePacket(packet) {
    const entries = this._extractSecureType3Entries(packet);
    if (entries.length === 0) {
      return;
    }

    for (const entry of entries) {
      const request = this.secureRequestMetaById.get(entry.requestId);
      if (!request) {
        continue;
      }

      for (const [channel, itemIds] of this.secureAirItems.entries()) {
        if (request.itemId === itemIds.airOnItemId) {
          const enabled = this._decodeSecureAirOnResponse(entry.valueBytes);
          if (enabled != null) {
            this.airStateByChannel.set(channel, enabled);
            this._markAirStatusRefresh(channel);
            this._resolveAirStateWaiters(channel, enabled);
          }
        }

        if (request.itemId === itemIds.airModeItemId) {
          const mode = this._decodeSecureAirModeResponse({
            request,
            status: entry.status,
            valueBytes: entry.valueBytes
          });
          if (mode != null) {
            this.airModeByChannel.set(channel, mode);
            this._markAirStatusRefresh(channel);
            this._resolveAirModeWaiters(channel, mode);
          }
        }
      }
    }
  }

  _observeSecurePacket(packet) {
    const type = packet.length > 7 ? packet[7] : 0xff;
    if (type === 0x03) {
      this._observeSecureResponsePacket(packet);
      return;
    }
    if (type !== 0x02) {
      return;
    }

    const entries = this._extractSecureType2Entries(packet);
    for (const [channel, itemIds] of this.secureAirItems.entries()) {
      const airOnIdBytes = Buffer.alloc(4);
      airOnIdBytes.writeUInt32BE(itemIds.airOnItemId, 0);
      const airModeIdBytes = Buffer.alloc(4);
      airModeIdBytes.writeUInt32BE(itemIds.airModeItemId, 0);

      for (const entry of entries) {
        if (entry.length < 8 || entry.length > 128) {
          continue;
        }

        if (entry.indexOf(airOnIdBytes) >= 0) {
          const maybeValue = entry[entry.length - 1];
          if (maybeValue === 0 || maybeValue === 1) {
            const enabled = maybeValue === 1;
            this.airStateByChannel.set(channel, enabled);
            this._markAirStatusRefresh(channel);
            this._resolveAirStateWaiters(channel, enabled);
          }
        }

        if (entry.indexOf(airModeIdBytes) >= 0) {
          const mode = this._decodeSecureAirModeEntry(entry);
          if (mode != null) {
            this.airModeByChannel.set(channel, mode);
            this._markAirStatusRefresh(channel);
            this._resolveAirModeWaiters(channel, mode);
          }
        }
      }
    }
  }

  _decodeSecureAirModeEntry(entry) {
    if (!entry || entry.length < 3) {
      return null;
    }

    const a = entry[entry.length - 3];
    const b = entry[entry.length - 2];
    const c = entry[entry.length - 1];

    // Focusrite Control 2 writes mode values as:
    // Presence        => 01 00 00
    // Presence&Drive  => 01 00 01
    if (a === 0x01 && b === 0x00 && c === 0x00) {
      return 1;
    }
    if (a === 0x01 && b === 0x00 && c === 0x01) {
      return 2;
    }

    // Focusrite notifications encode the same states differently:
    // Presence        => 00 00 01
    // Presence&Drive  => 00 01 01
    if (a === 0x00 && b === 0x00 && c === 0x01) {
      return 1;
    }
    if (a === 0x00 && b === 0x01 && c === 0x01) {
      return 2;
    }

    if (a === 0x00 && b === 0x00 && c === 0x00) {
      return 0;
    }

    return null;
  }

  _extractSecureType2Entries(packet) {
    if (packet.length < 14 || packet[7] !== 0x02) {
      return [packet];
    }

    let offset = 8;
    const count = packet.readUInt16BE(offset);
    offset += 2;

    const entries = [];
    for (let i = 0; i < count; i += 1) {
      if (offset + 4 > packet.length) {
        break;
      }
      const entryLength = packet.readUInt32BE(offset);
      offset += 4;
      if (entryLength <= 0 || offset + entryLength > packet.length) {
        break;
      }
      entries.push(packet.subarray(offset, offset + entryLength));
      offset += entryLength;
    }

    return entries.length > 0 ? entries : [packet];
  }

  _waitForAirState({ channel, expected, timeoutMs }) {
    if (this.airStateByChannel.get(channel) === expected) {
      return Promise.resolve(true);
    }

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        const waiters = this.airStateWaitersByChannel.get(channel);
        if (waiters) {
          this.airStateWaitersByChannel.set(
            channel,
            waiters.filter((entry) => entry !== waiter)
          );
        }
        resolve(false);
      }, timeoutMs);

      const waiter = {
        expected,
        resolve: () => {
          clearTimeout(timer);
          resolve(true);
        }
      };

      const waiters = this.airStateWaitersByChannel.get(channel) || [];
      waiters.push(waiter);
      this.airStateWaitersByChannel.set(channel, waiters);
    });
  }

  _resolveAirStateWaiters(channel, observed) {
    this._markAirStatusRefresh(channel);
    const waiters = this.airStateWaitersByChannel.get(channel);
    if (!waiters || waiters.length === 0) {
      return;
    }
    const remaining = [];
    for (const waiter of waiters) {
      if (waiter.expected === observed) {
        waiter.resolve();
      } else {
        remaining.push(waiter);
      }
    }
    this.airStateWaitersByChannel.set(channel, remaining);
  }

  _waitForAirMode({ channel, expected, timeoutMs }) {
    if (this.airModeByChannel.get(channel) === expected) {
      return Promise.resolve(true);
    }

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        const waiters = this.airModeWaitersByChannel.get(channel);
        if (waiters) {
          this.airModeWaitersByChannel.set(
            channel,
            waiters.filter((entry) => entry !== waiter)
          );
        }
        resolve(false);
      }, timeoutMs);

      const waiter = {
        expected,
        resolve: () => {
          clearTimeout(timer);
          resolve(true);
        }
      };

      const waiters = this.airModeWaitersByChannel.get(channel) || [];
      waiters.push(waiter);
      this.airModeWaitersByChannel.set(channel, waiters);
    });
  }

  _resolveAirModeWaiters(channel, observed) {
    this._markAirStatusRefresh(channel);
    const waiters = this.airModeWaitersByChannel.get(channel);
    if (!waiters || waiters.length === 0) {
      return;
    }
    const remaining = [];
    for (const waiter of waiters) {
      if (waiter.expected === observed) {
        waiter.resolve();
      } else {
        remaining.push(waiter);
      }
    }
    this.airModeWaitersByChannel.set(channel, remaining);
  }

  _secureParseWsRecords(payload, includeHeader) {
    const records = [];
    let offset = 0;
    let header = null;

    if (includeHeader) {
      if (payload.length < 24) {
        return { header: null, records: [] };
      }
      header = payload.subarray(0, 24);
      offset = 24;
    }

    while (offset + 2 <= payload.length) {
      const length = payload.readUInt16BE(offset);
      offset += 2;
      if (offset + length > payload.length) {
        break;
      }
      records.push(payload.subarray(offset, offset + length));
      offset += length;
    }

    return { header, records };
  }

  _secureEncryptRecord(session, plaintext, includeHeader) {
    const clear = Buffer.from(plaintext);
    const maxChunkBytes =
      Number.isFinite(this.secureRecordPlaintextBytes) && this.secureRecordPlaintextBytes > 0
        ? this.secureRecordPlaintextBytes
        : clear.length;

    const parts = includeHeader ? [session.pushHeader] : [];
    for (let offset = 0; offset < clear.length; offset += maxChunkBytes) {
      const chunk = clear.subarray(offset, Math.min(offset + maxChunkBytes, clear.length));
      const cipher = Buffer.from(
        sodium.crypto_secretstream_xchacha20poly1305_push(
          session.push.state,
          chunk,
          null,
          sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        )
      );

      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16BE(cipher.length, 0);
      parts.push(lenBuf, cipher);
    }

    return Buffer.concat(parts);
  }

  _secureSend(session, plaintext, includeHeader = false) {
    if (!session.ws || session.ws.readyState !== 1) {
      throw new Error('Secure websocket is not open.');
    }
    if (!includeHeader) {
      this._registerSecureRequestPacket(plaintext);
    }
    const payload = this._secureEncryptRecord(session, plaintext, includeHeader);
    session.ws.send(payload);
  }

  _secureEnqueue(task) {
    const queued = this.secureSendQueue.then(task, task);
    this.secureSendQueue = queued.catch(() => Promise.resolve());
    return queued;
  }

  _secureSendAndWaitForReplyWithSession({
    session,
    packet,
    requestId,
    timeoutMs = this.secureRequestTimeoutMs
  }) {
    return this._secureSendAndWaitForAckWithSession({
      session,
      packet,
      requestId,
      timeoutMs,
      requireStatus: false
    });
  }

  _runSecureCommand(task) {
    const queued = this.secureCommandQueue.then(task, task);
    this.secureCommandQueue = queued.catch(() => Promise.resolve());
    return queued;
  }

  async _secureQueueKeepAliveBurst() {
    const count = Number(this.secureKeepAliveBurst);
    if (!Number.isFinite(count) || count <= 0) {
      return;
    }

    const keepalivePacket = Buffer.from(KEEPALIVE_PACKET_HEX, 'hex');
    await this._secureEnqueue(async () => {
      const session = await this._ensureSecureSession();
      for (let i = 0; i < count; i += 1) {
        this._secureSend(session, keepalivePacket);
      }
    });
  }

  _extractClientSecureRequestId(packet) {
    if (packet.length < 20) {
      return null;
    }
    if (packet[7] !== 0x01) {
      return null;
    }
    return packet.readUInt32BE(14);
  }

  _knownBootstrapPackets() {
    return SOLO4TH_GEN_BOOTSTRAP_HEX.map((hex) => Buffer.from(hex, 'hex'));
  }

  _buildAirModeValueBytes(mode, previousMode = 1) {
    const normalized = mode === 2 ? 2 : mode > 0 ? 1 : 0;
    if (this.secureAirModeWriteEncoding === 'big') {
      return Buffer.from([0x00, 0x00, normalized]);
    }

    // Match Focusrite Control 2's observed write payloads:
    // Presence        => 01 00 00
    // Presence&Drive  => 01 00 01
    // OFF             => keep the previous mode latched while disabling AIR
    const latchedMode = previousMode === 2 ? 1 : 0;
    if (normalized <= 0) {
      return Buffer.from([0x01, 0x00, latchedMode]);
    }
    return Buffer.from([0x01, 0x00, normalized === 2 ? 0x01 : 0x00]);
  }

  _isRecoverableBootstrapError(error) {
    const message = String(error?.message || '').toLowerCase();
    return (
      message.includes('secure request aborted') ||
      message.includes('secure websocket closed') ||
      message.includes('code 1006') ||
      message.includes('timed out waiting for secure ack')
    );
  }

  async _ensureSecureBootstrap() {
    if (this.secureBootstrapMode === 'none') {
      return;
    }

    const session = await this._ensureSecureSession();
    if (session.bootstrapped) {
      return;
    }
    if (session.bootstrapPromise) {
      return session.bootstrapPromise;
    }

    session.bootstrapPromise = this._secureEnqueue(async () => {
      if (session.bootstrapped) {
        return;
      }
      this._debug(`running secure bootstrap profile "${this.secureBootstrapMode}"`);
      await this._runKnownSecureBootstrap(session);
      session.bootstrapped = true;
      this._debug('secure bootstrap completed');
    }).finally(() => {
      session.bootstrapPromise = null;
    });

    return session.bootstrapPromise;
  }

  async _runKnownSecureBootstrap(session) {
    const keepalivePacket = Buffer.from(KEEPALIVE_PACKET_HEX, 'hex');
    this._secureSend(session, keepalivePacket);

    for (const packet of this._knownBootstrapPackets()) {
      const requestId = this._extractClientSecureRequestId(packet);
      if (requestId == null) {
        this._secureSend(session, packet);
        continue;
      }
      await this._secureSendAndWaitForAckWithSession({
        session,
        packet,
        requestId,
        timeoutMs: this.secureBootstrapRequestTimeoutMs,
        requireStatus: false
      });
    }

    this._secureSend(session, keepalivePacket);
    this._secureSend(session, keepalivePacket);
  }

  async _ensureSecureSession() {
    if (!this._hasSecureConfig()) {
      throw new Error(
        'Secure transport is not configured. Missing RemoteConnection key or RemoteClient publicKey in settings.xml.'
      );
    }

    if (this.secureSession?.ready && this.secureSession.ws?.readyState === 1) {
      return this.secureSession;
    }

    if (this.secureSessionPromise) {
      return this.secureSessionPromise;
    }

    if (typeof WebSocket === 'undefined') {
      throw new Error('Global WebSocket is not available in this Node runtime.');
    }

    this.secureSessionPromise = ensureTimeout(
      this._openSecureSession(),
      this.secureHandshakeTimeoutMs,
      'Timed out while establishing Focusrite secure websocket session.'
    ).finally(() => {
      this.secureSessionPromise = null;
    });

    return this.secureSessionPromise;
  }

  async _openSecureSession() {
    await sodium.ready;

    const serverSecret = Buffer.from(this.remoteConnectionKeyHex, 'hex');
    const serverPublic = Buffer.from(sodium.crypto_scalarmult_base(serverSecret));
    const clientPublic = Buffer.from(this.remoteClientPublicKeyHex, 'hex');

    const sessionKeys = sodium.crypto_kx_server_session_keys(
      serverPublic,
      serverSecret,
      clientPublic
    );

    const sharedKey = Buffer.from(sessionKeys.sharedTx);
    const push = sodium.crypto_secretstream_xchacha20poly1305_init_push(sharedKey);
    const wsUrl = `ws://${this.secureWsHost}:${this.secureWsPort}/${this.remoteClientPublicKeyHex}`;

    this._debug(`opening secure websocket ${wsUrl}`);

    const session = {
      ws: null,
      sharedKey,
      push: {
        state: push.state
      },
      pushHeader: Buffer.from(push.header),
      pullState: null,
      helloNonce: Buffer.from(sodium.randombytes_buf(32)),
      handshakeStage: 'await_server_hello',
      ready: false,
      readyResolver: null,
      readyRejecter: null,
      pendingRequests: new Map(),
      clearPacketBuffer: Buffer.alloc(0),
      bootstrapped: false,
      bootstrapPromise: null
    };

    const readyPromise = new Promise((resolve, reject) => {
      session.readyResolver = resolve;
      session.readyRejecter = reject;
    });

    const ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';
    session.ws = ws;
    this.secureSession = session;

    ws.onopen = () => {
      if (!this._isCurrentSecureSession(session)) {
        return;
      }
      try {
        this._secureSend(session, session.helloNonce, true);
      } catch (error) {
        this._teardownSecureSession(`failed to send secure hello: ${error.message}`, session);
      }
    };

    ws.onmessage = (event) => {
      if (!this._isCurrentSecureSession(session)) {
        return;
      }
      const payload = Buffer.from(event.data);
      this._onSecureMessage(session, payload);
    };

    ws.onerror = () => {
      if (!this._isCurrentSecureSession(session)) {
        return;
      }
      if (!session.ready) {
        this._teardownSecureSession('secure websocket error during handshake', session);
      }
    };

    ws.onclose = (event) => {
      this._teardownSecureSession(`secure websocket closed (code ${event.code})`, session);
    };

    await readyPromise;
    this._debug('secure websocket ready');
    return session;
  }

  _isCurrentSecureSession(session) {
    return this.secureSession === session;
  }

  _teardownSecureSession(reason, targetSession = this.secureSession) {
    const session = targetSession;
    if (!session) {
      return;
    }
    if (!this._isCurrentSecureSession(session)) {
      this._debug(`ignoring teardown for stale secure session: ${reason}`);
      return;
    }

    this._debug(`tearing down secure session: ${reason}`);

    for (const [, pending] of session.pendingRequests.entries()) {
      clearTimeout(pending.timer);
      pending.reject(new Error(`Secure request aborted: ${reason}`));
    }
    session.pendingRequests.clear();

    if (!session.ready && session.readyRejecter) {
      session.readyRejecter(new Error(reason));
      session.readyRejecter = null;
    }

    try {
      if (session.ws && session.ws.readyState === 1) {
        session.ws.close(1000, 'session reset');
      }
    } catch {
      // no-op
    }

    this.secureSession = null;
    this.secureSessionPromise = null;
    this.airStateWaitersByChannel.clear();
    this.airModeWaitersByChannel.clear();
    this.secureRequestMetaById.clear();
    this.secureEnumOptionsByItemId.clear();
  }

  _onSecureMessage(session, payload) {
    if (!this._isCurrentSecureSession(session)) {
      return;
    }
    const parsed = this._secureParseWsRecords(payload, !session.pullState);
    if (!session.pullState) {
      if (!parsed.header) {
        this._teardownSecureSession('secure frame missing secretstream header', session);
        return;
      }
      try {
        session.pullState = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
          parsed.header,
          session.sharedKey
        );
      } catch (error) {
        this._teardownSecureSession(`failed to init secure pull state: ${error.message}`, session);
        return;
      }
    }

    for (const cipherRecord of parsed.records) {
      let message;
      try {
        const out = sodium.crypto_secretstream_xchacha20poly1305_pull(
          session.pullState,
          cipherRecord,
          null
        );
        if (!out || !out.message) {
          continue;
        }
        message = Buffer.from(out.message);
      } catch (error) {
        this._teardownSecureSession(`failed to decrypt secure frame: ${error.message}`, session);
        return;
      }

      if (session.handshakeStage === 'await_server_hello') {
        try {
          this._secureSend(session, message);
        } catch (error) {
          this._teardownSecureSession(`failed to send secure echo: ${error.message}`, session);
          return;
        }
        session.handshakeStage = 'await_server_echo';
        continue;
      }

      if (session.handshakeStage === 'await_server_echo') {
        if (!message.equals(session.helloNonce)) {
          this._teardownSecureSession(
            'secure handshake mismatch (unexpected echo payload)',
            session
          );
          return;
        }
        session.handshakeStage = 'ready';
        session.ready = true;
        if (session.readyResolver) {
          session.readyResolver();
        }
        continue;
      }

      const clearPackets = this._ingestSecureClearMessage(session, message);
      for (const packet of clearPackets) {
        const response = this._extractSecureResponse(packet);
        if (response) {
          const pending = session.pendingRequests.get(response.requestId);
          if (pending) {
            if (pending.requireStatus && !response.hasStatus) {
              continue;
            }
            clearTimeout(pending.timer);
            session.pendingRequests.delete(response.requestId);
            if (!response.hasStatus || response.status === 0) {
              pending.resolve(response);
            } else {
              pending.reject(
                new Error(
                  `Focusrite secure request 0x${response.requestId.toString(16)} failed with status ${response.status}.`
                )
              );
            }
          }
        }

        this._observeSecurePacket(packet);
      }
    }
  }

  _secureSendAndWaitForAckWithSession({
    session,
    packet,
    requestId,
    timeoutMs,
    requireStatus = true
  }) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        session.pendingRequests.delete(requestId);
        reject(
          new Error(
            `Timed out waiting for secure ACK for request 0x${requestId.toString(16)}.`
          )
        );
      }, timeoutMs);

      session.pendingRequests.set(requestId, {
        resolve,
        reject,
        timer,
        requireStatus
      });

      try {
        this._secureSend(session, packet);
      } catch (error) {
        clearTimeout(timer);
        session.pendingRequests.delete(requestId);
        reject(error);
      }
    });
  }

  async _secureSendAndWaitForAck(packet, requestId, timeoutMs = this.secureRequestTimeoutMs) {
    return this._secureEnqueue(async () => {
      const session = await this._ensureSecureSession();
      return this._secureSendAndWaitForAckWithSession({
        session,
        packet,
        requestId,
        timeoutMs
      });
    });
  }

  _buildSecureProbePacket({ requestId, itemId, op, valueBytes }) {
    return this._buildSecureSetPacket({
      requestId,
      itemId,
      op,
      valueBytes
    });
  }

  _buildSecureStatusProbeSteps(channel) {
    const itemIds = this.secureAirItems.get(channel);
    if (!itemIds) {
      return [];
    }

    return [
      { itemId: itemIds.airOnItemId, op: 0x0002, valueBytes: Buffer.from([0x00]) },
      { itemId: itemIds.airOnItemId, op: 0x0005, valueBytes: Buffer.from([0x00]) },
      { itemId: itemIds.airModeItemId, op: 0x0002, valueBytes: Buffer.from([0x00]) },
      { itemId: itemIds.airModeItemId, op: 0x0004, valueBytes: Buffer.from([0x00]) },
      { itemId: itemIds.airModeItemId, op: 0x0004, valueBytes: Buffer.from([0x05]) },
      { itemId: itemIds.airModeItemId, op: 0x0004, valueBytes: Buffer.from([0x09]) }
    ];
  }

  async _probeAirStatusSecure({ channel }) {
    const itemIds = this.secureAirItems.get(channel);
    if (!itemIds) {
      return;
    }

    try {
      try {
        await this._ensureSecureBootstrap();
      } catch (error) {
        if (this.secureBootstrapFallback && this._isRecoverableBootstrapError(error)) {
          this._debug(
            `secure bootstrap failed during status probe; retrying with direct reads: ${error.message}`
          );
          this._teardownSecureSession('secure bootstrap failed during status probe');
        } else {
          throw error;
        }
      }

      const session = await this._ensureSecureSession();
      const steps = this._buildSecureStatusProbeSteps(channel);
      for (const step of steps) {
        if (this._hasKnownAirStatus(channel)) {
          break;
        }

        const requestId = this._nextSecureRequestId();
        const packet = this._buildSecureProbePacket({
          requestId,
          itemId: step.itemId,
          op: step.op,
          valueBytes: step.valueBytes
        });

        try {
          await this._secureEnqueue(() =>
            this._secureSendAndWaitForReplyWithSession({
              session,
              packet,
              requestId,
              timeoutMs: this.secureStatusProbeTimeoutMs
            })
          );
        } catch (error) {
          this._debug(
            `secure AIR probe failed item=0x${step.itemId.toString(16)} op=0x${step.op
              .toString(16)
              .padStart(4, '0')}: ${error.message}`
          );
        }
      }

      if (!this._hasKnownAirStatus(channel)) {
        await new Promise((resolve) => {
          setTimeout(
            resolve,
            Math.max(100, Math.min(this.secureStatusProbeTimeoutMs, this.secureStateConfirmTimeoutMs))
          );
        });
      }
    } finally {
      if (this.secureResetSessionEachCommand) {
        this._teardownSecureSession('secure status probe completed; resetting session');
      }
    }
  }

  async _setAirSecure({ channel, mode }) {
    const itemIds = this.secureAirItems.get(channel);
    if (!itemIds) {
      throw new Error(
        `No secure AIR item ids configured for channel ${channel}. Set FOCUSRITE_SECURE_AIR_ITEMS (e.g. "1:0x1023:0x1024").`
      );
    }

    const normalizedMode = mode === 2 ? 2 : mode > 0 ? 1 : 0;
    const enabled = normalizedMode > 0;
    const previousEnabled = this.airStateByChannel.get(channel) === true;
    const previousMode = this.airModeByChannel.get(channel);
    let stateConfirmed = previousEnabled === enabled;
    let modeConfirmed = !enabled || previousMode === normalizedMode;

    try {
      try {
        await this._ensureSecureBootstrap();
      } catch (error) {
        if (this.secureBootstrapFallback && this._isRecoverableBootstrapError(error)) {
          this._debug(
            `secure bootstrap failed; retrying once with a fresh secure session: ${error.message}`
          );
          this._teardownSecureSession('secure bootstrap failed; retry with fresh session');
          try {
            await this._ensureSecureBootstrap();
          } catch (retryError) {
            this._debug(
              `secure bootstrap retry failed; continuing this command with direct writes: ${retryError.message}`
            );
          }
        } else {
          throw error;
        }
      }

      const requestIdAirOn = this._nextSecureRequestId();
      const requestIdAirMode = this._nextSecureRequestId();

      const airOnPacket = this._buildSecureSetPacket({
        requestId: requestIdAirOn,
        itemId: itemIds.airOnItemId,
        op: 0x0005,
        // Focusrite Control 2 writes AIR enable as:
        // ON  => 01 01
        // OFF => 01 00
        valueBytes: enabled ? Buffer.from([0x01, 0x01]) : Buffer.from([0x01, 0x00])
      });

      const airModePacket = this._buildSecureSetPacket({
        requestId: requestIdAirMode,
        itemId: itemIds.airModeItemId,
        op: 0x0004,
        valueBytes: this._buildAirModeValueBytes(normalizedMode, previousMode)
      });

      this._debug(
        `secure send AIR channel=${channel} on=0x${itemIds.airOnItemId.toString(
          16
        )} mode=0x${itemIds.airModeItemId.toString(16)} enabled=${enabled} modeValue=${normalizedMode}`
      );

      await this._secureQueueKeepAliveBurst();
      await this._secureSendAndWaitForAck(airOnPacket, requestIdAirOn);
      await this._secureSendAndWaitForAck(airModePacket, requestIdAirMode);
      await this._secureQueueKeepAliveBurst();

      if (previousEnabled !== enabled) {
        stateConfirmed = await this._waitForAirState({
          channel,
          expected: enabled,
          timeoutMs: this.secureStateConfirmTimeoutMs
        });
        if (!stateConfirmed) {
          if (this.secureRequireStateConfirm) {
            throw new Error(
              `AIR command was ACKed but no on/off state notification arrived for channel ${channel}.`
            );
          }
          this._debug(
            `AIR on/off notification missing for channel ${channel}; accepting ACK result.`
          );
        }
      }

      if (enabled && previousMode !== normalizedMode) {
        modeConfirmed = await this._waitForAirMode({
          channel,
          expected: normalizedMode,
          timeoutMs: this.secureStateConfirmTimeoutMs
        });
        if (!modeConfirmed) {
          if (this.secureRequireStateConfirm) {
            throw new Error(
              `AIR command was ACKed but no mode notification arrived for channel ${channel}.`
            );
          }
          this._debug(
            `AIR mode notification missing for channel ${channel}; accepting ACK result.`
          );
        }
      }

      // If Focusrite does not emit a timely notification but the write was ACKed,
      // keep the bridge cache aligned with the command we just sent. This keeps
      // Stream Deck state stable while still allowing later notifications to win.
      if (stateConfirmed || !this.secureRequireStateConfirm) {
        this.airStateByChannel.set(channel, enabled);
        this._markAirStatusRefresh(channel);
      }
      if (modeConfirmed || !this.secureRequireStateConfirm) {
        this.airModeByChannel.set(channel, normalizedMode);
        this._markAirStatusRefresh(channel);
      }
    } finally {
      if (this.secureResetSessionEachCommand) {
        this._teardownSecureSession('secure command completed; resetting session');
      }
    }
  }

  async _ensureSession() {
    if (this.session?.socket && !this.session.socket.destroyed) {
      return;
    }

    const port = await this._resolveServerPort();
    const socket = await this._connectTcp(port);

    this.session = {
      port,
      socket,
      keepAliveTimer: setInterval(() => {
        this._sendXml(KEEP_ALIVE_PAYLOAD).catch(() => {
          // If keep-alive fails, next command will reconnect.
        });
      }, 3000)
    };

    socket.on('data', (chunk) => {
      this._consumeData(chunk.toString());
    });

    socket.on('close', () => {
      this._teardownSession();
    });

    socket.on('error', () => {
      this._teardownSession();
    });

    await this._sendXml(`<client-details client-key="${this.clientKey}"/>`);
    await this._sendXml(`<device-subscribe devid="${this.deviceId}" subscribe="true"/>`);
  }

  _teardownSession() {
    if (this.session?.keepAliveTimer) {
      clearInterval(this.session.keepAliveTimer);
    }
    this.session = null;
    this.socketBuffer = '';
  }

  _consumeData(fragment) {
    this.socketBuffer += fragment;

    while (this.socketBuffer.startsWith('Length=')) {
      if (this.socketBuffer.length < 14) {
        return;
      }

      const hexSize = this.socketBuffer.slice(7, 13);
      const payloadLength = Number.parseInt(hexSize, 16);
      if (!Number.isFinite(payloadLength)) {
        this.socketBuffer = '';
        return;
      }

      const packetLength = 14 + payloadLength;
      if (this.socketBuffer.length < packetLength) {
        return;
      }

      const payload = this.socketBuffer.slice(14, packetLength);
      this._debug(`rx payload: ${payload}`);
      this._observePayload(payload);
      this.socketBuffer = this.socketBuffer.slice(packetLength);
    }
  }

  _observePayload(payload) {
    for (const [channel, itemId] of this.airItemIds.entries()) {
      const regex = new RegExp(`id="${itemId}"\\s+value="(true|false)"`);
      const match = payload.match(regex);
      if (match) {
        this.airStateByChannel.set(channel, match[1] === 'true');
        this._markAirStatusRefresh(channel);
      }
    }
  }

  _sendXml(xml) {
    if (!this.session?.socket || this.session.socket.destroyed) {
      return Promise.reject(new Error('Not connected to Focusrite ControlServer.'));
    }

    return new Promise((resolve, reject) => {
      this.session.socket.write(encodePacket(xml), (error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
  }

  _connectTcp(port) {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let settled = false;

      const done = (error, value) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(connectTimeout);
        if (error) {
          reject(error);
        } else {
          resolve(value);
        }
      };

      const onError = (error) => {
        socket.destroy();
        done(
          new Error(
            `Unable to connect to Focusrite ControlServer on ${this.serverHost}:${port}: ${error.message}`
          )
        );
      };

      socket.once('error', onError);
      const connectTimeout = setTimeout(() => {
        socket.destroy();
        done(new Error(`Connection timeout to ${this.serverHost}:${port}`));
      }, this.connectTimeoutMs);

      socket.connect(port, this.serverHost, () => {
        this._debug(`connected to control server on ${this.serverHost}:${port}`);
        socket.removeListener('error', onError);
        done(null, socket);
      });
    });
  }

  async _resolveServerPort() {
    if (this.forcedServerPort > 0) {
      this._debug(`using forced server port ${this.forcedServerPort}`);
      const forcedOk = await this._probeLegacyProtocolOnPort(this.forcedServerPort);
      if (forcedOk) {
        return this.forcedServerPort;
      }
      throw new Error(
        `Forced port ${this.forcedServerPort} is reachable but did not respond as a legacy Focusrite ControlServer.`
      );
    }

    try {
      const discovered = await this._discoverServerPort();
      this._debug(`discovered server port ${discovered}`);
      const discoveredOk = await this._probeLegacyProtocolOnPort(discovered);
      if (discoveredOk) {
        return discovered;
      }
      this._debug(`discovered port ${discovered} did not respond with legacy protocol`);
    } catch (discoveryError) {
      this._debug(`discovery failed: ${discoveryError.message}`);
    }

    for (const candidate of this.serverPortCandidates) {
      try {
        this._debug(`probing candidate port ${candidate}`);
        const ok = await this._probeLegacyProtocolOnPort(candidate);
        if (ok) {
          this._debug(`candidate port ${candidate} matched legacy protocol`);
          return candidate;
        }
      } catch (error) {
        this._debug(`candidate port ${candidate} failed: ${error.message}`);
      }
    }

    throw new Error(
      'Could not find a legacy Focusrite ControlServer endpoint. Ensure Focusrite Control/Control 2 is running. If your build no longer exposes the legacy protocol, this transport cannot control AIR.'
    );
  }

  _probeLegacyProtocolOnPort(port) {
    return new Promise(async (resolve) => {
      let socket = null;
      let done = false;
      let timer = null;

      const finish = (ok) => {
        if (done) {
          return;
        }
        done = true;
        if (timer) {
          clearTimeout(timer);
        }
        if (socket && !socket.destroyed) {
          socket.destroy();
        }
        resolve(ok);
      };

      try {
        socket = await this._connectTcp(port);
      } catch (_) {
        finish(false);
        return;
      }

      socket.on('data', (chunk) => {
        const text = chunk.toString();
        this._debug(`probe port ${port} received: ${text.slice(0, 160)}`);
        if (text.includes('Length=') || text.includes('<client-details') || text.includes('<device-arrival')) {
          finish(true);
        }
      });

      socket.on('error', () => finish(false));
      socket.on('close', () => finish(false));

      timer = setTimeout(() => finish(false), this.probeTimeoutMs);

      socket.write(encodePacket(`<client-details client-key="${this.clientKey}"/>`), () => {
        socket.write(encodePacket(`<device-subscribe devid="${this.deviceId}" subscribe="true"/>`));
      });
    });
  }

  _discoverServerPort() {
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket('udp4');
      let resolved = false;
      let intervalHandle = null;
      let timeoutHandle = null;

      const cleanup = () => {
        if (intervalHandle) {
          clearInterval(intervalHandle);
        }
        if (timeoutHandle) {
          clearTimeout(timeoutHandle);
        }
        socket.close();
      };

      const complete = (port) => {
        if (resolved) {
          return;
        }
        resolved = true;
        cleanup();
        resolve(port);
      };

      socket.on('message', (message) => {
        const match = message.toString().match(/port=['"]([0-9]+)['"]/);
        if (match) {
          complete(Number(match[1]));
        }
      });

      socket.on('error', (error) => {
        if (resolved) {
          return;
        }
        resolved = true;
        cleanup();
        reject(new Error(`Discovery socket error: ${error.message}`));
      });

      const announce = () => {
        const packet = encodePacket(DISCOVERY_PAYLOAD);
        const hosts = new Set([this.discoveryHost, '127.0.0.1']);
        this._debug(
          `sending discovery on hosts ${Array.from(hosts).join(', ')} to ports ${DISCOVERY_PORTS.join(',')}`
        );
        for (const host of hosts) {
          DISCOVERY_PORTS.forEach((port) => {
            socket.send(packet, port, host);
          });
        }
      };

      socket.bind(0, () => {
        socket.setBroadcast(true);
        announce();
        intervalHandle = setInterval(announce, this.discoveryIntervalMs);
      });

      timeoutHandle = setTimeout(() => {
        if (resolved) {
          return;
        }
        resolved = true;
        cleanup();
        reject(
          new Error(
            'Could not discover Focusrite ControlServer. Ensure Focusrite Control/Control 2 is open, then retry or set FOCUSRITE_SERVER_PORT.'
          )
        );
      }, this.discoveryTimeoutMs);
    });
  }

  _debug(message) {
    if (!this.debug) {
      return;
    }
    console.log(`[focusrite-adapter] ${message}`);
  }
}

module.exports = { FocusriteAdapter, encodePacket };

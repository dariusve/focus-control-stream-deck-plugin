'use strict';

const fs = require('node:fs');
const path = require('node:path');
const sodium = require('libsodium-wrappers');

const SECRETSTREAM_HEADER_BYTES = 24;
const AIR_ENABLED_ITEM_ID = 0x1023;
const AIR_MODE_ITEM_ID = 0x1024;

function parseArgs() {
  const pcapPath = process.argv[2] || process.env.FOCUSRITE_PCAP_PATH || '';
  if (!pcapPath) {
    throw new Error(
      'Missing pcap path. Usage: npm run decode:pcap:secure -- /absolute/path/focusrite-58322.pcap'
    );
  }

  const serverPort = Number(process.env.FOCUSRITE_PORT || 58322);
  const settingsPath =
    process.env.FOCUSRITE_SETTINGS_PATH ||
    path.join(
      process.env.HOME || '',
      'Library',
      'Application Support',
      'Focusrite',
      'Focusrite Control 2',
      'settings.xml'
    );

  const settings = readSettings(settingsPath);
  const remoteKeyHex = normalizeHex(
    process.env.FOCUSRITE_REMOTE_KEY || settings.remoteKeyHex
  );
  const remoteClientPublicKeyHex = normalizeHex(
    process.env.FOCUSRITE_REMOTE_CLIENT_PUBLIC_KEY || settings.remoteClientPublicKeyHex
  );

  if (!remoteKeyHex) {
    throw new Error(
      `Missing RemoteConnection key. Provide FOCUSRITE_REMOTE_KEY or ensure settings exist at: ${settingsPath}`
    );
  }

  return {
    pcapPath,
    serverPort,
    remoteKeyHex,
    remoteClientPublicKeyHex
  };
}

function normalizeHex(value) {
  const hex = String(value || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  return hex.length === 64 ? hex : '';
}

function readSettings(settingsPath) {
  if (!settingsPath || !fs.existsSync(settingsPath)) {
    return {
      remoteKeyHex: '',
      remoteClientPublicKeyHex: ''
    };
  }
  const xml = fs.readFileSync(settingsPath, 'utf8');
  const remoteKeyMatch = xml.match(/<RemoteConnection\s+key="([0-9a-fA-F]{64})"/);
  const remoteClientMatch = xml.match(/<RemoteClient\s+publicKey="([0-9a-fA-F]{64})"/);
  return {
    remoteKeyHex: remoteKeyMatch ? remoteKeyMatch[1] : '',
    remoteClientPublicKeyHex: remoteClientMatch ? remoteClientMatch[1] : ''
  };
}

function ipToString(buffer, offset) {
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}

function extractTcpStreams(pcap, serverPort) {
  let offset = 24;
  let synClientSeq = null;
  let synServerSeq = null;
  const clientToServerChunks = [];
  const serverToClientChunks = [];

  while (offset + 16 <= pcap.length) {
    const inclLen = pcap.readUInt32LE(offset + 8);
    const packetStart = offset + 16;
    const packetEnd = packetStart + inclLen;
    if (packetEnd > pcap.length) {
      break;
    }

    const packet = pcap.subarray(packetStart, packetEnd);
    offset = packetEnd;

    if (packet.length < 14) {
      continue;
    }

    const etherType = packet.readUInt16BE(12);
    if (etherType !== 0x0800) {
      continue;
    }

    const ipOffset = 14;
    const ipHeaderLength = (packet[ipOffset] & 0x0f) * 4;
    const protocol = packet[ipOffset + 9];
    if (protocol !== 6) {
      continue;
    }

    const _srcIp = ipToString(packet, ipOffset + 12);
    const _dstIp = ipToString(packet, ipOffset + 16);

    const tcpOffset = ipOffset + ipHeaderLength;
    if (tcpOffset + 20 > packet.length) {
      continue;
    }

    const srcPort = packet.readUInt16BE(tcpOffset);
    const dstPort = packet.readUInt16BE(tcpOffset + 2);
    const seq = packet.readUInt32BE(tcpOffset + 4);
    const flags = packet[tcpOffset + 13];
    const tcpHeaderLen = ((packet[tcpOffset + 12] >> 4) & 0x0f) * 4;
    const payloadOffset = tcpOffset + tcpHeaderLen;
    if (payloadOffset > packet.length) {
      continue;
    }
    const payload = packet.subarray(payloadOffset);

    const isSyn = (flags & 0x02) !== 0;
    if (isSyn && dstPort === serverPort && srcPort !== serverPort) {
      synClientSeq = seq;
    }
    if (isSyn && srcPort === serverPort && dstPort !== serverPort) {
      synServerSeq = seq;
    }

    if (dstPort === serverPort && srcPort !== serverPort && payload.length > 0) {
      clientToServerChunks.push({ seq, payload });
    } else if (
      srcPort === serverPort &&
      dstPort !== serverPort &&
      payload.length > 0
    ) {
      serverToClientChunks.push({ seq, payload });
    }
  }

  return {
    clientToServer: reassemble(clientToServerChunks, synClientSeq),
    serverToClient: reassemble(serverToClientChunks, synServerSeq)
  };
}

function reassemble(chunks, synSeq) {
  chunks.sort((a, b) => a.seq - b.seq);
  if (chunks.length === 0) {
    return Buffer.alloc(0);
  }

  let next = synSeq == null ? chunks[0].seq : (synSeq + 1) >>> 0;
  const out = [];
  for (const chunk of chunks) {
    let start = chunk.seq;
    let data = chunk.payload;

    const distance = (start - next) >>> 0;
    if (distance > 0x7fffffff) {
      continue;
    }
    if (distance > 0) {
      continue;
    }

    const overlap = (next - start) >>> 0;
    if (overlap >= data.length) {
      continue;
    }
    if (overlap > 0) {
      data = data.subarray(overlap);
    }

    out.push(data);
    next = (next + data.length) >>> 0;
  }

  return Buffer.concat(out);
}

function splitHttp(stream) {
  const marker = Buffer.from('\r\n\r\n');
  const idx = stream.indexOf(marker);
  if (idx < 0) {
    return { head: Buffer.alloc(0), body: stream };
  }
  return {
    head: stream.subarray(0, idx + marker.length),
    body: stream.subarray(idx + marker.length)
  };
}

function decodeWebSocketFrames(stream) {
  const frames = [];
  let i = 0;

  while (i + 2 <= stream.length) {
    const b1 = stream[i++];
    const b2 = stream[i++];
    const opcode = b1 & 0x0f;
    const masked = (b2 & 0x80) !== 0;
    let len = b2 & 0x7f;

    if (len === 126) {
      if (i + 2 > stream.length) {
        break;
      }
      len = stream.readUInt16BE(i);
      i += 2;
    } else if (len === 127) {
      if (i + 8 > stream.length) {
        break;
      }
      const hi = stream.readUInt32BE(i);
      const lo = stream.readUInt32BE(i + 4);
      i += 8;
      if (hi !== 0) {
        break;
      }
      len = lo;
    }

    let maskKey = null;
    if (masked) {
      if (i + 4 > stream.length) {
        break;
      }
      maskKey = stream.subarray(i, i + 4);
      i += 4;
    }

    if (i + len > stream.length) {
      break;
    }

    let payload = stream.subarray(i, i + len);
    i += len;

    if (masked && maskKey) {
      const unmasked = Buffer.alloc(payload.length);
      for (let j = 0; j < payload.length; j += 1) {
        unmasked[j] = payload[j] ^ maskKey[j % 4];
      }
      payload = unmasked;
    }

    frames.push({ opcode, payload });
  }

  return frames;
}

function extractClientPublicKeyFromRequestHead(head) {
  const text = head.toString('utf8');
  const firstLine = text.split('\r\n')[0] || '';
  const match = firstLine.match(/^GET\s+\/([0-9a-fA-F]{64})\s+HTTP\/1\.[01]$/);
  return match ? match[1].toLowerCase() : '';
}

function parseSecretstreamRecords(payload, hasHeader) {
  let offset = 0;
  let header = null;
  if (hasHeader) {
    if (payload.length < SECRETSTREAM_HEADER_BYTES) {
      return { header: null, records: [] };
    }
    header = payload.subarray(0, SECRETSTREAM_HEADER_BYTES);
    offset = SECRETSTREAM_HEADER_BYTES;
  }

  const records = [];
  while (offset + 2 <= payload.length) {
    const size = payload.readUInt16BE(offset);
    offset += 2;
    if (offset + size > payload.length) {
      break;
    }
    records.push(payload.subarray(offset, offset + size));
    offset += size;
  }
  return { header, records };
}

function extractClearPackets(buffer) {
  const packets = [];
  let cursor = 0;

  while (cursor < buffer.length && buffer[cursor] !== 0x3b) {
    cursor += 1;
  }

  while (cursor + 7 <= buffer.length) {
    if (buffer[cursor] !== 0x3b) {
      break;
    }

    const payloadLength = buffer.readUInt32BE(cursor + 3);
    const packetLength = payloadLength + 1;
    if (packetLength <= 0 || cursor + packetLength > buffer.length) {
      break;
    }

    packets.push(buffer.subarray(cursor, cursor + packetLength));
    cursor += packetLength;
  }

  return {
    packets,
    remainder: buffer.subarray(cursor)
  };
}

function formatRequestId(requestId) {
  return requestId == null ? 'n/a' : `0x${requestId.toString(16).padStart(8, '0')}`;
}

function formatItemId(itemId) {
  return itemId == null ? 'n/a' : `0x${itemId.toString(16).padStart(4, '0')}`;
}

function formatOp(op) {
  return op == null ? 'n/a' : `0x${op.toString(16).padStart(4, '0')}`;
}

function formatType(type) {
  return `0x${type.toString(16).padStart(2, '0')}`;
}

function describeAirItem(itemId, valueBytes, source) {
  const valueHex = valueBytes.toString('hex');

  if (itemId === AIR_ENABLED_ITEM_ID) {
    let airEnabled = null;
    if (source === 'write' && valueBytes.length >= 2) {
      airEnabled = valueBytes[1] === 0x01;
    } else if (source === 'notify' && valueBytes.length >= 2) {
      airEnabled = valueBytes[0] === 0x01;
    } else if (valueBytes.length >= 1) {
      airEnabled = valueBytes[valueBytes.length - 1] === 0x01;
    }

    return {
      kind: 'air-enabled',
      name: 'AIR enable',
      valueHex,
      human:
        airEnabled == null
          ? 'AIR enable (unknown)'
          : `AIR ${airEnabled ? 'ON' : 'OFF'}`,
      airEnabled
    };
  }

  if (itemId === AIR_MODE_ITEM_ID) {
    let airMode = null;
    if (source === 'write') {
      if (valueHex === '010000') {
        airMode = 1;
      } else if (valueHex === '010001') {
        airMode = 2;
      }
    } else if (source === 'notify') {
      if (valueHex === '000001') {
        airMode = 1;
      } else if (valueHex === '000101') {
        airMode = 2;
      }
    }

    return {
      kind: 'air-mode',
      name: 'AIR mode',
      valueHex,
      human:
        airMode === 1
          ? 'Presence'
          : airMode === 2
            ? 'Presence & Drive'
            : `AIR mode (unknown ${valueHex || 'empty'})`,
      airMode
    };
  }

  return null;
}

function parseWritePacket(packet) {
  if (packet.length < 26 || packet[7] !== 0x01) {
    return null;
  }

  const requestId = packet.readUInt32BE(14);
  const itemId = packet.readUInt32BE(18);
  const op = packet.readUInt16BE(22);
  const valueBytes = packet.subarray(26);
  const air = describeAirItem(itemId, valueBytes, 'write');

  return {
    packetType: 'write',
    requestId,
    itemId,
    op,
    valueBytes,
    air
  };
}

function parseAckPacket(packet) {
  if (packet.length < 20 || packet[7] !== 0x03) {
    return null;
  }

  return {
    packetType: 'ack',
    requestId: packet.readUInt32BE(14),
    status: packet.readUInt16BE(18)
  };
}

function parseNotifyPacket(packet) {
  if (packet.length < 20 || packet[7] !== 0x02) {
    return null;
  }

  const entries = [];
  for (const itemId of [AIR_ENABLED_ITEM_ID, AIR_MODE_ITEM_ID]) {
    const itemBytes = Buffer.alloc(4);
    itemBytes.writeUInt32BE(itemId, 0);
    const itemIndex = packet.indexOf(itemBytes);
    if (itemIndex < 0) {
      continue;
    }

    const opOffset = itemIndex + 8;
    const valueOffset = itemIndex + 12;
    if (valueOffset > packet.length) {
      continue;
    }

    const op = opOffset + 2 <= packet.length ? packet.readUInt16BE(opOffset) : null;
    const valueBytes = packet.subarray(valueOffset);
    entries.push({
      itemId,
      op,
      valueBytes,
      air: describeAirItem(itemId, valueBytes, 'notify')
    });
  }

  if (entries.length === 0) {
    return null;
  }

  return {
    packetType: 'notify',
    entries
  };
}

function parsePacketSummary(packet) {
  if (packet.length < 20) {
    return { type: -1, requestId: null, itemId: null, op: null, status: null };
  }

  const type = packet[7];
  const write = parseWritePacket(packet);
  if (write) {
    return {
      type,
      requestId: write.requestId,
      itemId: write.itemId,
      op: write.op,
      status: null,
      packetType: write.packetType,
      valueBytes: write.valueBytes,
      air: write.air,
      notifyEntries: []
    };
  }

  const ack = parseAckPacket(packet);
  if (ack) {
    return {
      type,
      requestId: ack.requestId,
      itemId: null,
      op: null,
      status: ack.status,
      packetType: ack.packetType,
      valueBytes: null,
      air: null,
      notifyEntries: []
    };
  }

  const notify = parseNotifyPacket(packet);
  if (notify) {
    const first = notify.entries[0];
    return {
      type,
      requestId: null,
      itemId: first.itemId,
      op: first.op,
      status: null,
      packetType: notify.packetType,
      valueBytes: first.valueBytes,
      air: first.air,
      notifyEntries: notify.entries
    };
  }

  const requestId = packet.readUInt32BE(14);
  const itemId = packet.length >= 22 ? packet.readUInt32BE(18) : null;
  const op = packet.length >= 24 ? packet.readUInt16BE(22) : null;
  const status = type === 0x03 && packet.length >= 20 ? packet.readUInt16BE(18) : null;

  return {
    type,
    requestId,
    itemId,
    op,
    status,
    packetType: 'generic',
    valueBytes: null,
    air: null,
    notifyEntries: []
  };
}

function shortHex(buffer, max = 80) {
  const hex = buffer.toString('hex');
  if (String(process.env.FOCUSRITE_FULL_HEX || '').toLowerCase() === 'true') {
    return hex;
  }
  return hex.length > max ? `${hex.slice(0, max)}...` : hex;
}

function formatPacketExtra(summary) {
  if (summary.packetType === 'write' && summary.valueBytes) {
    const parts = [`value=0x${summary.valueBytes.toString('hex') || 'empty'}`];
    if (summary.air) {
      parts.push(`${summary.air.name}="${summary.air.human}"`);
    }
    return ` ${parts.join(' ')}`;
  }

  if (summary.packetType === 'notify' && summary.notifyEntries.length > 0) {
    const parts = summary.notifyEntries.map((entry) => {
      const base = `${formatItemId(entry.itemId)} value=0x${entry.valueBytes.toString('hex') || 'empty'}`;
      if (entry.air) {
        return `${base} ${entry.air.name}="${entry.air.human}"`;
      }
      return base;
    });
    return ` notify=[${parts.join('; ')}]`;
  }

  return '';
}

function logDirection(name, frames, key) {
  const binaryFrames = frames.filter((f) => f.opcode === 0x2).map((f) => f.payload);
  console.log(`\n[${name}] binary frames=${binaryFrames.length}`);
  if (binaryFrames.length === 0) {
    return [];
  }

  const first = parseSecretstreamRecords(binaryFrames[0], true);
  if (!first.header || first.records.length === 0) {
    console.log('  first frame missing secretstream header or records');
    return [];
  }

  let pullState;
  try {
    pullState = sodium.crypto_secretstream_xchacha20poly1305_init_pull(first.header, key);
  } catch (error) {
    console.log(`  init_pull failed: ${error.message}`);
    return [];
  }

  const encryptedRecords = [...first.records];
  for (const payload of binaryFrames.slice(1)) {
    const parsed = parseSecretstreamRecords(payload, false);
    encryptedRecords.push(...parsed.records);
  }

  console.log(`  encrypted records=${encryptedRecords.length}`);

  let clearIndex = 0;
  let clearBuffer = Buffer.alloc(0);
  const events = [];
  for (const cipher of encryptedRecords) {
    let clear;
    try {
      const out = sodium.crypto_secretstream_xchacha20poly1305_pull(pullState, cipher, null);
      if (!out || !out.message) {
        continue;
      }
      clear = Buffer.from(out.message);
    } catch (error) {
      console.log(`  decrypt failed after ${clearIndex} records: ${error.message}`);
      break;
    }

    clearIndex += 1;
    if (clear.length === 32 && clear[0] !== 0x3b) {
      console.log(`  rec ${clearIndex}: handshake nonce ${shortHex(clear, 64)}`);
      continue;
    }

    clearBuffer = Buffer.concat([clearBuffer, clear]);
    const { packets, remainder } = extractClearPackets(clearBuffer);
    clearBuffer = remainder;

    if (packets.length === 0) {
      console.log(
        `  rec ${clearIndex}: buffered clear bytes=${clearBuffer.length} (awaiting full packet)`
      );
      continue;
    }

    for (const packet of packets) {
      const summary = parsePacketSummary(packet);
      const typeHex = formatType(summary.type);
      const requestHex = formatRequestId(summary.requestId);
      const itemHex = formatItemId(summary.itemId);
      const opHex = formatOp(summary.op);
      const status = summary.status == null ? '' : ` status=${summary.status}`;
      const extra = formatPacketExtra(summary);
      console.log(
        `  rec ${clearIndex}: packet type=${typeHex} req=${requestHex} item=${itemHex} op=${opHex}${status}${extra} len=${packet.length} hex=${shortHex(packet, 120)}`
      );

      if (summary.air && summary.packetType !== 'notify') {
        events.push({
          direction: name,
          record: clearIndex,
          kind: summary.packetType,
          requestId: summary.requestId,
          itemId: summary.itemId,
          op: summary.op,
          status: summary.status,
          valueHex: summary.valueBytes ? summary.valueBytes.toString('hex') : '',
          label: summary.air.human,
          itemName: summary.air.name
        });
      }

      for (const entry of summary.notifyEntries || []) {
        if (!entry.air) {
          continue;
        }
        events.push({
          direction: name,
          record: clearIndex,
          kind: 'notify',
          requestId: null,
          itemId: entry.itemId,
          op: entry.op,
          status: null,
          valueHex: entry.valueBytes.toString('hex'),
          label: entry.air.human,
          itemName: entry.air.name
        });
      }
    }
  }

  return events;
}

function printAirSummary(events) {
  const airEvents = events.filter((event) => event.itemId === AIR_ENABLED_ITEM_ID || event.itemId === AIR_MODE_ITEM_ID);
  if (airEvents.length === 0) {
    return;
  }

  console.log('\n=== AIR SUMMARY ===');
  for (const event of airEvents) {
    const req = event.requestId == null ? '' : ` req=${formatRequestId(event.requestId)}`;
    const op = event.op == null ? '' : ` op=${formatOp(event.op)}`;
    const status = event.status == null ? '' : ` status=${event.status}`;
    const value = event.valueHex ? ` value=0x${event.valueHex}` : '';
    console.log(
      `[${event.direction}] rec=${event.record} ${event.kind} item=${formatItemId(event.itemId)}${req}${op}${status}${value} ${event.itemName}="${event.label}"`
    );
  }
}

async function main() {
  await sodium.ready;

  const { pcapPath, serverPort, remoteKeyHex, remoteClientPublicKeyHex } = parseArgs();
  const pcap = fs.readFileSync(pcapPath);
  const streams = extractTcpStreams(pcap, serverPort);
  const req = splitHttp(streams.clientToServer);
  const res = splitHttp(streams.serverToClient);

  const clientPublicKeyHex =
    extractClientPublicKeyFromRequestHead(req.head) || remoteClientPublicKeyHex;
  if (!clientPublicKeyHex) {
    throw new Error(
      'Could not determine websocket client public key from HTTP GET path or settings.xml. ' +
        'Provide FOCUSRITE_REMOTE_CLIENT_PUBLIC_KEY or capture from before the websocket connects.'
    );
  }

  const serverSecret = Buffer.from(remoteKeyHex, 'hex');
  const serverPublic = Buffer.from(sodium.crypto_scalarmult_base(serverSecret));
  const clientPublic = Buffer.from(clientPublicKeyHex, 'hex');
  const sessionKeys = sodium.crypto_kx_server_session_keys(
    serverPublic,
    serverSecret,
    clientPublic
  );
  const sharedKey = Buffer.from(sessionKeys.sharedTx);

  const cFrames = decodeWebSocketFrames(req.body);
  const sFrames = decodeWebSocketFrames(res.body);

  console.log('=== REQUEST HEAD ===');
  console.log(req.head.toString('utf8'));
  console.log('=== RESPONSE HEAD ===');
  console.log(res.head.toString('utf8'));
  console.log(`sharedKey=${sharedKey.toString('hex')}`);

  const clientEvents = logDirection('client->server', cFrames, sharedKey);
  const serverEvents = logDirection('server->client', sFrames, sharedKey);
  printAirSummary([...clientEvents, ...serverEvents]);
}

main().catch((error) => {
  console.error(`[decodeSecurePcap] ${error.message}`);
  process.exit(1);
});

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const sodium = require('libsodium-wrappers');

const HEADER_BYTES = 24;

function parseArgs() {
  const pcapPath = process.argv[2] || process.env.FOCUSRITE_PCAP_PATH || '';
  if (!pcapPath) {
    throw new Error(
      'Missing pcap path. Usage: npm run decode:pcap -- /absolute/path/focusrite-58322.pcap'
    );
  }

  const serverPort = Number(process.env.FOCUSRITE_PORT || 58322);
  const keyHex = process.env.FOCUSRITE_REMOTE_KEY || readRemoteKeyFromSettings();

  if (!keyHex || keyHex.length !== 64) {
    throw new Error(
      'Missing or invalid FOCUSRITE_REMOTE_KEY (expect 64 hex chars).'
    );
  }

  return {
    pcapPath,
    serverPort,
    keyHex
  };
}

function readRemoteKeyFromSettings() {
  const settingsPath = path.join(
    process.env.HOME || '',
    'Library',
    'Application Support',
    'Focusrite',
    'Focusrite Control 2',
    'settings.xml'
  );

  if (!fs.existsSync(settingsPath)) {
    return '';
  }

  const xml = fs.readFileSync(settingsPath, 'utf8');
  const match = xml.match(/<RemoteConnection\s+key="([0-9a-fA-F]{64})"/);
  return match ? match[1] : '';
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

function decodeWebSocketFrames(stream, fromClient) {
  const frames = [];
  let i = 0;

  while (i + 2 <= stream.length) {
    const b1 = stream[i++];
    const b2 = stream[i++];
    const fin = (b1 & 0x80) !== 0;
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

    frames.push({
      fromClient,
      fin,
      opcode,
      payload
    });
  }

  return frames;
}

function printableText(buf) {
  if (buf.length === 0) {
    return '';
  }
  const printable = buf.every(
    (v) => v === 9 || v === 10 || v === 13 || (v >= 32 && v < 127)
  );
  return printable ? buf.toString('utf8') : '';
}

function tryDecryptDirection(name, frames, key) {
  const binaryFrames = frames.filter((f) => f.opcode === 2).map((f) => f.payload);
  if (binaryFrames.length === 0) {
    console.log(`\n[${name}] no binary frames`);
    return;
  }

  const first = binaryFrames[0];
  if (first.length <= HEADER_BYTES) {
    console.log(`\n[${name}] first frame too short for secretstream header`);
    return;
  }

  const header = first.subarray(0, HEADER_BYTES);
  const firstCipher = first.subarray(HEADER_BYTES);

  let state;
  try {
    state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
  } catch (error) {
    console.log(`\n[${name}] init_pull failed: ${error.message}`);
    return;
  }

  console.log(`\n[${name}] trying secretstream decrypt, frames=${binaryFrames.length}`);
  const payloads = [firstCipher, ...binaryFrames.slice(1)];
  let okCount = 0;

  for (let i = 0; i < payloads.length; i += 1) {
    const cipher = payloads[i];
    try {
      const out = sodium.crypto_secretstream_xchacha20poly1305_pull(
        state,
        cipher,
        null
      );
      if (!out || !out.message) {
        console.log(`  frame ${i + 1}: decrypt returned no message`);
        break;
      }
      okCount += 1;
      const msg = Buffer.from(out.message);
      const text = printableText(msg);
      console.log(
        `  frame ${i + 1}: ok tag=${out.tag} bytes=${msg.length} ${text ? `text="${text.slice(0, 120)}"` : `hex=${msg.toString('hex').slice(0, 120)}`}`
      );
    } catch (error) {
      console.log(
        `  frame ${i + 1}: decrypt failed (${error.message})`
      );
      break;
    }
  }

  if (okCount === 0) {
    console.log(`  no frames decrypted with this key`);
  }
}

async function main() {
  await sodium.ready;
  const args = parseArgs();
  const key = Buffer.from(args.keyHex, 'hex');
  const pcap = fs.readFileSync(args.pcapPath);

  const streams = extractTcpStreams(pcap, args.serverPort);
  const req = splitHttp(streams.clientToServer);
  const res = splitHttp(streams.serverToClient);

  console.log('=== REQUEST HEAD ===');
  console.log(req.head.toString('utf8'));
  console.log('=== RESPONSE HEAD ===');
  console.log(res.head.toString('utf8'));

  const cFrames = decodeWebSocketFrames(req.body, true);
  const sFrames = decodeWebSocketFrames(res.body, false);

  console.log(
    `frames: client->server=${cFrames.length}, server->client=${sFrames.length}`
  );

  tryDecryptDirection('client->server', cFrames, key);
  tryDecryptDirection('server->client', sFrames, key);
}

main().catch((error) => {
  console.error(`[decodeCapture] ${error.message}`);
  process.exit(1);
});

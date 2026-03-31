'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const DISCOVERY_PORTS = [30096, 30097, 30098];

function parseBoolean(value, defaultValue = false) {
  if (value == null || value === '') {
    return defaultValue;
  }
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(normalized)) {
    return false;
  }
  return defaultValue;
}

function parseNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function timestampForFilename(date = new Date()) {
  const iso = date.toISOString().replace(/[:]/g, '-');
  return iso.replace(/\.\d{3}Z$/, 'Z');
}

function defaultCapturePath() {
  const filename = `focusrite-${timestampForFilename()}.pcap`;
  return path.join(process.cwd(), 'captures', filename);
}

function guessInterface(host) {
  const normalizedHost = String(host || '').trim().toLowerCase();
  if (!normalizedHost || normalizedHost === '127.0.0.1' || normalizedHost === 'localhost') {
    return 'lo0';
  }
  return 'en0';
}

function buildFilter({ port, host, includeDiscovery }) {
  const clauses = [`tcp port ${port}`];

  if (includeDiscovery) {
    clauses.push(
      `udp port ${DISCOVERY_PORTS[0]} or udp port ${DISCOVERY_PORTS[1]} or udp port ${DISCOVERY_PORTS[2]}`
    );
  }

  let filter = clauses.length === 1 ? clauses[0] : `(${clauses.join(' or ')})`;
  const normalizedHost = String(host || '').trim();
  if (normalizedHost) {
    filter = `${filter} and host ${normalizedHost}`;
  }
  return filter;
}

function ensureParentDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function writeMetadata(outputPath, metadata) {
  const sidecarPath = `${outputPath}.json`;
  fs.writeFileSync(sidecarPath, JSON.stringify(metadata, null, 2));
  return sidecarPath;
}

function parseArgs() {
  const outputPath = path.resolve(process.argv[2] || process.env.FOCUSRITE_CAPTURE_PATH || defaultCapturePath());
  const host =
    process.env.FOCUSRITE_CAPTURE_PEER_IP ||
    process.env.FOCUSRITE_CAPTURE_PHONE_IP ||
    process.env.FOCUSRITE_CAPTURE_HOST ||
    process.env.FOCUSRITE_SECURE_WS_HOST ||
    '';
  const interfaceName =
    process.env.FOCUSRITE_CAPTURE_INTERFACE || guessInterface(host);
  const port = parseNumber(
    process.env.FOCUSRITE_CAPTURE_PORT || process.env.FOCUSRITE_SECURE_WS_PORT || process.env.FOCUSRITE_PORT || 58322,
    58322
  );
  const durationMs = parseNumber(process.env.FOCUSRITE_CAPTURE_DURATION_MS || 0, 0);
  const includeDiscovery = parseBoolean(process.env.FOCUSRITE_CAPTURE_INCLUDE_DISCOVERY, false);
  const extraArgs = String(process.env.FOCUSRITE_CAPTURE_TCPDUMP_ARGS || '')
    .split(/\s+/)
    .map((part) => part.trim())
    .filter(Boolean);
  const tcpdumpPath = process.env.FOCUSRITE_TCPDUMP_PATH || 'tcpdump';
  const filter = process.env.FOCUSRITE_CAPTURE_FILTER || buildFilter({ port, host, includeDiscovery });

  return {
    outputPath,
    interfaceName,
    port,
    host,
    filter,
    durationMs,
    includeDiscovery,
    extraArgs,
    tcpdumpPath
  };
}

function buildTcpdumpArgs({ interfaceName, outputPath, extraArgs, filter }) {
  return ['-i', interfaceName, '-s', '0', '-U', '-n', '-w', outputPath, ...extraArgs, filter];
}

async function main() {
  const options = parseArgs();
  ensureParentDir(options.outputPath);

  const tcpdumpArgs = buildTcpdumpArgs(options);
  const metadata = {
    createdAt: new Date().toISOString(),
    outputPath: options.outputPath,
    interface: options.interfaceName,
    port: options.port,
    host: options.host || null,
    filter: options.filter,
    includeDiscovery: options.includeDiscovery,
    durationMs: options.durationMs,
    tcpdumpCommand: [options.tcpdumpPath, ...tcpdumpArgs].join(' ')
  };
  const metadataPath = writeMetadata(options.outputPath, metadata);

  console.log(`[capture] writing packets to ${options.outputPath}`);
  console.log(`[capture] metadata written to ${metadataPath}`);
  console.log(`[capture] interface=${options.interfaceName} filter=${options.filter}`);
  console.log('[capture] stop with Ctrl+C or wait for duration timeout.');
  console.log(
    `[capture] decode later with: npm run decode:pcap:secure -- ${JSON.stringify(options.outputPath)}`
  );

  const child = spawn(options.tcpdumpPath, tcpdumpArgs, {
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let settled = false;
  let sawPermissionHint = false;
  let childError = null;

  const stopCapture = (signal = 'SIGINT') => {
    if (child.exitCode == null && !child.killed) {
      child.kill(signal);
    }
  };

  const finish = (code, signal) => {
    if (settled) {
      return;
    }
    settled = true;

    if (options.durationMs > 0) {
      clearTimeout(durationTimer);
    }

    process.off('SIGINT', onSigint);
    process.off('SIGTERM', onSigterm);

    if (signal) {
      console.log(`[capture] stopped by signal ${signal}`);
      return;
    }

    if (code === 0) {
      console.log('[capture] tcpdump exited cleanly');
      return;
    }

    if (childError) {
      throw childError;
    }

    if (sawPermissionHint) {
      throw new Error(
        'tcpdump could not start capture. On macOS you may need sudo/root or packet capture permissions.'
      );
    }

    throw new Error(`tcpdump exited with code ${code}`);
  };

  child.stdout.on('data', (chunk) => {
    const text = chunk.toString().trim();
    if (text) {
      console.log(`[tcpdump] ${text}`);
    }
  });

  child.stderr.on('data', (chunk) => {
    const text = chunk.toString().trim();
    if (!text) {
      return;
    }
    const normalized = text.toLowerCase();
    if (
      normalized.includes('permission denied') ||
      normalized.includes('operation not permitted') ||
      normalized.includes('cannot open bpf device')
    ) {
      sawPermissionHint = true;
    }
    console.error(`[tcpdump] ${text}`);
  });

  child.on('error', (error) => {
    childError = error;
  });

  const childExit = new Promise((resolve, reject) => {
    child.on('exit', (code, signal) => {
      try {
        finish(code, signal);
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  });

  const onSigint = () => {
    console.log('[capture] SIGINT received, stopping capture...');
    stopCapture('SIGINT');
  };
  const onSigterm = () => {
    console.log('[capture] SIGTERM received, stopping capture...');
    stopCapture('SIGTERM');
  };

  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);

  const durationTimer =
    options.durationMs > 0
      ? setTimeout(() => {
          console.log(`[capture] duration reached (${options.durationMs} ms), stopping capture...`);
          stopCapture('SIGINT');
        }, options.durationMs)
      : null;

  await childExit;
}

main().catch((error) => {
  console.error(`[capture] ${error.message}`);
  process.exit(1);
});

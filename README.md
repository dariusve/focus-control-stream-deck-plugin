# Focusrite Scarlett Solo 4th Gen + Stream Deck Starter

This repository gives you a practical baseline to control a Scarlett Solo 4th Gen from Stream Deck using JavaScript:

- `bridge/`: local Node.js HTTP service
- `plugin/com.dario.focusrite.scarlett.sdPlugin/`: Stream Deck plugin action

## Important note

Focusrite does not currently provide an official public JavaScript API for Scarlett control. This starter uses a bridge design so you can keep hardware-specific logic isolated in one place.

## 1) Run the bridge

```bash
cd bridge
npm install
npm run dev
```

Environment variables (optional):

- `BRIDGE_HOST` default: `127.0.0.1`
- `BRIDGE_PORT` default: `9123`
- `SIMULATE` default: `true`
- `FOCUSRITE_DEVICE_ID` default: `1`
- `FOCUSRITE_SERVER_PORT` default: auto-discover (set this to skip UDP discovery)
- `FOCUSRITE_SERVER_HOST` default: `127.0.0.1`
- `FOCUSRITE_SERVER_PORT_CANDIDATES` default: `50000,5000,7000,58322,58323` (fallback ports to probe if discovery fails)
- `FOCUSRITE_DISCOVERY_HOST` default: `255.255.255.255` (you can set `127.0.0.1` for local testing)
- `FOCUSRITE_AIR_ITEM_IDS` default: `1:23` (format: `channel:itemId`, comma separated)
- `FOCUSRITE_TRANSPORT` default: `auto` (`auto`, `secure`, `legacy`)
- `FOCUSRITE_REMOTE_KEY` optional override for Control 2 remote key (64 hex chars)
- `FOCUSRITE_REMOTE_CLIENT_PUBLIC_KEY` optional override for authorized remote client public key (64 hex chars)
- `FOCUSRITE_SECURE_WS_HOST` default: `127.0.0.1`
- `FOCUSRITE_SECURE_WS_PORT` default: `58322`
- `FOCUSRITE_SECURE_AIR_ITEMS` default: `1:0x1023:0x1024` (format: `channel:airOnItemId:airModeItemId`)
- `FOCUSRITE_SECURE_BOOTSTRAP` default: `known` (`known`, `none`)
- `FOCUSRITE_SECURE_BOOTSTRAP_FALLBACK` default: `true` (if bootstrap fails, retry once with a fresh session, then continue that command with direct secure AIR writes)
- `FOCUSRITE_SECURE_BOOTSTRAP_REQUEST_TIMEOUT_MS` default: `6000`
- `FOCUSRITE_SECURE_STATE_CONFIRM_TIMEOUT_MS` default: `2200`
- `FOCUSRITE_SECURE_KEEPALIVE_BURST` default: `3` (sends N keepalive packets before and after AIR writes to mirror Control 2 client behavior)
- `FOCUSRITE_SECURE_COMMAND_TIMEOUT_MS` default: `12000` (hard timeout for one full secure AIR command, including handshake + ACK waits)
- `FOCUSRITE_SECURE_REQUIRE_STATE_CONFIRM` default: `false` (if `true`, missing state-notify packets are treated as errors)
- `FOCUSRITE_SECURE_AIR_MODE_WRITE_ENCODING` default: `little` (`little`, `big`)
- `FOCUSRITE_SECURE_RESET_SESSION_EACH_COMMAND` default: `true` (opens/sends/closes per command for better stability)
- `FOCUSRITE_DEBUG` default: `false` (logs discovery/connect/packet activity)
- `FOCUSRITE_CONNECT_TIMEOUT_MS` default: `1200`
- `FOCUSRITE_PROBE_TIMEOUT_MS` default: `1200`

Health check:

```bash
curl http://127.0.0.1:9123/health
```

Test command:

```bash
curl -X POST http://127.0.0.1:9123/api/v1/focusrite/air/toggle \
  -H 'Content-Type: application/json' \
  -d '{"channel":1}'
```

## 2) Install plugin in Stream Deck

Copy:

- `plugin/com.dario.focusrite.scarlett.sdPlugin`

To:

- macOS: `~/Library/Application Support/com.elgato.StreamDeck/Plugins/`
- Windows: `%APPDATA%\Elgato\StreamDeck\Plugins\`

Then restart Stream Deck.

## 3) Use the action

1. Add **Focusrite -> Scarlett Air** action to a key.
2. In Property Inspector, set:
   - Bridge Host (usually `127.0.0.1`)
   - Bridge Port (`9123`)
   - Command (`toggle`, `enable`, `disable`)
   - Channel (`1` for Solo input 1)
3. Press the key.

The key title changes based on bridge response:

- Secure Control 2 mode: `AIR OFF`, `AIR 1`, `AIR 2`
- Legacy mode: `AIR ON` / `AIR OFF`

For Scarlett Solo 4th Gen secure transport, `toggle` cycles:

- `AIR OFF -> AIR 1 (Presence) -> AIR 2 (Presence + Drive) -> AIR OFF`

## 4) Use real hardware transport

- The adapter now supports:
  - Focusrite Control 2 secure websocket transport (default in `auto` mode when keys are available from `settings.xml`)
  - Legacy Focusrite ControlServer transport (UDP discovery + TCP XML commands)
- To use real transport, run with:

```bash
SIMULATE=false npm run dev
```

- Ensure Focusrite Control / Focusrite Control 2 is running.
- For Control 2 secure mode, keep an authorized phone/client in `Remote Devices` so a `RemoteClient publicKey` exists in `settings.xml`.
- If you want to force a mode:
  - `FOCUSRITE_TRANSPORT=secure`
  - `FOCUSRITE_TRANSPORT=legacy`
- For legacy mode, if discovery fails on your setup, set `FOCUSRITE_SERVER_PORT` manually.

Adapter file:

- `bridge/src/focusriteAdapter.js`

## 5) Probe Focusrite WebSocket (macOS)

If Focusrite Control 2 exposes a WebSocket (for example `127.0.0.1:58322`), run:

```bash
cd bridge
npm run probe:ws
```

Useful env vars:

- `FOCUSRITE_WS_URL` default: `ws://127.0.0.1:58322`
- `FOCUSRITE_WS_AUTH_MODE` one of: `none`, `raw`, `json`, `xml`
- `FOCUSRITE_CLIENT_KEY` optional pairing key/token
- `FOCUSRITE_WS_SEND_RAW` optional raw frame to send immediately
- `FOCUSRITE_WS_SEND_JSON` optional JSON object string to send immediately
- `FOCUSRITE_WS_SEND_HEX` optional binary frame payload as hex
- `FOCUSRITE_WS_SUBSCRIBE_RAW` optional subscription frame
- `FOCUSRITE_WS_CLOSE_AFTER_MS` default: `15000`

## 6) Decode Captured WS Traffic

Capture a pcap first:

```bash
cd bridge
npm run capture:pcap
```

Useful capture env vars:

- `FOCUSRITE_CAPTURE_INTERFACE` default: inferred from host (`lo0` for localhost, otherwise `en0`)
- `FOCUSRITE_CAPTURE_PHONE_IP` optional phone/peer IP filter
- `FOCUSRITE_CAPTURE_PEER_IP` optional alias for the same phone/peer IP filter
- `FOCUSRITE_CAPTURE_HOST` optional generic host filter
- `FOCUSRITE_CAPTURE_PORT` default: `58322`
- `FOCUSRITE_CAPTURE_DURATION_MS` optional auto-stop timeout
- `FOCUSRITE_CAPTURE_INCLUDE_DISCOVERY` default: `false` (include UDP discovery ports `30096-30098`)
- `FOCUSRITE_CAPTURE_FILTER` optional full tcpdump filter override
- `FOCUSRITE_CAPTURE_PATH` optional pcap output path
- `FOCUSRITE_CAPTURE_TCPDUMP_ARGS` optional extra raw `tcpdump` args

Examples:

```bash
cd bridge
FOCUSRITE_CAPTURE_INTERFACE=lo0 FOCUSRITE_CAPTURE_DURATION_MS=15000 npm run capture:pcap
```

```bash
cd bridge
FOCUSRITE_CAPTURE_INTERFACE=en0 \
FOCUSRITE_CAPTURE_PHONE_IP=192.168.1.30 \
FOCUSRITE_CAPTURE_DURATION_MS=20000 \
npm run capture:pcap
```

The capture script writes a `.pcap` plus a small `.json` sidecar under `bridge/captures/` and prints the exact decode command to run next.

Use `settings.xml` remote key (auto-read) to test decryption of a pcap:

```bash
cd bridge
npm run decode:pcap -- /absolute/path/focusrite-58322.pcap
```

For Control 2 secure websocket captures (correct key-derivation from ws URL public key + remote key):

```bash
cd bridge
npm run decode:pcap:secure -- /absolute/path/focusrite-58322.pcap
```

Optional overrides:

- `FOCUSRITE_PCAP_PATH`
- `FOCUSRITE_PORT` (default `58322`)
- `FOCUSRITE_REMOTE_KEY` (64 hex chars)

## 7) LLDB Script

Prepared breakpoint script:

- `bridge/scripts/focusrite-lldb.txt`

# GhostNet

Zero-client tether hiding for Android. No root required. Connecting devices need nothing installed.

## How it works

GhostNet runs a local VPN service on the host device that intercepts all forwarded tether traffic before it reaches the carrier:

- **TTL normalization** — rewrites every packet's TTL to 64, matching phone-originated traffic. Carriers detect tethering by looking for TTL values of 63 or 127 (decremented by 1 from the tethered device).
- **User-Agent scrubbing** — strips desktop/console UA strings from HTTP traffic and replaces with a mobile UA. Covers Windows, macOS, Linux, PlayStation, Xbox, Nintendo signatures.
- **DNS via 1.1.1.1** — routes all DNS through Cloudflare, bypasses carrier DNS leak detection.
- **Zero client footprint** — connecting device uses the hotspot normally. No app, no config, no VPN approval prompt on the connected device.

## What PdaNet does that GhostNet improves on

| Feature | PdaNet | GhostNet |
|---|---|---|
| TTL normalization | No | Yes — all protocols |
| UA scrubbing | HTTP only | HTTP only (HTTPS is encrypted) |
| Client requirement | PdaNet client app | Nothing |
| Activation server | Yes | No — ships unlocked |
| Discovery protocol | UDP 8000 handshake | None |
| DNS leak prevention | No | Yes — 1.1.1.1 |

## Requirements

- Android 8.0+ (API 26+)
- No root required
- Works with WiFi hotspot, USB tethering, Bluetooth DUN

## Build

```bash
./gradlew assembleRelease
```

## Architecture

```
GhostVpnService.kt   — TUN interface, packet loop, TTL + UA rewriting
MainActivity.kt      — Single toggle UI, VPN permission request
```

## Limitations

HTTPS traffic UA cannot be scrubbed — the payload is encrypted. TTL normalization covers all protocols including HTTPS. Carrier deep packet inspection on encrypted traffic relies primarily on TTL — this covers that surface.

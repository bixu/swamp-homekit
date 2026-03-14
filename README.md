# swamp-homekit

Pure TypeScript [HomeKit Accessory Protocol](https://developer.apple.com/homekit/) implementation for [swamp](https://github.com/systeminit/swamp).

Discover, pair with, and read sensor data from HomeKit accessories on your local network — no native dependencies, no Homebridge, no Apple SDK.

## Features

- **mDNS discovery** via `bonjour-service` — find all HomeKit accessories on the network
- **HAP pairing** — SRP-6a + Ed25519 key exchange using `@noble/*` crypto
- **Encrypted sessions** — X25519 + ChaCha20-Poly1305 per the HAP spec
- **Sensor reading** — temperature, humidity, air quality, light level, motion, and more

Everything bundles into a single ~86KB extension with zero native dependencies.

## Install

```bash
swamp extension pull @bixu/homekit
```

Or clone this repo into your swamp project:

```bash
git clone https://github.com/bixu/swamp-homekit.git
cp -r swamp-homekit/extensions/models/homekit*.ts your-project/extensions/models/
```

## Usage

### Create a HomeKit model instance

```bash
swamp model create @bixu/homekit home
```

### Discover accessories

```bash
swamp model method run home discover --json
```

### Pair with an accessory

```bash
swamp model method run home pair \
  --input accessoryName="HomePod" \
  --input setupCode="123-45-678" \
  --json
```

### Read sensor data

```bash
swamp model method run home readSensors \
  --input accessoryName="HomePod" \
  --json
```

## Architecture

The HAP protocol is implemented from scratch in pure TypeScript:

| Component | Implementation |
|-----------|---------------|
| mDNS/DNS-SD | `npm:bonjour-service` |
| SRP-6a (3072-bit) | Native `BigInt` + `@noble/hashes` (SHA-512) |
| Ed25519 signing | `@noble/curves` |
| X25519 key exchange | `@noble/curves` |
| HKDF key derivation | `@noble/hashes` |
| ChaCha20-Poly1305 | `@noble/ciphers` |
| TLV8 encoding | Custom implementation |

## Development

```bash
deno fmt --check    # format check
deno lint           # lint
deno test --no-check --allow-env  # tests
```

## License

MIT

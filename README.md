# 🏓 TPing

**Ping for Telegram Proxies** - Test connectivity to Telegram Proxies, just like `ping` for IP addresses.

A simple and clean CLI tool to continuously ping Telegram proxies (MTProto and SOCKS5) and measure latency in real-time using official Telegram API.

---

## ✨ Features

- 🏓 **Continuous ping mode** - Like standard `ping` command
- 🔄 **Multiple proxies** - Ping simultaneously
- ⚙️ **Configurable** - Custom count and interval
- 📊 **Statistics** - min/avg/max latency, packet loss
- 🚀 **Simple & clean** - Easy to use

---

## 📦 Installation

```bash
npm install -g @erfan_bahramali/tping
```

Or use directly with npx:

```bash
npx @erfan_bahramali/tping <proxy>
```

---

## 🚀 Usage

You can pass proxy as text or file path. For multiple proxies, separate by newlines (in text or file).

```bash
# Single proxy
tping "https://t.me/proxy?server=proxy.example.com&port=443&secret=0123456789abcdef"

# Multiple proxies
tping "https://t.me/proxy?server=proxy1.com&port=443&secret=abc
https://t.me/socks?server=proxy2.com&port=1080"

# From file (single or multiple proxies)
tping proxies.txt

# Ping 5 times
tping -c 5 "https://t.me/socks?server=proxy.example.com&port=1080"

# Ping unlimited times with custom interval (500ms)
tping -i 500 "https://t.me/socks?server=proxy.example.com&port=1080"

# Ping 10 times with custom interval (500ms)
tping -c 10 -i 500 proxies.txt
```

---

## ⚙️ Options

| Option | Description |
|--------|-------------|
| `-c, --count <n>` | Number of pings to send (default: unlimited) |
| `-i, --interval <ms>` | Interval between pings in milliseconds (default: 1000) |
| `-t, --timeout <ms>` | Timeout for each ping in milliseconds (default: 10000) |
| `-v, --version` | Show version number |
| `-h, --help` | Show help |

---

## 📊 Example Output

```
🏓 PING proxy.example.com:443 (MTProto)
Sending pings with 1000ms interval... (Press Ctrl+C to stop)

✓ proxy.example.com:443 │ MTProto │ seq=1 │ 45ms
✓ proxy.example.com:443 │ MTProto │ seq=2 │ 48ms
✓ proxy.example.com:443 │ MTProto │ seq=3 │ 43ms
^C
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Statistics for proxy.example.com:443
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Packets: 3 sent │ 3 received │ 0% loss
Latency: 43ms min │ 45ms avg │ 48ms max
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 🔍 How it Works

tping performs a **real MTProto handshake** through the proxy — the same first
step every official Telegram client does:

1. **Transport obfuscation** — a 64-byte header is generated with AES-256-CTR
   keys derived from the proxy secret (per the official
   [MTProto transport obfuscation](https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation)).
2. **Fake TLS** (secrets with `ee` prefix) — a TLS 1.3 ClientHello with a valid
   HMAC digest is sent; the proxy's signed ServerHello is verified before any
   data is trusted. Wrong secrets are detected immediately.
3. **MTProto ping** — a `req_pq_multi` request is sent through the proxy to the
   Telegram datacenter. The measured latency is the round trip of receiving a
   valid `resPQ` reply with our echoed nonce. A proxy only passes if the
   datacenter actually answers — dead or fake proxies are reported as failures,
   never as successes.

SOCKS5 proxies are checked by negotiating a connection to a Telegram datacenter
through them.

---

## 📋 License

MIT © 2026 [ErfanBahramali](https://github.com/ErfanBahramali)

---
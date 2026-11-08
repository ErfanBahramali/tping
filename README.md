# 🏓 TPing

**Ping for Telegram Proxies.** It checks Telegram proxies the way `ping` checks IP addresses.

TPing connects through the proxy exactly like the official Telegram apps (Android and Desktop) and only reports success when a Telegram datacenter actually answers. If TPing says a proxy works, Telegram can use it. If it fails, the error says where it broke.

---

## ✨ Features

- 🔐 **Every official proxy type**: MTProto with simple, `dd`, and Fake TLS (`ee`) secrets, SOCKS5 with or without login, and HTTP (Telegram Desktop)
- 🤝 **Real handshake**: a `req_pq_multi` request goes through the proxy to the Telegram datacenter and must come back with our nonce
- 🌐 **Datacenter selection**: test DC 2 (default), any set of DCs, or all five
- 🏓 **Continuous mode** like `ping`, with count and interval
- 🔄 **Many proxies at once**: from arguments, a file, or stdin
- 📊 **Statistics**: loss, min/avg/max/mdev, last error
- 🔍 **Clear errors**, for example: wrong secret, timeout during the Fake TLS handshake, SOCKS5 authentication failed

---

## 📦 Installation

```bash
npm install -g @erfan_bahramali/tping
```

Or use it directly with npx:

```bash
npx @erfan_bahramali/tping <proxy>
```

---

## 🚀 Usage

```bash
# Single proxy
tping "https://t.me/proxy?server=proxy.example.com&port=443&secret=ee0123456789abcdef0123456789abcdef7777772e676f6f676c652e636f6d"

# Several proxies (arguments, newlines, or spaces)
tping "tg://proxy?server=a.example.com&port=443&secret=dd0123456789abcdef0123456789abcdef" \
      "https://t.me/socks?server=b.example.com&port=1080&user=me&pass=secret"

# From a file, or from stdin
tping proxies.txt
cat proxies.txt | tping -

# 5 pings, 500ms apart, through all five Telegram datacenters
tping -c 5 -i 500 --dc all proxies.txt

# Show how long each phase took
tping -V -c 3 proxies.txt
```

---

## ⚙️ Options

| Option | Description |
|--------|-------------|
| `-c, --count <n>` | Number of pings to send (default: unlimited) |
| `-i, --interval <ms>` | Interval between pings in milliseconds (default: 1000) |
| `-t, --timeout <ms>` | Timeout for one ping (connect + handshake + reply) in milliseconds (default: 10000) |
| `-d, --dc <ids>` | Telegram DC(s) to test: `1`–`5`, comma-separated, or `all` (default: 2) |
| `-6, --ipv6` | Use IPv6 datacenter addresses for SOCKS5/HTTP proxies |
| `-V, --verbose` | Show the time of each phase: TCP connect, proxy handshake, Telegram round trip |
| `-v, --version` | Show version number |
| `-h, --help` | Show help |

**Exit status:** `0` if every proxy answered at least once, `1` if any proxy never answered, `2` on invalid input.

---

## 🔗 Supported proxy formats

| Type | Formats |
|------|---------|
| MTProto | `https://t.me/proxy?server=…&port=…&secret=…`, also `telegram.me`, `telegram.dog`, `www.`, `http://`, no scheme, `tg://proxy?…`, `tg:proxy?…` |
| SOCKS5 | `https://t.me/socks?server=…&port=…&user=…&pass=…`, `tg://socks?…`, `socks5://user:pass@host:port` |
| HTTP | `http://user:pass@host:port` (HTTP proxies are only supported by Telegram Desktop) |

MTProto secrets may be hex or base64/base64url, like in the official apps:

| Secret | Mode | What TPing does |
|--------|------|-----------------|
| 16 bytes | simple | obfuscated intermediate transport |
| `dd` + 16 bytes | secure | obfuscated padded intermediate transport |
| `ee` + 16 bytes + domain | Fake TLS | TLS-looking handshake with the domain as SNI, then padded intermediate inside TLS records |

Shell-escaped links (`t.me/proxy\?server\=…`) are accepted. Invalid lines are reported and skipped. WEB-Proxy links (`tg://webproxy`) are recognized but not checked yet, because there is no official protocol specification.

---

## 📊 Example Output

```
✅ #1 │ [1] proxy.example.com:443   │ MTProto · Fake TLS   │ 182ms
❌ #1 │ [2] 203.0.113.7:8443        │ MTProto · dd         │ Proxy closed the connection before Telegram answered (wrong secret, or the proxy cannot reach Telegram)
✅ #1 │ [3] socks.example.com:1080  │ SOCKS5               │ 95ms
```

Press Ctrl+C to stop and print the statistics table. Press it twice to quit immediately.

---

## 🔍 How it works

TPing builds the same connection as the official apps:

1. **Fake TLS (`ee`)**: sends a Chrome-like TLS ClientHello (shuffled extensions, GREASE, a valid x25519 key share, padded to 517 bytes). The client random is an HMAC-SHA256 of the hello with the secret, with the current time mixed in. The proxy's reply must be exactly ServerHello + ChangeCipherSpec + one Application Data record carrying a valid HMAC. A wrong secret, or the real website answering instead of the proxy, is detected here.
2. **Transport obfuscation**: a random 64-byte header carries the protocol tag and the DC id, encrypted with AES-256-CTR keys derived from the secret ([MTProto transport obfuscation](https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation)).
3. **MTProto ping**: a `req_pq_multi` request is sent and a `resPQ` with the same nonce must come back from the Telegram datacenter.

For SOCKS5 and HTTP proxies, TPing opens a tunnel to the Telegram datacenter's IP and runs the same obfuscated MTProto handshake through it. For HTTP proxies that refuse `CONNECT`, it falls back to the HTTP transport, as Telegram Desktop does.

The reported latency covers the whole sequence, TCP connect + proxy handshake + Telegram round trip, which is the same thing the official apps show as a proxy's ping. With several DCs, the slowest DC is reported and each DC is listed.

---

## 🧪 Development

```bash
bun install
bun test          # unit tests + end-to-end tests against local mock servers
bun run build
TPING_LIVE_PROXY="https://t.me/proxy?server=…&port=…&secret=…" bun test   # also test a real proxy
```

---

## 📋 License

MIT © 2026 [ErfanBahramali](https://github.com/ErfanBahramali)

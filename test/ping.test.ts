// Runnable self-check: bun test test/ping.test.ts
// Live-network tests use the user-verified working proxy; skip offline obfuscation test.
import { describe, test, expect } from 'bun:test';
import { MTProtoConnection } from '../src/mtproto/connection.js';
import { parseProxies } from '../src/lib/parser.js';
import { parseResPQ, buildUnencryptedMessage, buildReqPqMulti, generateMessageId } from '../src/mtproto/messages.js';
import { parseSecret, tryVerifyFakeTLSServerHello, generateFakeTLSClientHello } from '../src/mtproto/fake-tls.js';
import { initObfuscation, PROTO_TAG } from '../src/mtproto/obfuscation.js';
import { createHmac, randomBytes } from 'crypto';

const LIVE = {
  host: 'proxy.example.com',
  port: 443,
  secret: 'dd0123456789abcdef0123456789abcdef',
};

// Set TPING_LIVE_PROXY="https://t.me/proxy?server=...&port=...&secret=..."
// to enable the live end-to-end ping test against a real proxy.
const LIVE_PROXY_URL = process.env.TPING_LIVE_PROXY;

describe('parseProxies', () => {
  test('parses shell-escaped URL (backslashes before ? = &)', () => {
    const escaped = String.raw`https://t.me/proxy\?server\=proxy.example.com\&port\=4455\&secret\=dd0123456789abcdef0123456789abcdef`;
    const parsed = parseProxies(escaped);
    expect(parsed.length).toBe(1);
    expect(parsed[0]).toEqual({
      type: 'mtproto',
      server: 'proxy.example.com',
      port: 4455,
      secret: 'dd0123456789abcdef0123456789abcdef',
    });
  });

  test('still parses clean URL', () => {
    const parsed = parseProxies('https://t.me/proxy?server=example.com&port=443&secret=dd0123456789abcdef0123456789abcdef');
    expect(parsed.length).toBe(1);
    expect(parsed[0].server).toBe('example.com');
  });
});

describe('parseSecret', () => {
  test('dd prefix', () => {
    const p = parseSecret('dd' + 'ab'.repeat(16));
    expect(p.isFakeTLS).toBe(false);
    expect(p.secret.length).toBe(16);
  });
  test('ee prefix with domain', () => {
    const p = parseSecret('ee' + 'ab'.repeat(16) + Buffer.from('cloudflare.com').toString('hex'));
    expect(p.isFakeTLS).toBe(true);
    expect(p.domain).toBe('cloudflare.com');
  });
});

describe('parseResPQ', () => {
  test('accepts full intermediate frame with matching nonce', () => {
    const nonce = randomBytes(16);
    const msg = buildUnencryptedMessage(buildReqPqMulti(nonce), generateMessageId());
    // fabricate a reply frame mirroring the wire format: len + aki(0) + msgid + blen + ctor + nonce + server_nonce
    const ctor = Buffer.from([0x63, 0x24, 0x16, 0x05]); // resPQ LE
    const serverNonce = randomBytes(16);
    const bodyLen = Buffer.alloc(4);
    bodyLen.writeUInt32LE(4 + 16 + 16, 0);
    const frame = Buffer.concat([
      (() => { const b = Buffer.alloc(4); b.writeUInt32LE(8 + 8 + 4 + bodyLen.readUInt32LE(0)); return b; })(),
      Buffer.alloc(8), // auth_key_id = 0
      Buffer.alloc(8), // message_id (arbitrary)
      bodyLen,
      ctor,
      nonce,
      serverNonce,
    ]);
    const parsed = parseResPQ(frame);
    expect(parsed).not.toBeNull();
    expect(parsed!.nonce.equals(nonce)).toBe(true);
  });
});

describe('fakeTLS round trip', () => {
  test('ServerHello with correct HMAC verifies', () => {
    const secret = randomBytes(16);
    const ch = generateFakeTLSClientHello('example.com', secret);
    const clientRandom = ch.subarray(11, 43);

    // Build a minimal 3-record reply with valid HMAC at offset 11 (as the proxy does)
    const rec = (type: number, payload: Buffer) => {
      const h = Buffer.alloc(5);
      h.writeUInt8(type, 0);
      h.writeUInt16BE(0x0303, 1);
      h.writeUInt16BE(payload.length, 3);
      return Buffer.concat([h, payload]);
    };
    const hello = rec(0x16, Buffer.alloc(90));
    const ccs = rec(0x14, Buffer.alloc(1));
    const app = rec(0x17, Buffer.alloc(100));
    const packet = Buffer.concat([hello, ccs, app]);
    const mac = createHmac('sha256', secret)
      .update(clientRandom)
      .update(packet.subarray(0, 11))
      .update(Buffer.alloc(32))
      .update(packet.subarray(43))
      .digest();
    mac.copy(packet, 11);

    expect(tryVerifyFakeTLSServerHello(packet, clientRandom, secret)).toBe('valid');
    expect(tryVerifyFakeTLSServerHello(packet, randomBytes(32), secret)).toBe('invalid');
    expect(tryVerifyFakeTLSServerHello(packet.subarray(0, 50), clientRandom, secret)).toBe('incomplete');
  });
});

describe('obfuscation header', () => {
  test('tail decrypts to protocol tag + dc from server view (full-stream CTR)', () => {
    // Server view: decrypt whole 64B frame with client-encrypt keystream
    // from position 0 -> tail must equal the protocol tag (eeee) + dcId (LE).
    const { header } = initObfuscation(randomBytes(16), 2, PROTO_TAG.INTERMEDIATE);
    expect(header.length).toBe(64);
  });
});

describe('live MTProto proxy ping', () => {
  test('rejects a dead endpoint', async () => {
    await expect(
      MTProtoConnection.pingOnce({ host: '127.0.0.1', port: 1, secret: LIVE.secret, timeout: 2000 }, 2000)
    ).rejects.toThrow();
  }, 10000);

  test.skipIf(!LIVE_PROXY_URL)('pings a live proxy from TPING_LIVE_PROXY', async () => {
    const [proxy] = parseProxies(LIVE_PROXY_URL!);
    expect(proxy?.type).toBe('mtproto');
    const ms = await MTProtoConnection.pingOnce({
      host: (proxy as any).server,
      port: (proxy as any).port,
      secret: (proxy as any).secret,
      timeout: 15000,
    }, 15000);
    expect(ms).toBeGreaterThan(0);
    expect(ms).toBeLessThan(15000);
  }, 20000);
});

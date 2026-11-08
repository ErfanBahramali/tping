// Run: bun test
// End-to-end tests use local mock servers. Set TPING_LIVE_PROXY to a proxy link
// to also run a live test against a real proxy.
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { createHash, createHmac, randomBytes } from 'crypto';
import { parseProxies, parseProxyString } from '../src/lib/parser.js';
import { decodeSecret, parseSecret } from '../src/mtproto/secret.js';
import { buildClientHello, verifyServerHello, RANDOM_OFFSET } from '../src/mtproto/fake-tls.js';
import { createObfuscation } from '../src/mtproto/obfuscation.js';
import { encodeFrame, readFrame, TransportError, type TransportMode } from '../src/mtproto/transport.js';
import { buildReqPqMulti, buildResPQ, parseReqPqMulti, parseResPQ } from '../src/mtproto/messages.js';
import { AESCTR } from '../src/crypto/aes-ctr.js';
import { isOnCurve } from '../src/crypto/x25519.js';
import { checkProxy, type CheckOptions } from '../src/lib/checker.js';
import type { Pipe } from '../src/net/stream.js';
import type { TelegramProxy } from '../src/types/index.js';
import {
  startMockDatacenter,
  startMockHttpProxy,
  startMockMtproxy,
  startMockSocks5,
  startSilentServer,
  type MockServer,
  type SeenRequest,
} from './helpers/mock-servers.js';

const KEY_HEX = '0123456789abcdef0123456789abcdef';
const KEY = Buffer.from(KEY_HEX, 'hex');
const DOMAIN = 'www.google.com';
const EE_SECRET = `ee${KEY_HEX}${Buffer.from(DOMAIN).toString('hex')}`;

const proxyOf = (link: string): TelegramProxy => {
  const outcome = parseProxyString(link);
  if (!('proxy' in outcome)) {
    throw new Error(outcome.reason);
  }
  return outcome.proxy;
};

describe('parser', () => {
  const mt = (prefix: string) => `${prefix}?server=example.com&port=443&secret=dd${KEY_HEX}`;

  test.each([
    'https://t.me/proxy',
    'http://t.me/proxy',
    't.me/proxy',
    'https://telegram.me/proxy',
    'https://telegram.dog/proxy',
    'https://www.t.me/proxy',
    'https://T.ME/proxy',
    'tg://proxy',
    'tg:proxy',
  ])('MTProto link form %s', (prefix) => {
    expect(proxyOf(mt(prefix))).toEqual({ type: 'mtproto', server: 'example.com', port: 443, secret: `dd${KEY_HEX}` });
  });

  test('shell-escaped link', () => {
    const escaped = String.raw`https://t.me/proxy\?server\=example.com\&port\=4455\&secret\=dd${KEY_HEX}`;
    expect(proxyOf(escaped)).toMatchObject({ port: 4455, secret: `dd${KEY_HEX}` });
  });

  test('keeps "+" and "/" in base64 secrets', () => {
    expect(proxyOf('tg://proxy?server=a.com&port=443&secret=7gEj+0/Vn')).toMatchObject({ secret: '7gEj+0/Vn' });
  });

  test('SOCKS5 links', () => {
    expect(proxyOf('https://t.me/socks?server=1.2.3.4&port=1080&user=u&pass=p%26q')).toEqual({
      type: 'socks5', server: '1.2.3.4', port: 1080, username: 'u', password: 'p&q',
    });
    expect(proxyOf('tg://socks?server=1.2.3.4&port=1080')).toMatchObject({ type: 'socks5', username: undefined });
    expect(proxyOf('socks5://us%40r:pa%3Ass@host.com:9050')).toEqual({
      type: 'socks5', server: 'host.com', port: 9050, username: 'us@r', password: 'pa:ss',
    });
  });

  test('HTTP proxy', () => {
    expect(proxyOf('http://user:pass@10.0.0.1:3128')).toEqual({
      type: 'http', server: '10.0.0.1', port: 3128, username: 'user', password: 'pass',
    });
  });

  test('WEB-Proxy links are recognized', () => {
    expect(proxyOf(`tg://webproxy?server=web.example.com&secret=${KEY_HEX}`)).toMatchObject({ type: 'web', port: 443 });
  });

  test.each([
    ['tg://proxy?server=a.com&port=99999&secret=x', 'out of range'],
    ['tg://proxy?server=a.com&port=abc&secret=x', 'invalid port'],
    ['tg://proxy?server=a.com&port=443', 'secret is missing'],
    ['tg://proxy?port=443&secret=x', 'server is missing'],
    ['ftp://example.com', 'unsupported link'],
  ])('reports %s', (link, reason) => {
    const outcome = parseProxyString(link);
    expect('reason' in outcome && outcome.reason).toContain(reason);
  });

  test('multiple proxies, comments, whitespace separation, issues', () => {
    const { proxies, issues } = parseProxies([
      '# comment',
      `tg://proxy?server=a.com&port=443&secret=${KEY_HEX} tg://socks?server=b.com&port=1080`,
      '',
      'garbage',
    ].join('\n'));
    expect(proxies.map((p) => p.server)).toEqual(['a.com', 'b.com']);
    expect(issues).toHaveLength(1);
  });
});

describe('secret', () => {
  test('hex layouts', () => {
    expect(parseSecret(KEY_HEX)).toMatchObject({ kind: 'simple' });
    expect(parseSecret(`dd${KEY_HEX}`)).toMatchObject({ kind: 'secure' });
    expect(parseSecret(EE_SECRET)).toMatchObject({ kind: 'faketls', domain: DOMAIN });
    expect(parseSecret(EE_SECRET.toUpperCase()).key.equals(KEY)).toBe(true);
  });

  test('base64url and base64 layouts', () => {
    const raw = Buffer.concat([Buffer.from([0xee]), KEY, Buffer.from(DOMAIN)]);
    const parsed = parseSecret(raw.toString('base64url'));
    expect(parsed.kind).toBe('faketls');
    expect(parsed.domain).toBe(DOMAIN);
    expect(parsed.key.equals(KEY)).toBe(true);
    expect(parseSecret(raw.toString('base64')).domain).toBe(DOMAIN);
  });

  test('rejects bad secrets', () => {
    expect(() => parseSecret('dd0123')).toThrow('dd secret must be 17 bytes');
    expect(() => parseSecret(`ee${KEY_HEX}`)).toThrow('no domain');
    expect(() => parseSecret('not a secret!')).toThrow('neither hex nor base64');
    expect(decodeSecret('')).toBeNull();
  });
});

describe('fake TLS ClientHello', () => {
  const parseExtensions = (packet: Buffer): Map<number, Buffer> => {
    let offset = 5 + 4 + 2 + 32;
    offset += 1 + packet[offset];
    offset += 2 + packet.readUInt16BE(offset);
    offset += 1 + packet[offset];
    const end = offset + 2 + packet.readUInt16BE(offset);
    offset += 2;
    const result = new Map<number, Buffer>();
    while (offset < end) {
      const type = packet.readUInt16BE(offset);
      const length = packet.readUInt16BE(offset + 2);
      result.set(type, packet.subarray(offset + 4, offset + 4 + length));
      offset += 4 + length;
    }
    expect(offset).toBe(end);
    expect(end).toBe(packet.length);
    return result;
  };

  test('structure: 517 bytes, consistent lengths, SNI, valid x25519 key', () => {
    const { packet } = buildClientHello(DOMAIN, KEY);
    expect(packet.length).toBe(517);
    expect(packet.subarray(0, 3).toString('hex')).toBe('160301');
    expect(packet.readUInt16BE(3)).toBe(packet.length - 5);
    expect(packet[5]).toBe(0x01);
    expect(packet.readUIntBE(6, 3)).toBe(packet.length - 9);

    const extensions = parseExtensions(packet);
    expect(extensions.get(0x0000)?.subarray(5).toString()).toBe(DOMAIN);
    expect(extensions.has(0x0015)).toBe(true);
    const keyShare = extensions.get(0x0033)!;
    expect(keyShare.subarray(7, 11).toString('hex')).toBe('001d0020');
    expect(isOnCurve(keyShare.subarray(11, 43))).toBe(true);
  });

  test('long domain: no padding, still well formed', () => {
    const { packet } = buildClientHello(`${'a'.repeat(400)}.com`, KEY);
    expect(packet.length).toBeGreaterThan(517);
    expect(parseExtensions(packet).has(0x0015)).toBe(false);
  });

  test('client random = HMAC with timestamp XORed into the last 4 bytes', () => {
    const now = Date.now();
    const { packet, clientRandom } = buildClientHello(DOMAIN, KEY, now);
    const zeroed = Buffer.from(packet);
    zeroed.fill(0, RANDOM_OFFSET, RANDOM_OFFSET + 32);
    const hmac = createHmac('sha256', KEY).update(zeroed).digest();
    expect(clientRandom.subarray(0, 28).equals(hmac.subarray(0, 28))).toBe(true);
    expect((clientRandom.readUInt32LE(28) ^ hmac.readUInt32LE(28)) >>> 0).toBe(Math.floor(now / 1000));
  });

  test('ServerHello verification', () => {
    const clientRandom = randomBytes(32);
    const response = Buffer.concat([Buffer.from('160303005a', 'hex'), randomBytes(90)]);
    response.fill(0, 11, 43);
    createHmac('sha256', KEY).update(clientRandom).update(response).digest().copy(response, 11);
    expect(verifyServerHello(response, clientRandom, KEY)).toBe(true);
    expect(verifyServerHello(response, randomBytes(32), KEY)).toBe(false);
  });
});

describe('obfuscation header', () => {
  const serverView = (header: Buffer, secret?: Buffer): { tag: number; dc: number } => {
    const material = header.subarray(8, 40);
    const key = secret ? createHash('sha256').update(material).update(secret).digest() : Buffer.from(material);
    const plain = new AESCTR(key, Buffer.from(header.subarray(40, 56))).encrypt(header);
    return { tag: plain.readUInt32LE(56), dc: plain.readInt16LE(60) };
  };

  test.each([
    ['abridged', 0xefefefef],
    ['intermediate', 0xeeeeeeee],
    ['padded', 0xdddddddd],
  ] as const)('%s tag and DC decrypt correctly on the server side', (mode, tag) => {
    expect(serverView(createObfuscation(4, mode, KEY).header, KEY)).toEqual({ tag, dc: 4 });
    expect(serverView(createObfuscation(-2, mode).header)).toEqual({ tag, dc: -2 });
  });

  test('header never starts with forbidden values', () => {
    for (let i = 0; i < 2000; i++) {
      const { header } = createObfuscation(2, 'padded', KEY);
      expect(header[0]).not.toBe(0xef);
      expect(header.readUInt32LE(4)).not.toBe(0);
    }
  });
});

describe('transport framing', () => {
  const pipeOver = (data: Buffer): Pipe => {
    let offset = 0;
    return {
      write: () => {},
      read: async (n) => {
        const out = data.subarray(offset, offset + n);
        offset += n;
        return out;
      },
    };
  };

  test.each(['abridged', 'intermediate', 'padded'] as const)('%s round trip', async (mode: TransportMode) => {
    const { message } = buildReqPqMulti();
    const payload = await readFrame(mode, pipeOver(encodeFrame(mode, message)));
    expect(parseReqPqMulti(payload)).not.toBeNull();
  });

  test('abridged long frame', async () => {
    const big = randomBytes(4 * 200);
    expect((await readFrame('abridged', pipeOver(encodeFrame('abridged', big)))).equals(big)).toBe(true);
  });

  test('transport error frame', async () => {
    const frame = Buffer.alloc(8);
    frame.writeUInt32LE(4, 0);
    frame.writeInt32LE(-404, 4);
    await expect(readFrame('intermediate', pipeOver(frame))).rejects.toBeInstanceOf(TransportError);
  });

  test('resPQ parse checks nonce field and envelope', () => {
    const { nonce } = buildReqPqMulti();
    expect(parseResPQ(buildResPQ(nonce))?.nonce.equals(nonce)).toBe(true);
    expect(parseResPQ(randomBytes(80))).toBeNull();
  });
});

describe('end-to-end with mock servers', () => {
  const seen: SeenRequest[] = [];
  const servers: MockServer[] = [];
  let dc: MockServer;
  let simple: MockServer;
  let faketls: MockServer;
  let silent: MockServer;

  const options = (extra: Partial<CheckOptions> = {}): CheckOptions => ({
    timeout: 3000,
    resolveDc: () => ({ host: '127.0.0.1', port: dc.port }),
    ...extra,
  });

  beforeAll(async () => {
    dc = await startMockDatacenter((s) => seen.push(s));
    simple = await startMockMtproxy({ key: KEY, onSeen: (s) => seen.push(s) });
    faketls = await startMockMtproxy({ key: KEY, domain: DOMAIN, onSeen: (s) => seen.push(s) });
    silent = await startSilentServer();
    servers.push(dc, simple, faketls, silent);
  });

  afterAll(async () => {
    await Promise.all(servers.map((s) => s.close()));
  });

  const link = (port: number, secret: string) => proxyOf(`tg://proxy?server=127.0.0.1&port=${port}&secret=${secret}`);

  test('simple secret uses intermediate transport', async () => {
    seen.length = 0;
    const result = await checkProxy(link(simple.port, KEY_HEX), options());
    expect(result.error).toBeUndefined();
    expect(result.success).toBe(true);
    expect(seen).toEqual([{ dc: 2, mode: 'intermediate', clientHelloLength: undefined }]);
  });

  test('dd secret uses padded intermediate and the requested DC', async () => {
    seen.length = 0;
    const result = await checkProxy(link(simple.port, `dd${KEY_HEX}`), options({ dcs: [4] }));
    expect(result.success).toBe(true);
    expect(seen).toEqual([{ dc: 4, mode: 'padded', clientHelloLength: undefined }]);
  });

  test('ee secret: fake TLS handshake, then padded intermediate in TLS records', async () => {
    seen.length = 0;
    const result = await checkProxy(link(faketls.port, EE_SECRET), options({ dcs: [1, 2, 3, 4, 5] }));
    expect(result.error).toBeUndefined();
    expect(result.success).toBe(true);
    expect(result.dcs.map((d) => d.dc)).toEqual([1, 2, 3, 4, 5]);
    expect(seen.map((s) => s.dc).sort()).toEqual([1, 2, 3, 4, 5]);
    expect(seen.every((s) => s.mode === 'padded' && s.clientHelloLength === 517)).toBe(true);
    expect(result.dcs[0].timings!.handshake).toBeGreaterThanOrEqual(0);
  });

  test('ee secret in base64url form', async () => {
    const raw = Buffer.concat([Buffer.from([0xee]), KEY, Buffer.from(DOMAIN)]).toString('base64url');
    expect((await checkProxy(link(faketls.port, raw), options())).success).toBe(true);
  });

  test('ee with wrong secret is reported as fake-TLS verification failure', async () => {
    const wrong = `ee${'ff'.repeat(16)}${Buffer.from(DOMAIN).toString('hex')}`;
    const result = await checkProxy(link(faketls.port, wrong), options());
    expect(result.success).toBe(false);
    expect(result.error).toContain('Fake-TLS verification failed');
  });

  test('dd with wrong secret fails (proxy drops the connection)', async () => {
    const result = await checkProxy(link(simple.port, `dd${'ff'.repeat(16)}`), options());
    expect(result.success).toBe(false);
    expect(result.error).toContain('before Telegram answered');
  });

  test('plain secret against a fake-TLS-only proxy fails', async () => {
    const result = await checkProxy(link(faketls.port, `dd${KEY_HEX}`), options());
    expect(result.success).toBe(false);
  });

  test('invalid secret fails without connecting', async () => {
    const result = await checkProxy(link(simple.port, 'dd1234'), options());
    expect(result.success).toBe(false);
    expect(result.error).toContain('17 bytes');
  });

  test('refused connection', async () => {
    const closed = await startSilentServer();
    const port = closed.port;
    await closed.close();
    const result = await checkProxy(link(port, KEY_HEX), options());
    expect(result.error).toBe('Connection refused');
  });

  test('silent server times out with the stage in the message', async () => {
    const result = await checkProxy(link(silent.port, EE_SECRET), options({ timeout: 300 }));
    expect(result.error).toBe('Timeout while fake-TLS handshake');
  });

  test('abort stops the check and marks it aborted', async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 100);
    const result = await checkProxy(link(silent.port, KEY_HEX), options({ signal: controller.signal }));
    expect(result.aborted).toBe(true);
  });

  test('SOCKS5 without auth: MTProto handshake through the tunnel (abridged)', async () => {
    const socks = await startMockSocks5();
    servers.push(socks);
    seen.length = 0;
    const result = await checkProxy(proxyOf(`tg://socks?server=127.0.0.1&port=${socks.port}`), options({ dcs: [3] }));
    expect(result.error).toBeUndefined();
    expect(result.success).toBe(true);
    expect(seen).toEqual([{ dc: 3, mode: 'abridged' }]);
  });

  test('SOCKS5 with auth', async () => {
    const socks = await startMockSocks5({ username: 'user', password: 'secret' });
    servers.push(socks);
    const base = `tg://socks?server=127.0.0.1&port=${socks.port}`;
    expect((await checkProxy(proxyOf(`${base}&user=user&pass=secret`), options())).success).toBe(true);
    expect((await checkProxy(proxyOf(`${base}&user=user&pass=wrong`), options())).error).toContain('authentication failed');
    expect((await checkProxy(proxyOf(base), options())).error).toContain('requires authentication');
  });

  test('SOCKS5 proxy whose upstream is not Telegram fails', async () => {
    const socks = await startMockSocks5();
    servers.push(socks);
    const result = await checkProxy(
      proxyOf(`tg://socks?server=127.0.0.1&port=${socks.port}`),
      options({ timeout: 500, resolveDc: () => ({ host: '127.0.0.1', port: silent.port }) })
    );
    expect(result.error).toBe('Timeout while waiting for Telegram');
  });

  test('HTTP proxy with CONNECT', async () => {
    const http = await startMockHttpProxy({ username: 'u', password: 'p' });
    servers.push(http);
    const result = await checkProxy(proxyOf(`http://u:p@127.0.0.1:${http.port}`), options());
    expect(result.success).toBe(true);
    expect(result.dcs[0].via).toBeUndefined();
    expect((await checkProxy(proxyOf(`http://127.0.0.1:${http.port}`), options())).error).toContain('407');
  });

  test('HTTP proxy without CONNECT falls back to the HTTP transport', async () => {
    const http = await startMockHttpProxy({ allowConnect: false });
    servers.push(http);
    const result = await checkProxy(proxyOf(`http://127.0.0.1:${http.port}`), options());
    expect(result.error).toBeUndefined();
    expect(result.success).toBe(true);
    expect(result.dcs[0].via).toBe('http-transport');
  });

  test('WEB-Proxy is reported as unsupported', async () => {
    const result = await checkProxy(proxyOf(`tg://webproxy?server=x.com&secret=${KEY_HEX}`), options());
    expect(result.success).toBe(false);
    expect(result.error).toContain('not supported');
  });
});

const LIVE_PROXY_URL = process.env.TPING_LIVE_PROXY;

describe('live proxy', () => {
  test.skipIf(!LIVE_PROXY_URL)('pings the proxy from TPING_LIVE_PROXY', async () => {
    const result = await checkProxy(proxyOf(LIVE_PROXY_URL!), { timeout: 15000 });
    expect(result.error).toBeUndefined();
    expect(result.success).toBe(true);
  }, 20000);
});

import { createHmac, randomBytes, randomInt } from 'crypto';
import { generateX25519PublicKey } from '../crypto/x25519.js';
import type { Pipe, SocketStream } from '../net/stream.js';

/**
 * Fake TLS layer for MTProto proxies (secret with "ee" prefix), implemented
 * like Telegram Desktop (mtproto_tls_socket.cpp) and Android (tgnet).
 */

export class FakeTlsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FakeTlsError';
  }
}

/** Offset of the 32-byte random field inside the ClientHello / ServerHello packet. */
export const RANDOM_OFFSET = 11;
const RANDOM_LENGTH = 32;
/** Official clients pad the ClientHello to 517 bytes, like Chrome. */
const PADDING_TARGET = 513;
/** Official clients split outgoing data into records of at most this size. */
export const MAX_CLIENT_RECORD = 2878;
const MAX_SERVER_RECORD = 16384 + 256;

const SERVER_HELLO_HEADER = Buffer.from('160303', 'hex');
const SERVER_HELLO_MIDDLE = Buffer.from('140303000101170303', 'hex');
const CLIENT_PREFIX = Buffer.from('140303000101', 'hex');
const APP_DATA_HEADER = Buffer.from('170303', 'hex');
const TLS_ALERT = 0x15;

const hex = (value: string): Buffer => Buffer.from(value.replace(/\s+/g, ''), 'hex');

const u16 = (value: number): Buffer => {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value, 0);
  return out;
};

const u24 = (value: number): Buffer => {
  const out = Buffer.alloc(3);
  out.writeUIntBE(value, 0, 3);
  return out;
};

/**
 * Seven GREASE values (RFC 8701), consecutive pairs forced to differ.
 */
const generateGrease = (): Buffer => {
  const grease = randomBytes(7);
  for (let i = 0; i < grease.length; i++) {
    grease[i] = (grease[i] & 0xf0) + 0x0a;
  }
  for (let i = 1; i < grease.length; i += 2) {
    if (grease[i] === grease[i - 1]) {
      grease[i] ^= 0x10;
    }
  }
  return grease;
};

const shuffle = <T>(items: readonly T[]): T[] => {
  const result = [...items];
  for (let i = result.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
};

export interface ClientHello {
  readonly packet: Buffer;
  readonly clientRandom: Buffer;
}

/**
 * Build the ClientHello exactly like the official clients: Chrome-like cipher
 * suites and extensions (shuffled), GREASE, a valid x25519 key share, padding
 * to 517 bytes, and the client random set to HMAC-SHA256(secret, packet) with
 * the last 4 bytes XORed with the current UNIX time.
 */
export const buildClientHello = (domain: string, key: Buffer, nowMs: number = Date.now()): ClientHello => {
  const g = generateGrease();
  const grease = (index: number): Buffer => Buffer.from([g[index], g[index]]);
  const host = Buffer.from(domain, 'utf8');

  const extensions = shuffle([
    Buffer.concat([hex('0000'), u16(host.length + 5), u16(host.length + 3), hex('00'), u16(host.length), host]),
    hex('0005 0005 01 0000 0000'),
    Buffer.concat([hex('000a 000a 0008'), grease(4), hex('001d 0017 0018')]),
    hex('000b 0002 01 00'),
    hex('000d 0012 0010 0403 0804 0401 0503 0805 0501 0806 0601'),
    hex('0010 000e 000c 02 6832 08 687474702f312e31'),
    hex('0012 0000'),
    hex('0017 0000'),
    hex('001b 0003 02 0002'),
    hex('0023 0000'),
    Buffer.concat([hex('002b 0007 06'), grease(6), hex('0304 0303')]),
    hex('002d 0002 01 01'),
    Buffer.concat([hex('0033 002b 0029'), grease(4), hex('0001 00 001d 0020'), generateX25519PublicKey()]),
    hex('4469 0005 0003 02 6832'),
    hex('ff01 0001 00'),
  ]);

  let extensionBlock = Buffer.concat([grease(2), hex('0000'), ...extensions, grease(3), hex('0001 00')]);

  const cipherSuites = Buffer.concat([
    grease(0),
    hex('1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035'),
  ]);

  // record header + handshake header + version + random + session id + suites + compression + ext length
  const fixedLength = 5 + 4 + 2 + RANDOM_LENGTH + 1 + 32 + 2 + cipherSuites.length + 2 + 2;
  const unpadded = fixedLength + extensionBlock.length;
  if (unpadded < PADDING_TARGET) {
    const size = PADDING_TARGET - unpadded;
    extensionBlock = Buffer.concat([extensionBlock, hex('0015'), u16(size), Buffer.alloc(size)]);
  }

  const body = Buffer.concat([
    hex('0303'),
    Buffer.alloc(RANDOM_LENGTH),
    hex('20'),
    randomBytes(32),
    u16(cipherSuites.length),
    cipherSuites,
    hex('0100'),
    u16(extensionBlock.length),
    extensionBlock,
  ]);
  const handshake = Buffer.concat([hex('01'), u24(body.length), body]);
  const packet = Buffer.concat([hex('160301'), u16(handshake.length), handshake]);

  const digest = createHmac('sha256', key).update(packet).digest();
  const timestamp = Math.floor(nowMs / 1000) >>> 0;
  digest.writeUInt32LE((digest.readUInt32LE(28) ^ timestamp) >>> 0, 28);
  digest.copy(packet, RANDOM_OFFSET);

  return { packet, clientRandom: Buffer.from(digest) };
};

/**
 * Check the proxy's ServerHello: HMAC-SHA256(secret, clientRandom || response
 * with the random field zeroed) must equal the random field.
 */
export const verifyServerHello = (response: Buffer, clientRandom: Buffer, key: Buffer): boolean => {
  if (response.length < RANDOM_OFFSET + RANDOM_LENGTH) {
    return false;
  }
  const zeroed = Buffer.from(response);
  zeroed.fill(0, RANDOM_OFFSET, RANDOM_OFFSET + RANDOM_LENGTH);
  const expected = createHmac('sha256', key).update(clientRandom).update(zeroed).digest();
  return expected.equals(response.subarray(RANDOM_OFFSET, RANDOM_OFFSET + RANDOM_LENGTH));
};

/**
 * TLS record wrapper used after the handshake.
 * Outgoing: one ChangeCipherSpec prefix, then Application Data records of at most 2878 bytes.
 * Incoming: only Application Data records are accepted.
 */
export class FakeTlsPipe implements Pipe {
  private prefixSent = false;
  private incoming: Buffer = Buffer.alloc(0);

  constructor(private readonly inner: Pipe) {}

  write(data: Buffer): void {
    const parts: Buffer[] = [];
    if (!this.prefixSent) {
      parts.push(CLIENT_PREFIX);
      this.prefixSent = true;
    }
    for (let offset = 0; offset < data.length; offset += MAX_CLIENT_RECORD) {
      const chunk = data.subarray(offset, Math.min(offset + MAX_CLIENT_RECORD, data.length));
      parts.push(APP_DATA_HEADER, u16(chunk.length), chunk);
    }
    this.inner.write(Buffer.concat(parts));
  }

  async read(length: number): Promise<Buffer> {
    while (this.incoming.length < length) {
      const header = await this.inner.read(5);
      if (!header.subarray(0, 3).equals(APP_DATA_HEADER)) {
        throw new FakeTlsError(`Unexpected TLS record type 0x${header[0].toString(16)} from proxy`);
      }
      const size = header.readUInt16BE(3);
      if (size > MAX_SERVER_RECORD) {
        throw new FakeTlsError('TLS record from proxy is too large');
      }
      const body = await this.inner.read(size);
      this.incoming = Buffer.concat([this.incoming, body]);
    }
    const out = this.incoming.subarray(0, length);
    this.incoming = this.incoming.subarray(length);
    return out;
  }
}

/**
 * Perform the fake TLS handshake. Like the official clients, the response must
 * be exactly: ServerHello record, ChangeCipherSpec (1 byte), one Application
 * Data record; anything else is rejected.
 */
export const fakeTlsHandshake = async (stream: SocketStream, key: Buffer, domain: string): Promise<FakeTlsPipe> => {
  const hello = buildClientHello(domain, key);
  stream.write(hello.packet);

  const first = await stream.read(5);
  if (first[0] === TLS_ALERT) {
    throw new FakeTlsError('Proxy answered with a TLS alert (ClientHello rejected)');
  }
  if (!first.subarray(0, 3).equals(SERVER_HELLO_HEADER)) {
    throw new FakeTlsError('Not a fake-TLS proxy (response is not a TLS ServerHello)');
  }
  const helloBody = await stream.read(first.readUInt16BE(3));
  const middle = await stream.read(SERVER_HELLO_MIDDLE.length);
  if (!middle.equals(SERVER_HELLO_MIDDLE)) {
    throw new FakeTlsError('Unexpected fake-TLS ServerHello layout (looks like a real TLS server, not the proxy)');
  }
  const appLength = await stream.read(2);
  const appBody = await stream.read(appLength.readUInt16BE(0));

  const response = Buffer.concat([first, helloBody, middle, appLength, appBody]);
  if (!verifyServerHello(response, hello.clientRandom, key)) {
    throw new FakeTlsError(
      'Fake-TLS verification failed: wrong secret, or the real site answered instead of the proxy (check system clock too)'
    );
  }

  return new FakeTlsPipe(stream);
};

import { createHmac, randomBytes } from 'crypto';

/**
 * FakeTLS layer for MTProto proxies (secret with "ee" prefix).
 */

/**
 * Parse MTProto proxy secret and extract components.
 */
export interface ParsedSecret {
  secret: Buffer; // 16 bytes
  domain?: string; // Optional SNI domain for fake TLS
  isFakeTLS: boolean;
}

/**
 * Parse MTProto proxy secret (dd or ee prefix).
 *
 * @param secretHex - Hex-encoded secret (with or without dd/ee prefix)
 */
export function parseSecret(secretHex: string): ParsedSecret {
  const hex = secretHex.toLowerCase().replace(/[^0-9a-f]/g, '');

  if (hex.startsWith('dd')) {
    const secret = Buffer.from(hex.slice(2), 'hex');
    if (secret.length !== 16) {
      throw new Error('dd secret must be 16 bytes');
    }
    return { secret, isFakeTLS: false };
  }

  if (hex.startsWith('ee')) {
    const rest = hex.slice(2);
    if (rest.length < 32) {
      throw new Error('ee secret must have at least 16 bytes');
    }
    const secret = Buffer.from(rest.slice(0, 32), 'hex');
    const domain = rest.length > 32 ? Buffer.from(rest.slice(32), 'hex').toString('ascii') : undefined;
    return { secret, domain, isFakeTLS: true };
  }

  const secret = Buffer.from(hex, 'hex');
  if (secret.length !== 16) {
    throw new Error('Secret must be 16 bytes');
  }
  return { secret, isFakeTLS: false };
}

/**
 * TLS record content types.
 */
export const TLS_RECORD = {
  CHANGE_CIPHER_SPEC: 0x14,
  ALERT: 0x15,
  HANDSHAKE: 0x16,
  APPLICATION_DATA: 0x17,
} as const;

/** Random field offset inside the ClientHello record:
 * record header (5) + handshake type (1) + handshake length (3) + client version (2). */
const RANDOM_OFFSET = 11;
const RANDOM_LEN = 32;

const u16 = (n: number): Buffer => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
};

const u24 = (n: number): Buffer => {
  const b = Buffer.alloc(3);
  b.writeUIntBE(n, 0, 3);
  return b;
};

const extension = (type: number, data: Buffer): Buffer =>
  Buffer.concat([u16(type), u16(data.length), data]);

/**
 * Build the SNI (server_name) extension.
 */
const sniExtension = (domain: string): Buffer => {
  const host = Buffer.from(domain, 'ascii');
  const list = Buffer.concat([Buffer.from([0x00]), u16(host.length), host]);
  return extension(0x0000, Buffer.concat([u16(list.length), list]));
};

/**
 * Generate a FakeTLS ClientHello with a valid HMAC digest in the client random,
 * exactly as official Telegram clients do. The proxy verifies this digest.
 *
 * @param domain - SNI domain from the ee secret
 * @param secret - 16-byte proxy secret
 */
export function generateFakeTLSClientHello(domain: string, secret: Buffer): Buffer {
  const sessionId = randomBytes(32);
  const keyShare = randomBytes(32);

  // Include a trailing GREASE value like real browsers do.
  const cipherSuites = [
    0x1301, 0x1302, 0x1303, 0x1305, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
    0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a, 0x0a0a,
  ];
  const csBuf = Buffer.alloc(cipherSuites.length * 2);
  cipherSuites.forEach((c, i) => csBuf.writeUInt16BE(c, i * 2));

  const alpn = Buffer.concat([
    u16(2 + 1 + 2 + 1 + 8), // protocol name list length
    Buffer.from([2]), Buffer.from('h2', 'ascii'),
    Buffer.from([8]), Buffer.from('http/1.1', 'ascii'),
  ]);

  const extensions = Buffer.concat([
    sniExtension(domain),
    extension(0x0010, alpn), // ALPN
    extension(0x000a, Buffer.concat([u16(4), u16(0x001d), u16(0x0017)])), // supported_groups: x25519, secp256r1
    extension(0x000b, Buffer.concat([u16(2), Buffer.from([0x01, 0x00])])), // ec_point_formats: uncompressed
    extension(0x000d, Buffer.concat([u16(4), u16(0x0804), u16(0x0401)])), // signature_algorithms
    extension(0x002b, Buffer.concat([u16(4), Buffer.from([0x03, 0x04, 0x03, 0x03])])), // supported_versions: TLS1.3, TLS1.2
    extension(0x0033, Buffer.concat([u16(2 + 2 + keyShare.length), u16(0x001d), u16(keyShare.length), keyShare])), // key_share x25519
    extension(0x0016, Buffer.alloc(0)), // encrypt_then_mac
    extension(0x0017, Buffer.alloc(0)), // extended_master_secret
  ]);

  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]), // client version TLS 1.2
    Buffer.alloc(RANDOM_LEN), // placeholder: random filled below
    Buffer.from([sessionId.length]), sessionId,
    u16(csBuf.length), csBuf,
    Buffer.from([0x01, 0x00]), // compression methods: null
    u16(extensions.length), extensions,
  ]);

  const handshake = Buffer.concat([Buffer.from([0x01]), u24(body.length), body]); // ClientHello
  const packet = Buffer.concat([
    Buffer.from([TLS_RECORD.HANDSHAKE, 0x03, 0x01]), u16(handshake.length), handshake,
  ]);

  // Client random = HMAC(secret, handshake with zeroed random); last 4 bytes = UNIX timestamp (LE).
  const digest = createHmac('sha256', secret).update(packet).digest();
  digest.writeUInt32LE(Math.floor(Date.now() / 1000) >>> 0, RANDOM_LEN - 4);
  digest.copy(packet, RANDOM_OFFSET);

  return packet;
}

/**
 * Wrap data into TLS Application Data record(s).
 */
export function wrapInTLSRecords(data: Buffer): Buffer {
  const MAX_CHUNK_SIZE = 16384;
  const chunks: Buffer[] = [];
  for (let i = 0; i < data.length; i += MAX_CHUNK_SIZE) {
    const chunk = data.subarray(i, Math.min(i + MAX_CHUNK_SIZE, data.length));
    const record = Buffer.alloc(5 + chunk.length);
    record.writeUInt8(TLS_RECORD.APPLICATION_DATA, 0);
    record.writeUInt16BE(0x0303, 1);
    record.writeUInt16BE(chunk.length, 3);
    chunk.copy(record, 5);
    chunks.push(record);
  }
  return Buffer.concat(chunks);
}

/**
 * Extract complete TLS record payloads from a stream buffer.
 *
 * @returns Concatenated payload of complete records and the remaining (incomplete) buffer
 */
export function extractTlsRecords(buffer: Buffer): { payload: Buffer; rest: Buffer } {
  let offset = 0;
  let payload = Buffer.alloc(0);
  while (buffer.length - offset >= 5) {
    const len = buffer.readUInt16BE(offset + 3);
    if (buffer.length - offset < 5 + len) break;
    payload = Buffer.concat([payload, buffer.subarray(offset + 5, offset + 5 + len)]);
    offset += 5 + len;
  }
  return { payload, rest: buffer.subarray(offset) };
}

/**
 * Try to read and verify the proxy's ServerHello response.
 * The proxy answers with exactly 3 records: ServerHello + ChangeCipherSpec + noise AppData,
 * placing HMAC(secret, clientRandom || records-with-zeroed-digest) at RANDOM_OFFSET.
 *
 * @returns 'incomplete' while waiting for more bytes, 'valid' or 'invalid' when decided
 */
export function tryVerifyFakeTLSServerHello(
  buffer: Buffer,
  clientRandom: Buffer,
  secret: Buffer
): 'incomplete' | 'valid' | 'invalid' {
  let offset = 0;
  for (let i = 0; i < 3; i++) {
    if (buffer.length - offset < 5) return 'incomplete';
    offset += 5 + buffer.readUInt16BE(offset + 3);
  }
  if (buffer.length < offset) return 'incomplete';

  const packet = buffer.subarray(0, offset);
  if (packet[0] !== TLS_RECORD.HANDSHAKE) return 'invalid';

  const mac = createHmac('sha256', secret)
    .update(clientRandom)
    .update(packet.subarray(0, RANDOM_OFFSET))
    .update(Buffer.alloc(RANDOM_LEN))
    .update(packet.subarray(RANDOM_OFFSET + RANDOM_LEN))
    .digest();

  return mac.equals(packet.subarray(RANDOM_OFFSET, RANDOM_OFFSET + RANDOM_LEN)) ? 'valid' : 'invalid';
}

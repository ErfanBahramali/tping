import { randomBytes, createHash } from 'crypto';
import { AESCTR } from '../crypto/aes-ctr.js';
import type { Pipe } from '../net/stream.js';
import { PROTOCOL_TAGS, type TransportMode } from './transport.js';

/**
 * First-int values the 64-byte init header must not start with: they would make
 * the connection look like HTTP (HEAD/POST/GET /OPTIONS), TLS, or a plain transport tag.
 */
const FORBIDDEN_FIRST_INTS: readonly number[] = [
  0x44414548, // HEAD
  0x54534f50, // POST
  0x20544547, // GET
  0x4954504f, // OPTI
  0x02010316, // TLS handshake
  0xdddddddd,
  0xeeeeeeee,
];

export interface Obfuscation {
  readonly header: Buffer;
  readonly encryptor: AESCTR;
  readonly decryptor: AESCTR;
}

const generateRandomHeader = (): Buffer => {
  for (;;) {
    const random = randomBytes(64);
    if (random[0] === 0xef) continue;
    if (FORBIDDEN_FIRST_INTS.includes(random.readUInt32LE(0))) continue;
    if (random.readUInt32LE(4) === 0) continue;
    return random;
  }
};

const deriveKey = (material: Buffer, secret?: Buffer): Buffer =>
  secret ? createHash('sha256').update(material).update(secret).digest() : Buffer.from(material);

/**
 * Build the obfuscated2 init header (MTProto transport obfuscation).
 *
 * @param dcId - DC id written at offset 60 (signed 16-bit LE); negative for media DCs
 * @param mode - transport framing, selects the protocol tag at offset 56
 * @param secret - 16-byte proxy key; omitted for direct connections to a DC
 */
export const createObfuscation = (dcId: number, mode: TransportMode, secret?: Buffer): Obfuscation => {
  if (secret && secret.length !== 16) {
    throw new Error('Proxy secret key must be 16 bytes');
  }

  const header = generateRandomHeader();
  const reversed = Buffer.from(header.subarray(8, 56)).reverse();

  const encryptor = new AESCTR(deriveKey(header.subarray(8, 40), secret), Buffer.from(header.subarray(40, 56)));
  const decryptor = new AESCTR(deriveKey(reversed.subarray(0, 32), secret), Buffer.from(reversed.subarray(32, 48)));

  header.writeUInt32LE(PROTOCOL_TAGS[mode], 56);
  header.writeInt16LE(dcId, 60);

  // Encrypt the full header to advance the keystream by 64 bytes, but only
  // the tail (protocol tag, DC id, 2 random bytes) goes out encrypted.
  const encrypted = encryptor.encrypt(header);
  encrypted.copy(header, 56, 56);

  return { header, encryptor, decryptor };
};

/**
 * Pipe that prepends the init header to the first write and AES-CTR
 * encrypts/decrypts everything else.
 */
export class ObfuscatedPipe implements Pipe {
  private headerSent = false;

  constructor(private readonly inner: Pipe, private readonly obfuscation: Obfuscation) {}

  write(data: Buffer): void {
    const encrypted = this.obfuscation.encryptor.encrypt(data);
    if (this.headerSent) {
      this.inner.write(encrypted);
      return;
    }
    this.headerSent = true;
    this.inner.write(Buffer.concat([this.obfuscation.header, encrypted]));
  }

  async read(length: number): Promise<Buffer> {
    return this.obfuscation.decryptor.encrypt(await this.inner.read(length));
  }
}

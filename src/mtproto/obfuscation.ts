import { randomBytes, createHash } from 'crypto';
import { AESCTR } from '../crypto/aes-ctr.js';

/**
 * Protocol tags for MTProto transports.
 */
export const PROTO_TAG = {
  ABRIDGED: Buffer.from([0xef, 0xef, 0xef, 0xef]),
  INTERMEDIATE: Buffer.from([0xee, 0xee, 0xee, 0xee]),
  SECURE: Buffer.from([0xdd, 0xdd, 0xdd, 0xdd]),
};

/**
 * Reserved byte sequences that must be avoided in random nonce.
 */
const RESERVED_KEYWORDS = [
  Buffer.from([0x50, 0x56, 0x72, 0x47]), // PVrG
  Buffer.from([0x47, 0x45, 0x54, 0x20]), // GET
  Buffer.from([0x50, 0x4f, 0x53, 0x54]), // POST
  Buffer.from([0xee, 0xee, 0xee, 0xee]), // eeee
];

interface ObfuscationKeys {
  header: Buffer;
  encryptor: AESCTR;
  decryptor: AESCTR;
}

/**
 * Initialize MTProto obfuscation layer.
 * Generates random 64-byte header and derives encryption keys.
 *
 * @param secret - 16-byte secret from proxy
 * @param dcId - Telegram datacenter ID
 * @param protocolTag - Transport protocol tag (default: INTERMEDIATE)
 * @returns Header buffer and encryptor/decryptor ciphers
 */
export function initObfuscation(
  secret: Buffer,
  dcId: number,
  protocolTag: Buffer = PROTO_TAG.INTERMEDIATE
): ObfuscationKeys {
  if (secret.length !== 16) {
    throw new Error('Secret must be 16 bytes');
  }

  // Generate 64 random bytes, avoiding reserved patterns
  let random: Buffer;
  while (true) {
    random = randomBytes(64);

    // Check if first byte is not 0xef
    if (random[0] === 0xef) continue;

    // Check if bytes 4-8 are not all zeros
    if (random.slice(4, 8).equals(Buffer.alloc(4))) continue;

    // Check if first 4 bytes don't match reserved keywords
    const isReserved = RESERVED_KEYWORDS.some((keyword) =>
      keyword.equals(random.slice(0, 4))
    );
    if (isReserved) continue;

    break;
  }

  // Convert to mutable buffer
  const header = Buffer.from(random);

  // Reverse bytes 8-56 for decryption key derivation
  const reversed = Buffer.from(header.slice(8, 56)).reverse();

  // Derive encryption key and IV
  const encryptKey = createHash('sha256')
    .update(Buffer.concat([header.slice(8, 40), secret]))
    .digest(); // 32 bytes

  const encryptIv = header.slice(40, 56); // 16 bytes

  // Derive decryption key and IV
  const decryptKey = createHash('sha256')
    .update(Buffer.concat([reversed.slice(0, 32), secret]))
    .digest();

  const decryptIv = reversed.slice(32, 48);

  // Create AES-256-CTR ciphers
  const encryptor = new AESCTR(encryptKey, encryptIv);
  const decryptor = new AESCTR(decryptKey, decryptIv);

  // Encode protocol tag and DC ID at positions 56-62
  protocolTag.copy(header, 56);

  // DC ID as signed 16-bit little-endian
  header.writeInt16LE(dcId, 60);

  // Encrypt the tail (tag + dc ID) in place. The cipher stream position must
  // be 56 here: the proxy decrypts the whole 64-byte frame from position 0 and
  // expects the tag to appear at bytes 56-60. Encrypting the whole header and
  // taking the tail (as official clients do) yields exactly that.
  const encryptedTail = encryptor.encrypt(header).subarray(56);
  encryptedTail.copy(header, 56);

  return { header, encryptor, decryptor };
}

import { createCipheriv } from 'crypto';

/**
 * AES-256-CTR cipher with continuous counter mode.
 * Used for MTProto obfuscation layer encryption.
 */
export class AESCTR {
  private cipher: ReturnType<typeof createCipheriv>;

  /**
   * @param key - 32 bytes encryption key
   * @param iv - 16 bytes initialization vector (counter)
   */
  constructor(key: Buffer, iv: Buffer) {
    if (key.length !== 32) {
      throw new Error('AES-256 key must be 32 bytes');
    }
    if (iv.length !== 16) {
      throw new Error('IV must be 16 bytes');
    }

    // CTR mode doesn't distinguish between encrypt/decrypt
    this.cipher = createCipheriv('aes-256-ctr', key, iv);
  }

  /**
   * Encrypt/decrypt data (CTR mode is symmetric).
   * Maintains internal counter state across multiple calls.
   */
  encrypt(data: Buffer): Buffer {
    return this.cipher.update(data);
  }
}

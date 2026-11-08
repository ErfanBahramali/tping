/**
 * MTProto proxy secret handling, matching Telegram Android (tgnet) and Desktop.
 *
 * Accepted encodings: hex, or base64 / base64url (padding optional).
 * Accepted layouts (raw bytes):
 *   16 bytes                    -> simple obfuscation, intermediate transport (0xeeeeeeee)
 *   0xdd + 16 bytes             -> secure, padded intermediate transport (0xdddddddd)
 *   0xee + 16 bytes + domain    -> fake TLS, padded intermediate inside TLS records
 */

export type SecretKind = 'simple' | 'secure' | 'faketls';

export interface ParsedSecret {
  readonly kind: SecretKind;
  /** 16-byte key used for obfuscation key derivation and fake TLS HMAC. */
  readonly key: Buffer;
  /** SNI domain (fake TLS only). */
  readonly domain?: string;
}

export class SecretError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecretError';
  }
}

/**
 * Decode a secret string the same way the official clients do:
 * all-hex with even length is hex, anything else is base64url.
 */
export const decodeSecret = (value: string): Buffer | null => {
  const text = value.trim();
  if (text.length === 0) {
    return null;
  }
  if (text.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(text)) {
    return Buffer.from(text, 'hex');
  }
  if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(text)) {
    const standard = text.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    const decoded = Buffer.from(standard, 'base64');
    return decoded.length > 0 ? decoded : null;
  }
  return null;
};

export const parseSecret = (value: string): ParsedSecret => {
  const bytes = decodeSecret(value);
  if (!bytes) {
    throw new SecretError('Secret is neither hex nor base64');
  }

  if (bytes.length === 16) {
    return { kind: 'simple', key: bytes };
  }

  if (bytes[0] === 0xdd) {
    if (bytes.length !== 17) {
      throw new SecretError(`dd secret must be 17 bytes, got ${bytes.length}`);
    }
    return { kind: 'secure', key: bytes.subarray(1, 17) };
  }

  if (bytes[0] === 0xee) {
    if (bytes.length <= 17) {
      throw new SecretError(`Fake-TLS (ee) secret has no domain; Telegram rejects it (as dd it would be dd${bytes.subarray(1).toString('hex')})`);
    }
    const domain = bytes.subarray(17).toString('utf8');
    return { kind: 'faketls', key: bytes.subarray(1, 17), domain };
  }

  throw new SecretError(`Unsupported secret format (${bytes.length} bytes, prefix 0x${bytes[0].toString(16).padStart(2, '0')})`);
};

export const describeSecretKind = (kind: SecretKind): string => {
  switch (kind) {
    case 'faketls':
      return 'Fake TLS';
    case 'secure':
      return 'dd';
    default:
      return 'simple';
  }
};

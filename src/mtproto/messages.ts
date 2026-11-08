import { randomBytes } from 'crypto';

const REQ_PQ_MULTI = 0xbe7e8ef1;
const RES_PQ = 0x05162463;

/**
 * Client message_id: unixtime * 2^32, divisible by 4.
 */
export const generateMessageId = (nowMs: number = Date.now()): bigint => {
  const seconds = BigInt(Math.floor(nowMs / 1000));
  const fraction = BigInt(Math.floor(((nowMs % 1000) / 1000) * 2 ** 32));
  return ((seconds << 32n) | fraction) & ~3n;
};

/**
 * Unencrypted message: auth_key_id (0) + message_id + length + body.
 */
export const buildUnencryptedMessage = (body: Buffer, messageId: bigint = generateMessageId()): Buffer => {
  const header = Buffer.alloc(20);
  header.writeBigInt64LE(messageId, 8);
  header.writeUInt32LE(body.length, 16);
  return Buffer.concat([header, body]);
};

/**
 * req_pq_multi#be7e8ef1 nonce:int128 = ResPQ;
 */
export const buildReqPqMulti = (nonce: Buffer = randomBytes(16)): { readonly message: Buffer; readonly nonce: Buffer } => {
  const body = Buffer.alloc(20);
  body.writeUInt32LE(REQ_PQ_MULTI, 0);
  nonce.copy(body, 4);
  return { message: buildUnencryptedMessage(body), nonce };
};

export interface ResPQ {
  readonly nonce: Buffer;
  readonly serverNonce: Buffer;
}

/**
 * Parse an unencrypted resPQ message (transport framing already removed;
 * trailing transport padding is allowed).
 *
 * resPQ#05162463 nonce:int128 server_nonce:int128 pq:string server_public_key_fingerprints:Vector<long> = ResPQ;
 */
export const parseResPQ = (data: Buffer): ResPQ | null => {
  if (data.length < 20 + 4 + 32) {
    return null;
  }
  if (data.readBigUInt64LE(0) !== 0n) {
    return null;
  }
  const bodyLength = data.readUInt32LE(16);
  if (bodyLength < 36 || 20 + bodyLength > data.length) {
    return null;
  }
  if (data.readUInt32LE(20) !== RES_PQ) {
    return null;
  }
  return {
    nonce: Buffer.from(data.subarray(24, 40)),
    serverNonce: Buffer.from(data.subarray(40, 56)),
  };
};

/**
 * Parse a req_pq_multi message (used by tests and mock servers).
 */
export const parseReqPqMulti = (data: Buffer): Buffer | null => {
  if (data.length < 40 || data.readBigUInt64LE(0) !== 0n || data.readUInt32LE(20) !== REQ_PQ_MULTI) {
    return null;
  }
  return Buffer.from(data.subarray(24, 40));
};

/**
 * Build a resPQ reply for the given nonce (used by tests and mock servers).
 */
export const buildResPQ = (nonce: Buffer): Buffer => {
  const pq = Buffer.from([0x08, 0x17, 0xed, 0x48, 0x94, 0x1a, 0x08, 0xf9, 0x81, 0x00, 0x00, 0x00]);
  const fingerprints = Buffer.alloc(16);
  fingerprints.writeUInt32LE(0x1cb5c415, 0); // vector constructor
  fingerprints.writeUInt32LE(1, 4);
  fingerprints.writeBigUInt64LE(0xc3b42b026ce86b21n, 8);
  const body = Buffer.concat([Buffer.alloc(4), nonce, randomBytes(16), pq, fingerprints]);
  body.writeUInt32LE(RES_PQ, 0);
  const message = buildUnencryptedMessage(body, (generateMessageId() | 1n));
  return message;
};

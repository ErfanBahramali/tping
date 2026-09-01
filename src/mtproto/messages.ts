/**
 * Generate MTProto message_id.
 * Format: time.time() * 2^32, must be divisible by 4
 * Client message IDs must be divisible by 4
 */
export function generateMessageId(): bigint {
  // Get current time in seconds (with milliseconds as decimal)
  const now = Date.now() / 1000; // seconds with decimal

  // Multiply by 2^32
  let msgId = BigInt(Math.floor(now * 2 ** 32));

  // Must be divisible by 4 (client messages)
  msgId = (msgId / 4n) * 4n;

  return msgId;
}

/**
 * Build req_pq_multi message.
 * TL Schema: req_pq_multi#be7e8ef1 nonce:int128 = ResPQ;
 *
 * @param nonce - 16-byte random nonce
 * @returns TL-serialized message
 */
export function buildReqPqMulti(nonce: Buffer): Buffer {
  // Constructor ID: 0xbe7e8ef1 (little-endian)
  const constructor = Buffer.from([0xf1, 0x8e, 0x7e, 0xbe]);

  return Buffer.concat([constructor, nonce]);
}

/**
 * Build unencrypted MTProto message wrapper.
 *
 * Format:
 * - auth_key_id: 8 bytes (all zeros for unencrypted)
 * - message_id: 8 bytes
 * - message_length: 4 bytes
 * - message: N bytes
 *
 * @param tlMessage - TL-serialized message
 * @param messageId - Message ID
 * @returns Unencrypted message
 */
export function buildUnencryptedMessage(
  tlMessage: Buffer,
  messageId: bigint
): Buffer {
  const authKeyId = Buffer.alloc(8, 0); // All zeros

  const msgIdBuf = Buffer.alloc(8);
  msgIdBuf.writeBigInt64LE(messageId, 0);

  const msgLen = Buffer.alloc(4);
  msgLen.writeUInt32LE(tlMessage.length, 0);

  return Buffer.concat([authKeyId, msgIdBuf, msgLen, tlMessage]);
}

/**
 * Add Intermediate protocol length prefix.
 *
 * @param payload - Message payload
 * @returns Payload with length prefix
 */
export function addLengthPrefix(payload: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32LE(payload.length, 0);

  return Buffer.concat([length, payload]);
}

/**
 * Parse ResPQ response.
 * TL Schema: resPQ#05162463 nonce:int128 server_nonce:int128 pq:string server_public_key_fingerprints:Vector<long> = ResPQ;
 *
 * @param data - Decrypted response data
 * @returns Parsed response or null if invalid
 */
export function parseResPQ(
  data: Buffer
): { nonce: Buffer; serverNonce: Buffer; constructor: number } | null {
  try {
    let offset = 0;

    // Intermediate frame: 4-byte LE length prefix, then the unencrypted
    // MTProto envelope: auth_key_id(8) + message_id(8) + body_length(4) + body.
    if (data.length < 4) return null;
    const length = data.readUInt32LE(offset);
    offset += 4;
    if (data.length < 4 + length) return null;

    // Parse auth_key_id (8 bytes) - should be all zeros
    const authKeyId = data.slice(offset, offset + 8);
    offset += 8;
    if (!authKeyId.equals(Buffer.alloc(8, 0))) return null;

    // Parse message_id (8 bytes) - skip
    offset += 8;

    // Parse message_length (4 bytes) - skip
    offset += 4;

    // Parse constructor (4 bytes)
    const constructor = data.readUInt32LE(offset);
    offset += 4;

    // Valid constructors: 0x05162463 or 0x83c95aec
    if (constructor !== 0x05162463 && constructor !== 0x83c95aec) {
      return null;
    }
    // Parse nonce (16 bytes)
    const nonce = data.slice(offset, offset + 16);
    offset += 16;

    // Parse server_nonce (16 bytes)
    const serverNonce = data.slice(offset, offset + 16);

    return { nonce, serverNonce, constructor };
  } catch (err) {
    return null;
  }
}

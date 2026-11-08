import { randomBytes, randomInt } from 'crypto';
import type { Pipe } from '../net/stream.js';

/**
 * MTProto TCP transports (https://core.telegram.org/mtproto/mtproto-transports).
 *
 * The official clients pick the transport from the secret:
 *   no secret (direct DC, SOCKS5, HTTP) -> abridged
 *   16-byte secret                      -> intermediate
 *   dd / ee secret                      -> padded intermediate
 */
export type TransportMode = 'abridged' | 'intermediate' | 'padded';

export const PROTOCOL_TAGS: Readonly<Record<TransportMode, number>> = {
  abridged: 0xefefefef,
  intermediate: 0xeeeeeeee,
  padded: 0xdddddddd,
};

const MAX_FRAME = 1 << 24;

const TRANSPORT_ERRORS: Readonly<Record<number, string>> = {
  [-404]: 'not found',
  [-429]: 'too many connections from this IP (flood)',
  [-444]: 'invalid DC',
};

/**
 * A 4-byte frame carrying a negative error code instead of a message.
 */
export class TransportError extends Error {
  constructor(readonly code: number) {
    super(`Telegram returned transport error ${code}${TRANSPORT_ERRORS[code] ? ` (${TRANSPORT_ERRORS[code]})` : ''}`);
    this.name = 'TransportError';
  }
}

export class FramingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FramingError';
  }
}

export const encodeFrame = (mode: TransportMode, payload: Buffer): Buffer => {
  if (payload.length % 4 !== 0) {
    throw new Error('MTProto payload length must be a multiple of 4');
  }

  if (mode === 'abridged') {
    const words = payload.length / 4;
    const header = words < 0x7f
      ? Buffer.from([words])
      : Buffer.from([0x7f, words & 0xff, (words >> 8) & 0xff, (words >> 16) & 0xff]);
    return Buffer.concat([header, payload]);
  }

  const padding = mode === 'padded' ? randomBytes(randomInt(16)) : Buffer.alloc(0);
  const header = Buffer.alloc(4);
  header.writeUInt32LE(payload.length + padding.length, 0);
  return Buffer.concat([header, payload, padding]);
};

/**
 * Read one server frame. Quick-ack frames are skipped; 4-byte error frames throw TransportError.
 * For the padded transport the returned payload may carry trailing padding.
 */
export const readFrame = async (mode: TransportMode, pipe: Pipe): Promise<Buffer> => {
  for (;;) {
    let length: number;

    if (mode === 'abridged') {
      const first = (await pipe.read(1))[0];
      if (first & 0x80) {
        await pipe.read(3); // quick ack
        continue;
      }
      length = first === 0x7f ? (await pipe.read(3)).readUIntLE(0, 3) * 4 : first * 4;
    } else {
      const value = (await pipe.read(4)).readUInt32LE(0);
      if (value & 0x80000000) {
        continue; // quick ack
      }
      length = value;
    }

    if (length < 4 || length > MAX_FRAME) {
      throw new FramingError(`Invalid frame length ${length} from server (wrong secret or not an MTProto proxy)`);
    }

    const payload = await pipe.read(length);
    if (length === 4) {
      throw new TransportError(payload.readInt32LE(0));
    }
    return payload;
  }
};

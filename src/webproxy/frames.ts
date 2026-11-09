/**
 * WEB proxy shared frames: type:u8 | stream_id:u24 | payload_length:u32 | payload (big-endian).
 */

export const FRAME = {
  OPEN: 0x01,
  DATA: 0x02,
  CLOSE: 0x03,
  WINDOW: 0x04,
  PING: 0x05,
  PONG: 0x06,
  HELLO: 0x10,
  WELCOME: 0x11,
  BYE: 0x1f,
} as const;

export const MAX_FRAME_PAYLOAD = 1024 * 1024;
export const MAX_DATA_CHUNK = 64 * 1024;
const MAX_FRAMES_PER_BATCH = 4096;

export interface WebFrame {
  readonly type: number;
  readonly streamId: number;
  readonly payload: Buffer;
}

export class FrameError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FrameError';
  }
}

export const encodeWebFrame = (type: number, streamId: number, payload: Buffer = Buffer.alloc(0)): Buffer => {
  const header = Buffer.alloc(8);
  header[0] = type;
  header.writeUIntBE(streamId, 1, 3);
  header.writeUInt32BE(payload.length, 4);
  return Buffer.concat([header, payload]);
};

/** DATA frames for `data`, split into relay-sized chunks. */
export const encodeDataFrames = (streamId: number, data: Buffer): Buffer[] => {
  const frames: Buffer[] = [];
  for (let offset = 0; offset < data.length; offset += MAX_DATA_CHUNK) {
    frames.push(encodeWebFrame(FRAME.DATA, streamId, data.subarray(offset, offset + MAX_DATA_CHUNK)));
  }
  return frames;
};

/** Split a carrier body into complete frames. */
export const decodeWebFrames = (batch: Buffer): WebFrame[] => {
  const frames: WebFrame[] = [];
  let offset = 0;
  while (offset < batch.length) {
    if (batch.length - offset < 8 || frames.length >= MAX_FRAMES_PER_BATCH) {
      throw new FrameError('Invalid frame batch from relay');
    }
    const type = batch[offset];
    const streamId = batch.readUIntBE(offset + 1, 3);
    const size = batch.readUInt32BE(offset + 4);
    const end = offset + 8 + size;
    if (size > MAX_FRAME_PAYLOAD || end > batch.length || (type === FRAME.DATA && size === 0)) {
      throw new FrameError('Invalid frame from relay');
    }
    frames.push({ type, streamId, payload: batch.subarray(offset + 8, end) });
    offset = end;
  }
  return frames;
};

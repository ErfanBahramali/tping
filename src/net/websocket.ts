import { createHash, randomBytes } from 'crypto';
import type { HttpConnection } from './http-client.js';
import { readResponseHead } from './http-proxy.js';
import type { SocketStream } from './stream.js';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_MESSAGE = 4 * 1024 * 1024;

const OPCODE = { CONTINUATION: 0x0, TEXT: 0x1, BINARY: 0x2, CLOSE: 0x8, PING: 0x9, PONG: 0xa } as const;

export class WebSocketError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebSocketError';
  }
}

/**
 * Minimal RFC 6455 client: binary messages only, answers pings.
 */
export class WebSocketConnection {
  private constructor(private readonly stream: SocketStream) {}

  /**
   * Upgrade an HTTP/1.1 connection. The server must echo `protocol` exactly.
   */
  static async open(http: HttpConnection, path: string, protocol: string, origin: string): Promise<WebSocketConnection> {
    const key = randomBytes(16).toString('base64');
    http.writeRequest('GET', path, {
      Upgrade: 'websocket',
      Connection: 'Upgrade',
      'Sec-WebSocket-Key': key,
      'Sec-WebSocket-Version': '13',
      'Sec-WebSocket-Protocol': protocol,
      Origin: origin,
    });
    const head = await readResponseHead(http.stream);
    if (head.status !== 101) {
      throw new WebSocketError(`WebSocket upgrade refused (HTTP ${head.status})`);
    }
    const accept = createHash('sha1').update(key + GUID).digest('base64');
    if (head.headers.get('sec-websocket-accept') !== accept) {
      throw new WebSocketError('Invalid WebSocket handshake (bad Sec-WebSocket-Accept)');
    }
    if (head.headers.get('sec-websocket-protocol') !== protocol) {
      throw new WebSocketError('WebSocket subprotocol was not accepted');
    }
    return new WebSocketConnection(http.stream);
  }

  send(data: Buffer, opcode: number = OPCODE.BINARY): void {
    const mask = randomBytes(4);
    let header: Buffer;
    if (data.length < 126) {
      header = Buffer.from([0x80 | opcode, 0x80 | data.length]);
    } else if (data.length < 0x10000) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 126;
      header.writeUInt16BE(data.length, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(data.length), 2);
    }
    const masked = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
      masked[i] = data[i] ^ mask[i & 3];
    }
    this.stream.write(Buffer.concat([header, mask, masked]));
  }

  /** Next complete binary message. */
  async receive(): Promise<Buffer> {
    const parts: Buffer[] = [];
    let total = 0;
    for (;;) {
      const head = await this.stream.read(2);
      const fin = (head[0] & 0x80) !== 0;
      const opcode = head[0] & 0x0f;
      let length = head[1] & 0x7f;
      if (length === 126) {
        length = (await this.stream.read(2)).readUInt16BE(0);
      } else if (length === 127) {
        const big = (await this.stream.read(8)).readBigUInt64BE(0);
        if (big > BigInt(MAX_MESSAGE)) {
          throw new WebSocketError('WebSocket message too large');
        }
        length = Number(big);
      }
      const mask = head[1] & 0x80 ? await this.stream.read(4) : undefined;
      const payload = await this.stream.read(length);
      if (mask) {
        for (let i = 0; i < payload.length; i++) {
          payload[i] ^= mask[i & 3];
        }
      }

      switch (opcode) {
        case OPCODE.PING:
          this.send(payload, OPCODE.PONG);
          continue;
        case OPCODE.PONG:
          continue;
        case OPCODE.CLOSE: {
          const code = payload.length >= 2 ? payload.readUInt16BE(0) : undefined;
          const reason = payload.subarray(2).toString('utf8');
          throw new WebSocketError(`Relay closed the WebSocket${code ? ` (${code}${reason ? ` ${reason}` : ''})` : ''}`);
        }
        case OPCODE.TEXT:
          throw new WebSocketError('Unexpected text message from relay');
        default:
          break;
      }

      total += payload.length;
      if (total > MAX_MESSAGE) {
        throw new WebSocketError('WebSocket message too large');
      }
      parts.push(payload);
      if (fin) {
        return Buffer.concat(parts);
      }
    }
  }
}

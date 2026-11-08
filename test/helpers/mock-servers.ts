// Local mock servers implementing the server side of each protocol, so the
// whole client stack can be tested end-to-end without network access.
import { createServer, connect, type Server, type Socket, type AddressInfo } from 'net';
import { createHash, createHmac, randomBytes } from 'crypto';
import { SocketStream, type Pipe } from '../../src/net/stream.js';
import { AESCTR } from '../../src/crypto/aes-ctr.js';
import { PROTOCOL_TAGS, encodeFrame, readFrame, type TransportMode } from '../../src/mtproto/transport.js';
import { buildResPQ, parseReqPqMulti } from '../../src/mtproto/messages.js';

export interface MockServer {
  readonly port: number;
  close(): Promise<void>;
}

export interface SeenRequest {
  readonly dc: number;
  readonly mode: TransportMode;
  readonly clientHelloLength?: number;
}

const listen = async (handler: (socket: Socket) => void): Promise<{ server: Server; port: number }> => {
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    handler(socket);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const close = server.close.bind(server);
  server.close = ((cb?: (err?: Error) => void) => {
    sockets.forEach((s) => s.destroy());
    return close(cb);
  }) as typeof server.close;
  return { server, port: (server.address() as AddressInfo).port };
};

const toMock = (server: Server, port: number): MockServer => ({
  port,
  close: () => new Promise((resolve) => server.close(() => resolve())),
});

const derive = (material: Buffer, secret?: Buffer): Buffer =>
  secret ? createHash('sha256').update(material).update(secret).digest() : Buffer.from(material);

const MODE_BY_TAG = new Map<number, TransportMode>(
  (Object.entries(PROTOCOL_TAGS) as [TransportMode, number][]).map(([mode, tag]) => [tag, mode])
);

/**
 * Server side of obfuscated2 + one req_pq_multi -> resPQ exchange.
 */
const serveObfuscated = async (pipe: Pipe, secret: Buffer | undefined, onSeen: (seen: SeenRequest) => void, extra: Partial<SeenRequest> = {}): Promise<void> => {
  const header = await pipe.read(64);
  const reversed = Buffer.from(header.subarray(8, 56)).reverse();
  const decryptor = new AESCTR(derive(header.subarray(8, 40), secret), Buffer.from(header.subarray(40, 56)));
  const encryptor = new AESCTR(derive(reversed.subarray(0, 32), secret), Buffer.from(reversed.subarray(32, 48)));
  const plain = decryptor.encrypt(header);
  const mode = MODE_BY_TAG.get(plain.readUInt32LE(56));
  if (!mode) {
    throw new Error('bad protocol tag (wrong secret)');
  }
  const dc = plain.readInt16LE(60);
  const inner: Pipe = {
    write: (data) => pipe.write(encryptor.encrypt(data)),
    read: async (n) => decryptor.encrypt(await pipe.read(n)),
  };
  const nonce = parseReqPqMulti(await readFrame(mode, inner));
  if (!nonce) {
    throw new Error('not a req_pq_multi');
  }
  onSeen({ dc, mode, ...extra });
  inner.write(encodeFrame(mode, buildResPQ(nonce)));
};

const record = (type: number, payload: Buffer): Buffer => {
  const head = Buffer.alloc(5);
  head[0] = type;
  head.writeUInt16BE(0x0303, 1);
  head.writeUInt16BE(payload.length, 3);
  return Buffer.concat([head, payload]);
};

/** Server-side TLS record pipe: skips the client's ChangeCipherSpec, accepts Application Data. */
class ServerTlsPipe implements Pipe {
  private incoming = Buffer.alloc(0);
  constructor(private readonly stream: SocketStream) {}
  write(data: Buffer): void {
    this.stream.write(record(0x17, data));
  }
  async read(n: number): Promise<Buffer> {
    while (this.incoming.length < n) {
      const head = await this.stream.read(5);
      const body = await this.stream.read(head.readUInt16BE(3));
      if (head[0] === 0x17) {
        this.incoming = Buffer.concat([this.incoming, body]);
      } else if (head[0] !== 0x14) {
        throw new Error('unexpected record');
      }
    }
    const out = this.incoming.subarray(0, n);
    this.incoming = this.incoming.subarray(n);
    return out;
  }
}

export interface MockMtproxyOptions {
  /** 16-byte proxy key. */
  readonly key: Buffer;
  /** Enables fake TLS with this domain. */
  readonly domain?: string;
  readonly onSeen?: (seen: SeenRequest) => void;
}

/**
 * MTProxy-like server. On a bad fake-TLS ClientHello it answers like the real
 * domain would (a TLS response without our HMAC); on a bad obfuscation header
 * it drops the connection, as the official MTProxy does.
 */
export const startMockMtproxy = async (options: MockMtproxyOptions): Promise<MockServer> => {
  const { server, port } = await listen((socket) => {
    const stream = new SocketStream(socket);
    (async () => {
      let pipe: Pipe = stream;
      let clientHelloLength: number | undefined;
      if (options.domain !== undefined) {
        const head = await stream.read(5);
        const packet = Buffer.concat([head, await stream.read(head.readUInt16BE(3))]);
        clientHelloLength = packet.length;
        const clientRandom = Buffer.from(packet.subarray(11, 43));
        const zeroed = Buffer.from(packet);
        zeroed.fill(0, 11, 43);
        const expected = createHmac('sha256', options.key).update(zeroed).digest();
        const timestamp = (expected.readUInt32LE(28) ^ clientRandom.readUInt32LE(28)) >>> 0;
        const valid = head[0] === 0x16
          && expected.subarray(0, 28).equals(clientRandom.subarray(0, 28))
          && Math.abs(timestamp - Date.now() / 1000) < 120
          && packet.includes(Buffer.from(options.domain));

        const response = Buffer.concat([
          record(0x16, randomBytes(90)),
          Buffer.from('140303000101', 'hex'),
          record(0x17, randomBytes(120)),
        ]);
        if (valid) {
          response.fill(0, 11, 43);
          createHmac('sha256', options.key).update(clientRandom).update(response).digest().copy(response, 11);
        }
        stream.write(response);
        if (!valid) {
          return;
        }
        pipe = new ServerTlsPipe(stream);
      }
      await serveObfuscated(pipe, options.key, options.onSeen ?? (() => {}), { clientHelloLength });
    })().catch(() => socket.destroy());
  });
  return toMock(server, port);
};

/**
 * Telegram DC-like server: obfuscated2 without a secret.
 */
export const startMockDatacenter = async (onSeen: (seen: SeenRequest) => void = () => {}): Promise<MockServer> => {
  const { server, port } = await listen((socket) => {
    serveObfuscated(new SocketStream(socket), undefined, onSeen).catch(() => socket.destroy());
  });
  return toMock(server, port);
};

/** Server that accepts connections and never answers. */
export const startSilentServer = async (): Promise<MockServer> => {
  const { server, port } = await listen(() => {});
  return toMock(server, port);
};

const relay = (client: Socket, host: string, port: number, onReady: () => void): void => {
  const upstream = connect({ host, port }, () => {
    onReady();
    client.removeAllListeners('data');
    client.pipe(upstream);
    upstream.pipe(client);
  });
  upstream.on('error', () => client.destroy());
  client.on('close', () => upstream.destroy());
};

export interface MockSocksOptions {
  readonly username?: string;
  readonly password?: string;
}

export const startMockSocks5 = async (options: MockSocksOptions = {}): Promise<MockServer> => {
  const requireAuth = options.username !== undefined;
  const { server, port } = await listen((socket) => {
    const stream = new SocketStream(socket);
    (async () => {
      const greeting = await stream.read(2);
      const methods = await stream.read(greeting[1]);
      if (requireAuth) {
        if (!methods.includes(0x02)) {
          stream.write(Buffer.from([0x05, 0xff]));
          return;
        }
        stream.write(Buffer.from([0x05, 0x02]));
        await stream.read(1);
        const user = (await stream.read((await stream.read(1))[0])).toString();
        const pass = (await stream.read((await stream.read(1))[0])).toString();
        const ok = user === options.username && pass === options.password;
        stream.write(Buffer.from([0x01, ok ? 0x00 : 0x01]));
        if (!ok) return;
      } else {
        stream.write(Buffer.from([0x05, 0x00]));
      }
      const request = await stream.read(4);
      if (request[3] !== 0x01) throw new Error('mock only supports IPv4');
      const host = [...(await stream.read(4))].join('.');
      const targetPort = (await stream.read(2)).readUInt16BE(0);
      relay(socket, host, targetPort, () => stream.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])));
    })().catch(() => socket.destroy());
  });
  return toMock(server, port);
};

export interface MockHttpProxyOptions {
  readonly allowConnect?: boolean;
  readonly username?: string;
  readonly password?: string;
}

export const startMockHttpProxy = async (options: MockHttpProxyOptions = {}): Promise<MockServer> => {
  const { server, port } = await listen((socket) => {
    const stream = new SocketStream(socket);
    (async () => {
      const head = (await stream.readUntil(Buffer.from('\r\n\r\n'), 8192)).toString('latin1');
      const [requestLine, ...lines] = head.split('\r\n');
      const [method, target] = requestLine.split(' ');
      if (options.username !== undefined) {
        const expected = `Basic ${Buffer.from(`${options.username}:${options.password ?? ''}`).toString('base64')}`;
        if (!lines.some((l) => l.toLowerCase() === `proxy-authorization: ${expected.toLowerCase()}`)) {
          stream.write(Buffer.from('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n'));
          return;
        }
      }
      if (method === 'CONNECT') {
        if (options.allowConnect === false) {
          stream.write(Buffer.from('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'));
          return;
        }
        const colon = target.lastIndexOf(':');
        relay(socket, target.slice(0, colon), Number(target.slice(colon + 1)), () =>
          stream.write(Buffer.from('HTTP/1.1 200 Connection established\r\n\r\n')));
        return;
      }
      if (method === 'POST' && target.endsWith('/api')) {
        const length = Number(lines.find((l) => l.toLowerCase().startsWith('content-length:'))?.split(':')[1]);
        const nonce = parseReqPqMulti(await stream.read(length));
        if (!nonce) throw new Error('bad body');
        const body = buildResPQ(nonce);
        stream.write(Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n`), body]));
        return;
      }
      stream.write(Buffer.from('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n'));
    })().catch(() => socket.destroy());
  });
  return toMock(server, port);
};

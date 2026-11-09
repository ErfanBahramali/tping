// Mock WEB proxy relay (server side of telegramdesktop/tproxy-server protocol v1)
// over real HTTPS with a self-signed certificate.
import { createServer as createHttpsServer, type Server } from 'https';
import type { IncomingMessage, ServerResponse } from 'http';
import { connect, type Socket, type AddressInfo } from 'net';
import { createHash, randomBytes } from 'crypto';
import { execFileSync } from 'child_process';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SocketStream } from '../../src/net/stream.js';
import { basePrefix, deriveCapability } from '../../src/webproxy/link.js';
import { FRAME, decodeWebFrames, encodeWebFrame } from '../../src/webproxy/frames.js';
import type { CarrierMode } from '../../src/types/index.js';

export interface TestCertificate {
  readonly cert: Buffer;
  readonly key: Buffer;
}

export const hasOpenssl = (): boolean => {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
};

export const createCertificate = (hostname: string): TestCertificate => {
  const dir = mkdtempSync(join(tmpdir(), 'tping-cert-'));
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-subj', `/CN=${hostname}`, '-addext', `subjectAltName=DNS:${hostname}`, '-days', '1',
      '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'),
    ], { stdio: 'ignore' });
    return { cert: readFileSync(join(dir, 'cert.pem')), key: readFileSync(join(dir, 'key.pem')) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

export interface MockRelayOptions {
  readonly hostname: string;
  readonly basePath?: string;
  /** Client-facing secret bytes (16, or 17 with dd). */
  readonly secret: Buffer;
  readonly carrier: CarrierMode;
  /** TCP port of the MTProxy backend. */
  readonly backendPort: number;
  readonly certificate: TestCertificate;
  /** Close every stream right after OPEN (backend refuses). */
  readonly rejectStreams?: boolean;
}

export interface MockRelay {
  readonly port: number;
  readonly stats: { sessions: number; deleted: number; streams: number };
  close(): Promise<void>;
}

const token = (): string => randomBytes(32).toString('base64url');

interface Lane {
  queue: Buffer[];
  waiter: (() => void) | null;
  sequence: number;
  cursor: number;
}

interface RelaySession {
  readonly backends: Map<number, Socket>;
  readonly lanes: Map<number, Lane>;
  /** WebSocket senders per stream (lane id), or 0 for the multiplexed socket. */
  readonly sockets: Map<number, (data: Buffer) => void>;
}

export const startMockRelay = async (options: MockRelayOptions): Promise<MockRelay> => {
  const base = basePrefix(options.basePath ?? '');
  const capability = deriveCapability({ host: options.hostname, basePath: options.basePath ?? '' }, options.secret);
  const bootstraps = new Set<string>();
  const sessions = new Map<string, RelaySession>();
  const stats = { sessions: 0, deleted: 0, streams: 0 };
  const lanesMode = options.carrier.endsWith('-lanes');

  const laneOf = (session: RelaySession, streamId: number): Lane => {
    const id = lanesMode ? streamId : 0;
    let lane = session.lanes.get(id);
    if (!lane) {
      lane = { queue: [], waiter: null, sequence: 1, cursor: 0 };
      session.lanes.set(id, lane);
    }
    return lane;
  };

  const emit = (session: RelaySession, streamId: number, frame: Buffer): void => {
    const send = session.sockets.get(lanesMode ? streamId : 0);
    if (send) {
      send(frame);
      return;
    }
    const lane = laneOf(session, streamId);
    lane.queue.push(frame);
    lane.waiter?.();
  };

  const applyFrames = (session: RelaySession, body: Buffer): void => {
    for (const frame of decodeWebFrames(body)) {
      if (frame.type === FRAME.OPEN) {
        stats.streams++;
        if (options.rejectStreams) {
          emit(session, frame.streamId, encodeWebFrame(FRAME.CLOSE, frame.streamId));
          continue;
        }
        const backend = connect({ host: '127.0.0.1', port: options.backendPort });
        backend.on('data', (data: Buffer) => emit(session, frame.streamId, encodeWebFrame(FRAME.DATA, frame.streamId, data)));
        backend.on('close', () => emit(session, frame.streamId, encodeWebFrame(FRAME.CLOSE, frame.streamId)));
        backend.on('error', () => {});
        session.backends.set(frame.streamId, backend);
      } else if (frame.type === FRAME.DATA) {
        session.backends.get(frame.streamId)?.write(frame.payload);
      } else if (frame.type === FRAME.CLOSE) {
        session.backends.get(frame.streamId)?.destroy();
      }
    }
  };

  const readBody = (request: IncomingMessage): Promise<Buffer> =>
    new Promise((resolve) => {
      const parts: Buffer[] = [];
      request.on('data', (chunk: Buffer) => parts.push(chunk));
      request.on('end', () => resolve(Buffer.concat(parts)));
    });

  const notFound = (response: ServerResponse): void => {
    response.writeHead(404, { 'Content-Length': '0' }).end();
  };

  const bearer = (request: IncomingMessage): string => (request.headers.authorization ?? '').replace(/^Bearer /, '');

  const handler = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    const body = await readBody(request);
    const url = request.url ?? '/';
    if (request.headers.host !== options.hostname) {
      notFound(response);
      return;
    }

    if (request.method === 'GET' && url === `${base}?bridge=${capability}`) {
      const bootstrap = token();
      bootstraps.add(bootstrap);
      const html = `<!doctype html><script nonce="x">(()=>{'use strict';\nconst relayBase=${JSON.stringify(`https://${options.hostname}${base}`)},bootstrap=${JSON.stringify(bootstrap)},carrierMode=${JSON.stringify(options.carrier)};\n})();</script>`;
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(html);
      return;
    }

    if (url === `${base}api/v1/session` && request.method === 'POST') {
      const bootstrap = bearer(request);
      const frames = decodeWebFrames(body);
      if (!bootstraps.delete(bootstrap) || request.headers['content-type'] !== 'application/octet-stream'
        || frames.length !== 1 || frames[0].type !== FRAME.HELLO) {
        notFound(response);
        return;
      }
      const sessionToken = token();
      sessions.set(sessionToken, { backends: new Map(), lanes: new Map(), sockets: new Map() });
      stats.sessions++;
      response.writeHead(200, {
        'X-Session-Token': sessionToken,
        'X-Down-Cursor': '0',
        'X-Carrier-Mode': options.carrier,
        'Content-Type': 'application/octet-stream',
      }).end(encodeWebFrame(FRAME.WELCOME, 0));
      return;
    }

    if (url === `${base}api/v1/session` && request.method === 'DELETE') {
      const session = sessions.get(bearer(request));
      if (!session) {
        notFound(response);
        return;
      }
      session.backends.forEach((backend) => backend.destroy());
      sessions.delete(bearer(request));
      stats.deleted++;
      response.writeHead(204).end();
      return;
    }

    const session = sessions.get(bearer(request));
    const laneHeader = request.headers['x-lane-id'];
    const laneId = laneHeader === undefined ? 0 : Number(laneHeader);
    if (!session || lanesMode !== (laneHeader !== undefined) || request.method !== 'POST') {
      notFound(response);
      return;
    }
    const lane = laneOf(session, laneId);

    if (url === `${base}api/v1/up`) {
      if (request.headers['content-type'] !== 'application/octet-stream' || request.headers['x-up-seq'] !== String(lane.sequence)) {
        notFound(response);
        return;
      }
      applyFrames(session, body);
      response.writeHead(204, { 'X-Up-Ack': String(lane.sequence) }).end();
      lane.sequence++;
      return;
    }

    if (url === `${base}api/v1/down`) {
      if (request.headers['content-type'] !== undefined || request.headers['x-down-cursor'] !== String(lane.cursor)) {
        notFound(response);
        return;
      }
      if (lane.queue.length === 0) {
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, 1000);
          lane.waiter = () => {
            clearTimeout(timer);
            resolve();
          };
        });
        lane.waiter = null;
      }
      if (lane.queue.length === 0) {
        response.writeHead(204, { 'X-Down-Cursor': String(lane.cursor) }).end();
        return;
      }
      lane.cursor++;
      response.writeHead(200, { 'X-Down-Cursor': String(lane.cursor), 'Content-Type': 'application/octet-stream' })
        .end(Buffer.concat(lane.queue.splice(0)));
      return;
    }

    notFound(response);
  };

  const server: Server = createHttpsServer({ cert: options.certificate.cert, key: options.certificate.key }, (request, response) => {
    handler(request, response).catch(() => response.destroy());
  });

  server.on('upgrade', (request: IncomingMessage, socket: Socket, head: Buffer) => {
    const protocol = String(request.headers['sec-websocket-protocol'] ?? '');
    const match = /^tproxy-(lane-)?v1\.([A-Za-z0-9_-]{43})(?:\.(\d+))?$/.exec(protocol);
    const session = match ? sessions.get(match[2]) : undefined;
    if (request.url !== `${base}api/v1/ws` || !match || !session || Boolean(match[1]) !== lanesMode || request.headers.authorization) {
      socket.end('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    const accept = createHash('sha1').update(`${request.headers['sec-websocket-key']}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: ${protocol}\r\n\r\n`);
    if (head.length) socket.unshift(head);

    const send = (data: Buffer): void => {
      const header = data.length < 126 ? Buffer.from([0x82, data.length]) : Buffer.from([0x82, 126, data.length >> 8, data.length & 0xff]);
      socket.write(Buffer.concat([header, data]));
    };
    session.sockets.set(match[3] ? Number(match[3]) : 0, send);

    const stream = new SocketStream(socket);
    (async () => {
      for (;;) {
        const h = await stream.read(2);
        let length = h[1] & 0x7f;
        if (length === 126) length = (await stream.read(2)).readUInt16BE(0);
        const mask = await stream.read(4);
        const payload = await stream.read(length);
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
        if ((h[0] & 0x0f) === 0x8) break;
        applyFrames(session, payload);
      }
    })().catch(() => {}).finally(() => socket.destroy());
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as AddressInfo).port,
    stats,
    close: () => new Promise((resolve) => {
      sessions.forEach((s) => s.backends.forEach((b) => b.destroy()));
      server.closeAllConnections?.();
      server.close(() => resolve());
    }),
  };
};

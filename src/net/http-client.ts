import { connect as tlsConnect } from 'tls';
import type { Attempt } from '../lib/attempt.js';
import type { SocketStream } from './stream.js';
import { readResponseHead, type HttpResponseHead } from './http-proxy.js';

const CRLF = Buffer.from('\r\n');
const MAX_BODY = 8 * 1024 * 1024;

export interface HttpResponse extends HttpResponseHead {
  readonly body: Buffer;
}

export interface TlsEndpoint {
  /** Where to connect (defaults to the hostname). */
  readonly host?: string;
  readonly port?: number;
  /** Extra trusted CA (tests). */
  readonly ca?: Buffer;
}

export interface TlsConnection {
  readonly stream: SocketStream;
  /** TCP connect time in ms. */
  readonly tcp: number;
  /** TLS handshake time in ms. */
  readonly tls: number;
}

/**
 * Open a certificate-verified TLS connection with SNI set to `hostname`,
 * speaking HTTP/1.1 (needed for the WebSocket upgrade).
 */
export const openTls = async (attempt: Attempt, hostname: string, endpoint: TlsEndpoint = {}): Promise<TlsConnection> => {
  const start = Date.now();
  let tcpAt = start;
  const socket = tlsConnect({
    host: endpoint.host ?? hostname,
    port: endpoint.port ?? 443,
    servername: hostname,
    ALPNProtocols: ['http/1.1'],
    ...(endpoint.ca ? { ca: endpoint.ca } : {}),
  });
  socket.once('connect', () => {
    tcpAt = Date.now();
  });
  const stream = attempt.newStream(socket, 'secureConnect');
  await stream.ready();
  const end = Date.now();
  return { stream, tcp: tcpAt - start, tls: end - tcpAt };
};

const readChunked = async (stream: SocketStream): Promise<Buffer> => {
  const parts: Buffer[] = [];
  let total = 0;
  for (;;) {
    const line = (await stream.readUntil(CRLF, 1024)).toString('latin1');
    const size = parseInt(line.split(';')[0].trim(), 16);
    if (!Number.isFinite(size) || size < 0) {
      throw new Error('Invalid chunked response');
    }
    if (size === 0) {
      while ((await stream.readUntil(CRLF, 8192)).length > 2) {
        // Skip trailers.
      }
      return Buffer.concat(parts);
    }
    total += size;
    if (total > MAX_BODY) {
      throw new Error('Response body too large');
    }
    parts.push(await stream.read(size));
    await stream.read(2);
  }
};

/**
 * Minimal keep-alive HTTP/1.1 client over one connection (one request at a time).
 */
export class HttpConnection {
  constructor(readonly stream: SocketStream, private readonly hostname: string) {}

  writeRequest(method: string, path: string, headers: Readonly<Record<string, string>>, body?: Buffer): void {
    const lines = [`${method} ${path} HTTP/1.1`, `Host: ${this.hostname}`];
    for (const [name, value] of Object.entries(headers)) {
      lines.push(`${name}: ${value}`);
    }
    if (body || method === 'POST' || method === 'DELETE') {
      lines.push(`Content-Length: ${body?.length ?? 0}`);
    }
    this.stream.write(Buffer.concat([Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1'), body ?? Buffer.alloc(0)]));
  }

  async request(method: string, path: string, headers: Readonly<Record<string, string>>, body?: Buffer): Promise<HttpResponse> {
    this.writeRequest(method, path, headers, body);
    const head = await readResponseHead(this.stream);
    return { ...head, body: await this.readBody(method, head) };
  }

  private async readBody(method: string, head: HttpResponseHead): Promise<Buffer> {
    if (method === 'HEAD' || head.status === 204 || head.status === 304 || (head.status >= 100 && head.status < 200)) {
      return Buffer.alloc(0);
    }
    if (head.headers.get('transfer-encoding')?.toLowerCase().includes('chunked')) {
      return readChunked(this.stream);
    }
    const length = head.headers.get('content-length');
    if (length !== undefined) {
      const size = Number(length);
      if (!Number.isSafeInteger(size) || size < 0 || size > MAX_BODY) {
        throw new Error('Invalid Content-Length');
      }
      return this.stream.read(size);
    }
    return this.stream.readToEnd(MAX_BODY);
  }
}

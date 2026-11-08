import { isIPv6 } from 'net';
import type { SocketStream } from './stream.js';

export class HttpProxyError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = 'HttpProxyError';
  }
}

export interface HttpCredentials {
  readonly username?: string;
  readonly password?: string;
}

const HEADER_END = Buffer.from('\r\n\r\n');
const MAX_HEADER = 16 * 1024;

const hostPort = (host: string, port: number): string => `${isIPv6(host) ? `[${host}]` : host}:${port}`;

const authHeader = (credentials: HttpCredentials): string =>
  credentials.username || credentials.password
    ? `Proxy-Authorization: Basic ${Buffer.from(`${credentials.username ?? ''}:${credentials.password ?? ''}`).toString('base64')}\r\n`
    : '';

export interface HttpResponseHead {
  readonly status: number;
  readonly reason: string;
  readonly headers: ReadonlyMap<string, string>;
}

export const readResponseHead = async (stream: SocketStream): Promise<HttpResponseHead> => {
  const raw = (await stream.readUntil(HEADER_END, MAX_HEADER)).toString('latin1');
  const [statusLine, ...lines] = raw.split('\r\n');
  const match = /^HTTP\/\d(?:\.\d)?\s+(\d{3})\s*(.*)$/.exec(statusLine);
  if (!match) {
    throw new HttpProxyError('Not an HTTP proxy (invalid status line)');
  }
  const headers = new Map<string, string>();
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon > 0) {
      headers.set(line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim());
    }
  }
  return { status: Number(match[1]), reason: match[2], headers };
};

const statusError = (head: HttpResponseHead, action: string): HttpProxyError => {
  if (head.status === 407) {
    return new HttpProxyError('HTTP proxy requires authentication (407) or credentials are wrong', 407);
  }
  return new HttpProxyError(`HTTP proxy refused ${action}: ${head.status} ${head.reason}`.trim(), head.status);
};

/**
 * Open a TCP tunnel with the CONNECT method (what Telegram Desktop does through an HTTP proxy).
 */
export const httpConnect = async (
  stream: SocketStream,
  host: string,
  port: number,
  credentials: HttpCredentials
): Promise<void> => {
  const target = hostPort(host, port);
  stream.write(Buffer.from(
    `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Connection: keep-alive\r\n${authHeader(credentials)}\r\n`,
    'latin1'
  ));
  const head = await readResponseHead(stream);
  if (head.status < 200 || head.status >= 300) {
    throw statusError(head, 'CONNECT');
  }
};

/**
 * Send one MTProto message with the HTTP transport (POST http://<dc>:80/api)
 * through the proxy and return the response body. Telegram Desktop falls back
 * to this transport when TCP through the proxy does not work.
 */
export const httpTransportRequest = async (
  stream: SocketStream,
  host: string,
  port: number,
  credentials: HttpCredentials,
  body: Buffer
): Promise<Buffer> => {
  const target = hostPort(host, port);
  stream.write(Buffer.concat([
    Buffer.from(
      `POST http://${target}/api HTTP/1.1\r\nHost: ${target}\r\nConnection: keep-alive\r\n` +
      `Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ${body.length}\r\n${authHeader(credentials)}\r\n`,
      'latin1'
    ),
    body,
  ]));
  const head = await readResponseHead(stream);
  if (head.status !== 200) {
    throw statusError(head, 'the HTTP transport request');
  }
  const length = Number(head.headers.get('content-length'));
  if (!Number.isInteger(length) || length <= 0 || length > 1 << 20) {
    throw new HttpProxyError('HTTP transport response has no valid Content-Length');
  }
  return stream.read(length);
};

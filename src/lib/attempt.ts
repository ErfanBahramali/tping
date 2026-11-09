import type { Socket } from 'net';
import { SocketStream, StreamClosedError } from '../net/stream.js';

export class TimeoutError extends Error {
  constructor() {
    super('Timeout');
    this.name = 'TimeoutError';
  }
}

export class AbortedError extends Error {
  constructor() {
    super('Aborted');
    this.name = 'AbortedError';
  }
}

export const STAGE_CONNECTING = 'connecting to proxy';
export const STAGE_WAITING = 'waiting for Telegram';

/**
 * One check: a deadline and an abort signal shared by every connection it opens,
 * plus the current phase for error messages.
 */
export class Attempt {
  stage = STAGE_CONNECTING;
  private readonly streams = new Set<SocketStream>();
  private primary?: SocketStream;
  private failure?: Error;
  private readonly timer: NodeJS.Timeout;
  private readonly onAbort = (): void => this.failAll(new AbortedError());

  constructor(deadline: number, private readonly signal?: AbortSignal) {
    this.timer = setTimeout(() => this.failAll(new TimeoutError()), Math.max(0, deadline - Date.now()));
    if (signal?.aborted) {
      this.onAbort();
    }
    signal?.addEventListener('abort', this.onAbort, { once: true });
  }

  /** The default TCP stream, created on first use. */
  get stream(): SocketStream {
    this.primary ??= this.newStream();
    return this.primary;
  }

  newStream(socket?: Socket, readyEvent?: string): SocketStream {
    const stream = new SocketStream(socket, readyEvent);
    if (this.failure) {
      stream.fail(this.failure);
    }
    this.streams.add(stream);
    return stream;
  }

  close(): void {
    clearTimeout(this.timer);
    this.signal?.removeEventListener('abort', this.onAbort);
    this.streams.forEach((stream) => stream.destroy());
  }

  private failAll(err: Error): void {
    this.failure ??= err;
    this.streams.forEach((stream) => stream.fail(err));
  }
}

const NETWORK_ERRORS: Readonly<Record<string, string>> = {
  ECONNREFUSED: 'Connection refused',
  ENOTFOUND: 'DNS lookup failed (unknown host)',
  EAI_AGAIN: 'DNS lookup failed (temporary)',
  EHOSTUNREACH: 'Host unreachable',
  ENETUNREACH: 'Network unreachable',
  ETIMEDOUT: 'Connection timed out',
  EPIPE: 'Connection broken',
};

const CERTIFICATE_ERROR = /CERT|SELF_SIGNED|ALTNAME|UNABLE_TO_(GET|VERIFY)/;
const TLS_HANDSHAKE_ERROR = /^ERR_(SSL|TLS)_/;

export const describeError = (err: unknown, stage: string): string => {
  if (err instanceof TimeoutError) {
    return `Timeout while ${stage}`;
  }
  if (err instanceof StreamClosedError) {
    return stage === STAGE_WAITING
      ? 'Proxy closed the connection before Telegram answered (wrong secret, or the proxy cannot reach Telegram)'
      : `Connection closed while ${stage}`;
  }
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  if (code === 'ECONNRESET') {
    return `Connection reset while ${stage}`;
  }
  if (code && NETWORK_ERRORS[code]) {
    return NETWORK_ERRORS[code];
  }
  if (code && CERTIFICATE_ERROR.test(code)) {
    return `TLS certificate error (${code})`;
  }
  if (code && TLS_HANDSHAKE_ERROR.test(code)) {
    return `TLS handshake failed, not a normal HTTPS server (${code})`;
  }
  return err instanceof Error ? err.message : String(err);
};

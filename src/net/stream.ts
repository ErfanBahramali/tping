import { Socket } from 'net';

/**
 * A byte pipe that higher layers (fake TLS, obfuscation) can stack on.
 */
export interface Pipe {
  write(data: Buffer): void;
  read(length: number): Promise<Buffer>;
}

/**
 * Raised when the remote side closes the connection.
 */
export class StreamClosedError extends Error {
  constructor() {
    super('Connection closed by remote');
    this.name = 'StreamClosedError';
  }
}

/**
 * Promise-based wrapper around a TCP socket: exact-length reads, and a single
 * `fail()` entry point used for timeouts and aborts.
 *
 * Buffered data is always delivered before a close/error is reported, so a
 * server that answers and immediately hangs up is still read correctly.
 */
export class SocketStream implements Pipe {
  private buffer: Buffer = Buffer.alloc(0);
  private pending: (() => void) | null = null;
  private failure: Error | null = null;
  private connected: boolean;
  readonly socket: Socket;

  /**
   * @param socket - existing socket; treated as connected unless `readyEvent` is given
   * @param readyEvent - event that marks the socket as ready (e.g. 'secureConnect' for TLS)
   */
  constructor(socket?: Socket, readyEvent?: string) {
    this.socket = socket ?? new Socket();
    this.connected = socket !== undefined && readyEvent === undefined;
    this.socket.setNoDelay(true);
    this.socket.on(readyEvent ?? 'connect', () => {
      this.connected = true;
      this.pending?.();
    });
    this.socket.on('data', (chunk: Buffer) => {
      this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
      this.pending?.();
    });
    this.socket.on('error', (err) => this.fail(err));
    this.socket.on('close', () => this.fail(new StreamClosedError()));
  }

  connect(host: string, port: number): Promise<void> {
    if (!this.failure) {
      this.socket.connect({ host, port });
    }
    return this.ready();
  }

  /** Resolves once the socket is connected (or its ready event fired). */
  ready(): Promise<void> {
    return this.waitFor(() => (this.connected ? true : undefined)).then(() => undefined);
  }

  write(data: Buffer): void {
    if (!this.failure && data.length > 0) {
      this.socket.write(data);
    }
  }

  read(length: number): Promise<Buffer> {
    return this.waitFor(() => {
      if (this.buffer.length < length) {
        return undefined;
      }
      const out = Buffer.from(this.buffer.subarray(0, length));
      this.buffer = this.buffer.subarray(length);
      return out;
    });
  }

  /**
   * Read up to and including `delimiter`. Fails if it does not show up within `maxLength` bytes.
   */
  readUntil(delimiter: Buffer, maxLength: number): Promise<Buffer> {
    return this.waitFor(() => {
      const index = this.buffer.indexOf(delimiter);
      if (index === -1) {
        if (this.buffer.length > maxLength) {
          throw new Error('Response header too large');
        }
        return undefined;
      }
      const end = index + delimiter.length;
      const out = Buffer.from(this.buffer.subarray(0, end));
      this.buffer = this.buffer.subarray(end);
      return out;
    });
  }

  /**
   * Read everything until the remote side closes the connection.
   */
  readToEnd(maxLength: number): Promise<Buffer> {
    return this.waitFor(() => {
      if (this.buffer.length > maxLength) {
        throw new Error('Response body too large');
      }
      if (!(this.failure instanceof StreamClosedError)) {
        return undefined;
      }
      const out = Buffer.from(this.buffer);
      this.buffer = Buffer.alloc(0);
      return out;
    });
  }

  /**
   * Abort the stream: pending and future reads reject with `err`.
   * Only the first failure is kept.
   */
  fail(err: Error): void {
    if (!this.failure) {
      this.failure = err;
    }
    this.socket.destroy();
    this.pending?.();
  }

  destroy(): void {
    this.socket.destroy();
  }

  private waitFor<T>(attempt: () => T | undefined): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const tick = (): void => {
        try {
          const value = attempt();
          if (value !== undefined) {
            this.pending = null;
            resolve(value);
            return;
          }
        } catch (err) {
          this.pending = null;
          reject(err);
          return;
        }
        if (this.failure) {
          this.pending = null;
          reject(this.failure);
        }
      };
      this.pending = tick;
      tick();
    });
  }
}

import { Socket } from 'net';
import { randomBytes } from 'crypto';
import { AESCTR } from '../crypto/aes-ctr.js';
import { initObfuscation } from './obfuscation.js';
import {
  parseSecret,
  generateFakeTLSClientHello,
  wrapInTLSRecords,
  extractTlsRecords,
  tryVerifyFakeTLSServerHello,
} from './fake-tls.js';
import {
  buildReqPqMulti,
  buildUnencryptedMessage,
  generateMessageId,
  parseResPQ,
} from './messages.js';

export interface MTProtoConnectionOptions {
  host: string;
  port: number;
  secret: string; // Hex-encoded secret (with or without dd/ee prefix)
  dcId?: number; // Telegram datacenter ID (default: 2)
  timeout?: number; // Handshake timeout in ms (default: 10000)
}

type Phase = 'handshake' | 'ping' | 'done';

/**
 * MTProto proxy connection supporting both simple (dd) and fake TLS (ee) modes.
 *
 * A ping is a real MTProto handshake: req_pq_multi is sent and a valid ResPQ
 * must come back from the Telegram datacenter. In fake TLS mode the proxy's
 * ServerHello is also verified against an HMAC of the proxy secret, so a wrong
 * secret is detected immediately.
 */
export class MTProtoConnection {
  private socket: Socket;
  private encryptor?: AESCTR;
  private decryptor?: AESCTR;
  private isFakeTLS = false;
  private receiveBuffer = Buffer.alloc(0);
  private pending: ((data: Buffer) => void) | null = null;
  private phase: Phase = 'handshake';
  private clientRandom?: Buffer;

  constructor(private options: MTProtoConnectionOptions) {
    this.socket = new Socket();
    this.socket.on('data', (data) => this.onData(data));
    this.socket.on('error', () => {});
    this.socket.on('close', () => this.failPending('Connection closed by proxy'));
  }

  /**
   * Connect to the MTProto proxy and perform the obfuscation (+ fake TLS) handshake.
   * Resolves only after the proxy's ServerHello is HMAC-verified (fake TLS mode).
   */
  async connect(): Promise<void> {
    const { host, port, secret, dcId = 2, timeout = 10000 } = this.options;

    const parsed = parseSecret(secret);
    this.isFakeTLS = parsed.isFakeTLS;

    const { header, encryptor, decryptor } = initObfuscation(parsed.secret, dcId);
    this.encryptor = encryptor;
    this.decryptor = decryptor;

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.socket.destroy();
        reject(new Error('Connection timeout'));
      }, timeout);

      const onError = (err: Error) => {
        clearTimeout(timer);
        reject(err);
      };

      this.socket.once('error', onError);

      this.socket.connect(port, host, () => {
        clearTimeout(timer);
        this.socket.off('error', onError);
        resolve();
      });
    });

    this.socket.write(header);

    if (this.isFakeTLS && parsed.domain) {
      const clientHello = generateFakeTLSClientHello(parsed.domain, parsed.secret);
      this.clientRandom = clientHello.subarray(11, 43);
      this.socket.write(clientHello);

      // ServerHello = ServerHello + ChangeCipherSpec + one ApplicationData record.
      const verdict = await this.awaitVerdict(parsed.secret, timeout);
      if (verdict === 'invalid') {
        throw new Error('FakeTLS handshake failed (bad secret or not a proxy)');
      }
    }
  }

  /**
   * Send a real MTProto ping: req_pq_multi and wait for a valid ResPQ.
   *
   * @returns Round-trip time in ms
   */
  async ping(timeout = 10000): Promise<number> {
    if (!this.encryptor || !this.decryptor) {
      throw new Error('Not connected');
    }

    const nonce = randomBytes(16);
    const message = buildUnencryptedMessage(buildReqPqMulti(nonce), generateMessageId());

    // Intermediate transport framing: 4-byte LE length prefix before the message.
    const framed = Buffer.alloc(4 + message.length);
    framed.writeUInt32LE(message.length, 0);
    message.copy(framed, 4);

    const payload = this.isFakeTLS
      ? wrapInTLSRecords(this.encryptor.encrypt(framed))
      : this.encryptor.encrypt(framed);

    const start = Date.now();
    this.phase = 'ping';
    this.receiveBuffer = Buffer.alloc(0);

    const response = await new Promise<Buffer>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        reject(new Error('Ping timeout'));
      }, timeout);
      this.pending = (data) => {
        clearTimeout(timer);
        this.pending = null;
        resolve(data);
      };
      this.socket.write(payload);
    });

    this.phase = 'done';

    const parsed = parseResPQ(response);
    if (!parsed || !parsed.nonce.equals(nonce)) {
      throw new Error('Invalid ResPQ response');
    }
    return Date.now() - start;
  }

  /**
   * Connect + single real ping in one call. Closes the connection afterwards.
   */
  static async pingOnce(options: MTProtoConnectionOptions, timeout = 10000): Promise<number> {
    const conn = new MTProtoConnection(options);
    try {
      await conn.connect();
      return await conn.ping(timeout);
    } finally {
      conn.close();
    }
  }

  /**
   * Handle incoming socket data depending on the current phase.
   */
  private onData(data: Buffer): void {
    if (this.phase === 'handshake') {
      this.receiveBuffer = Buffer.concat([this.receiveBuffer, data]);
      const handler = this.pending;
      if (handler) handler(this.receiveBuffer);
      return;
    }

    if (this.phase !== 'ping' || !this.decryptor) {
      return;
    }

    // Ping phase: decrypt, strip TLS records, feed the MTProto stream.
    const decrypted = this.decryptor.encrypt(data);
    const { payload } = this.isFakeTLS ? extractTlsRecords(decrypted) : { payload: decrypted };
    this.receiveBuffer = Buffer.concat([this.receiveBuffer, payload]);

    // Intermediate framed message: 4-byte LE length then the message.
    // Pass the whole frame (length prefix included) so parseResPQ sees it.
    if (this.receiveBuffer.length >= 4) {
      const len = this.receiveBuffer.readUInt32LE(0);
      if (this.receiveBuffer.length >= 4 + len) {
        const handler = this.pending;
        if (handler) handler(this.receiveBuffer.subarray(0, 4 + len));
      }
    }
  }

  /**
   * Wait until the FakeTLS ServerHello can be verified.
   */
  private async awaitVerdict(
    proxySecret: Buffer,
    timeout: number
  ): Promise<'valid' | 'invalid'> {
    const clientRandom = this.clientRandom!;
    const started = this.receiveBuffer;
    this.receiveBuffer = Buffer.alloc(0);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        reject(new Error('FakeTLS handshake timeout'));
      }, timeout);
      const check = (data: Buffer) => {
        const verdict = tryVerifyFakeTLSServerHello(data, clientRandom, proxySecret);
        if (verdict !== 'incomplete') {
          clearTimeout(timer);
          this.pending = null;
          resolve(verdict);
        }
      };
      this.pending = check;
      if (started.length > 0) check(started);
    });
  }

  /**
   * Reject any pending waiters (socket closed mid-handshake/ping).
   */
  private failPending(_reason: string): void {
    const handler = this.pending;
    this.pending = null;
    if (handler) {
      if (this.phase === 'ping') {
        handler(Buffer.alloc(0)); // empty data -> parse fails -> error surfaces
      }
      // Handshake waiters resolve via their timeout; socket is gone anyway.
    }
  }

  /**
   * Close the connection.
   */
  close(): void {
    this.phase = 'done';
    this.socket.destroy();
  }
}

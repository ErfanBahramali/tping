import type {
  CheckResult,
  DcResult,
  HTTPProxy,
  MTProtoProxy,
  SOCKS5Proxy,
  TelegramProxy,
  Timings,
} from '../types/index.js';
import { SocketStream, StreamClosedError, type Pipe } from '../net/stream.js';
import { socks5Connect } from '../net/socks5.js';
import { HttpProxyError, httpConnect, httpTransportRequest } from '../net/http-proxy.js';
import { parseSecret } from '../mtproto/secret.js';
import { fakeTlsHandshake } from '../mtproto/fake-tls.js';
import { createObfuscation, ObfuscatedPipe } from '../mtproto/obfuscation.js';
import { encodeFrame, readFrame, type TransportMode } from '../mtproto/transport.js';
import { buildReqPqMulti, parseResPQ } from '../mtproto/messages.js';
import { DEFAULT_DC, resolveDatacenter, type DcAddress } from './datacenters.js';

export interface CheckOptions {
  /** Deadline for one whole check (connect + handshake + round trip), per DC. */
  readonly timeout: number;
  readonly dcs?: readonly number[];
  /** Use IPv6 DC addresses for SOCKS5/HTTP proxies. */
  readonly ipv6?: boolean;
  readonly signal?: AbortSignal;
  /** Override DC addresses (tests). */
  readonly resolveDc?: (dc: number, transport: 'tcp' | 'http') => DcAddress;
}

class TimeoutError extends Error {
  constructor() {
    super('Timeout');
    this.name = 'TimeoutError';
  }
}

class AbortedError extends Error {
  constructor() {
    super('Aborted');
    this.name = 'AbortedError';
  }
}

class InvalidResponseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidResponseError';
  }
}

const STAGE_WAITING = 'waiting for Telegram';

/**
 * Tracks the current phase (for error messages) and owns the stream's deadline.
 */
class Attempt {
  stage = 'connecting to proxy';
  readonly stream = new SocketStream();
  private readonly timer: NodeJS.Timeout;
  private readonly onAbort = (): void => this.stream.fail(new AbortedError());

  constructor(deadline: number, private readonly signal?: AbortSignal) {
    this.timer = setTimeout(() => this.stream.fail(new TimeoutError()), Math.max(0, deadline - Date.now()));
    if (signal?.aborted) {
      this.onAbort();
    }
    signal?.addEventListener('abort', this.onAbort, { once: true });
  }

  close(): void {
    clearTimeout(this.timer);
    this.signal?.removeEventListener('abort', this.onAbort);
    this.stream.destroy();
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

const describeError = (err: unknown, stage: string): string => {
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
  return err instanceof Error ? err.message : String(err);
};

/**
 * Send req_pq_multi and wait for a resPQ with our nonce.
 */
const exchangeReqPq = async (pipe: Pipe, mode: TransportMode): Promise<void> => {
  const { message, nonce } = buildReqPqMulti();
  pipe.write(encodeFrame(mode, message));
  const reply = parseResPQ(await readFrame(mode, pipe));
  if (!reply || !reply.nonce.equals(nonce)) {
    throw new InvalidResponseError('Invalid reply from Telegram (not a resPQ with our nonce)');
  }
};

interface Measured {
  readonly timings: Timings;
  readonly via?: 'http-transport';
}

/**
 * Run `body` on a fresh connection to the proxy and measure the phases.
 * `body` calls `handshakeDone()` when the proxy-level negotiation is finished.
 */
const measure = async (
  proxy: TelegramProxy,
  deadline: number,
  options: CheckOptions,
  body: (attempt: Attempt, handshakeDone: () => void) => Promise<void>
): Promise<Measured> => {
  const attempt = new Attempt(deadline, options.signal);
  try {
    const start = Date.now();
    await attempt.stream.connect(proxy.server, proxy.port);
    const connected = Date.now();
    let negotiated = connected;
    await body(attempt, () => {
      negotiated = Date.now();
    });
    const end = Date.now();
    return { timings: { connect: connected - start, handshake: negotiated - connected, rtt: end - negotiated } };
  } catch (err) {
    throw Object.assign(err instanceof Error ? err : new Error(String(err)), { stage: attempt.stage });
  } finally {
    attempt.close();
  }
};

const checkMTProto = (proxy: MTProtoProxy, dc: number, deadline: number, options: CheckOptions): Promise<Measured> => {
  const secret = parseSecret(proxy.secret);
  const mode: TransportMode = secret.kind === 'simple' ? 'intermediate' : 'padded';

  return measure(proxy, deadline, options, async (attempt, handshakeDone) => {
    let pipe: Pipe = attempt.stream;
    if (secret.kind === 'faketls') {
      attempt.stage = 'fake-TLS handshake';
      pipe = await fakeTlsHandshake(attempt.stream, secret.key, secret.domain ?? '');
    }
    handshakeDone();
    attempt.stage = STAGE_WAITING;
    await exchangeReqPq(new ObfuscatedPipe(pipe, createObfuscation(dc, mode, secret.key)), mode);
  });
};

const dcAddress = (dc: number, transport: 'tcp' | 'http', options: CheckOptions): DcAddress =>
  options.resolveDc?.(dc, transport) ?? resolveDatacenter(dc, options.ipv6 ?? false, transport);

/**
 * Direct (unsecured) obfuscated connection to the DC, as used through SOCKS5/HTTP proxies.
 */
const exchangeDirect = (pipe: Pipe, dc: number): Promise<void> =>
  exchangeReqPq(new ObfuscatedPipe(pipe, createObfuscation(dc, 'abridged')), 'abridged');

const checkSocks5 = (proxy: SOCKS5Proxy, dc: number, deadline: number, options: CheckOptions): Promise<Measured> =>
  measure(proxy, deadline, options, async (attempt, handshakeDone) => {
    const target = dcAddress(dc, 'tcp', options);
    await socks5Connect(attempt.stream, target.host, target.port, proxy, (stage) => {
      attempt.stage = stage;
    });
    handshakeDone();
    attempt.stage = STAGE_WAITING;
    await exchangeDirect(attempt.stream, dc);
  });

const checkHttp = async (proxy: HTTPProxy, dc: number, deadline: number, options: CheckOptions): Promise<Measured> => {
  try {
    return await measure(proxy, deadline, options, async (attempt, handshakeDone) => {
      const target = dcAddress(dc, 'tcp', options);
      attempt.stage = 'HTTP CONNECT';
      await httpConnect(attempt.stream, target.host, target.port, proxy);
      handshakeDone();
      attempt.stage = STAGE_WAITING;
      await exchangeDirect(attempt.stream, dc);
    });
  } catch (err) {
    // Like Telegram Desktop, fall back to the HTTP transport when the proxy refuses CONNECT.
    if (!(err instanceof HttpProxyError) || err.status === undefined || err.status === 407) {
      throw err;
    }
    const measured = await measure(proxy, deadline, options, async (attempt, handshakeDone) => {
      const target = dcAddress(dc, 'http', options);
      handshakeDone();
      attempt.stage = `${STAGE_WAITING} (HTTP transport)`;
      const { message, nonce } = buildReqPqMulti();
      const reply = parseResPQ(await httpTransportRequest(attempt.stream, target.host, target.port, proxy, message));
      if (!reply || !reply.nonce.equals(nonce)) {
        throw new InvalidResponseError('Invalid reply from Telegram over HTTP transport');
      }
    });
    return { ...measured, via: 'http-transport' };
  }
};

const checkDc = async (proxy: TelegramProxy, dc: number, options: CheckOptions): Promise<DcResult> => {
  const deadline = Date.now() + options.timeout;
  try {
    let measured: Measured;
    switch (proxy.type) {
      case 'mtproto':
        measured = await checkMTProto(proxy, dc, deadline, options);
        break;
      case 'socks5':
        measured = await checkSocks5(proxy, dc, deadline, options);
        break;
      case 'http':
        measured = await checkHttp(proxy, dc, deadline, options);
        break;
      default:
        return { dc, success: false, error: 'WEB-Proxy is not supported yet' };
    }
    const { connect, handshake, rtt } = measured.timings;
    return { dc, success: true, latency: connect + handshake + rtt, timings: measured.timings, via: measured.via };
  } catch (err) {
    if (err instanceof AbortedError) {
      throw err;
    }
    const stage = (err as { stage?: string }).stage ?? 'connecting to proxy';
    return { dc, success: false, error: describeError(err, stage) };
  }
};

/**
 * Check one proxy the way the official clients use it: open a real connection,
 * do the proxy handshake, and get a resPQ back from each requested Telegram DC.
 */
export const checkProxy = async (proxy: TelegramProxy, options: CheckOptions): Promise<CheckResult> => {
  const dcs = options.dcs?.length ? options.dcs : [DEFAULT_DC];

  if (proxy.type === 'mtproto') {
    try {
      parseSecret(proxy.secret);
    } catch (err) {
      return { proxy, success: false, dcs: [], error: (err as Error).message };
    }
  }
  if (proxy.type === 'web') {
    return {
      proxy,
      success: false,
      dcs: [],
      error: 'WEB-Proxy is not supported yet (no official protocol specification)',
    };
  }

  let results: DcResult[];
  try {
    results = await Promise.all(dcs.map((dc) => checkDc(proxy, dc, options)));
  } catch (err) {
    if (err instanceof AbortedError) {
      return { proxy, success: false, dcs: [], error: 'Aborted', aborted: true };
    }
    throw err;
  }

  const success = results.every((r) => r.success);
  const failed = results.find((r) => !r.success);
  return {
    proxy,
    success,
    latency: success ? Math.max(...results.map((r) => r.latency ?? 0)) : undefined,
    dcs: results,
    error: failed?.error,
  };
};

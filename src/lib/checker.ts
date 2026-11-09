import type {
  CheckResult,
  DcResult,
  HTTPProxy,
  MTProtoProxy,
  SOCKS5Proxy,
  TelegramProxy,
  Timings,
} from '../types/index.js';
import type { Pipe } from '../net/stream.js';
import { AbortedError, Attempt, STAGE_CONNECTING, STAGE_WAITING, describeError } from './attempt.js';
import { checkWebProxy } from '../webproxy/check.js';
import { socks5Connect } from '../net/socks5.js';
import { HttpProxyError, httpConnect, httpTransportRequest } from '../net/http-proxy.js';
import { parseSecret } from '../mtproto/secret.js';
import { fakeTlsHandshake } from '../mtproto/fake-tls.js';
import { createObfuscation, ObfuscatedPipe } from '../mtproto/obfuscation.js';
import type { TransportMode } from '../mtproto/transport.js';
import { buildReqPqMulti, parseResPQ } from '../mtproto/messages.js';
import { exchangeReqPq, InvalidResponseError } from '../mtproto/exchange.js';
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
  /** Override where a WEB proxy hostname connects, and trusted CA (tests). */
  readonly webProxyEndpoint?: { readonly host: string; readonly port: number; readonly ca?: Buffer };
}

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
        return { dc, success: false, error: 'Unsupported proxy type' };
    }
    const { connect, handshake, rtt } = measured.timings;
    return { dc, success: true, latency: connect + handshake + rtt, timings: measured.timings, via: measured.via };
  } catch (err) {
    if (err instanceof AbortedError) {
      throw err;
    }
    const stage = (err as { stage?: string }).stage ?? STAGE_CONNECTING;
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
  let results: readonly DcResult[];
  try {
    results = proxy.type === 'web'
      ? await checkWebProxy(proxy, dcs, options)
      : await Promise.all(dcs.map((dc) => checkDc(proxy, dc, options)));
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

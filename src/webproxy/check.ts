import type { CheckOptions } from '../lib/checker.js';
import type { CarrierMode, DcResult, WebProxy } from '../types/index.js';
import { AbortedError, Attempt, STAGE_WAITING, describeError } from '../lib/attempt.js';
import { HttpConnection, openTls, type HttpResponse, type TlsEndpoint } from '../net/http-client.js';
import { WebSocketConnection } from '../net/websocket.js';
import type { Pipe } from '../net/stream.js';
import { createObfuscation, ObfuscatedPipe } from '../mtproto/obfuscation.js';
import { exchangeReqPq } from '../mtproto/exchange.js';
import type { TransportMode } from '../mtproto/transport.js';
import { basePrefix, deriveCapability } from './link.js';
import { FRAME, decodeWebFrames, encodeDataFrames, encodeWebFrame, type WebFrame } from './frames.js';

/**
 * WEB proxy check (telegramdesktop/tproxy-server, protocol v1). TPing plays
 * both the Telegram app and the bridge page:
 *
 *   GET  /?bridge=<capability>      -> bridge page with a bootstrap token and carrier mode
 *   POST /api/v1/session (HELLO)    -> session token (WELCOME)
 *   one stream per DC: OPEN + DATA carrying the normal MTProxy bytes
 *   (obfuscation with the secret), over the carrier the relay selected,
 *   until the Telegram DC answers req_pq_multi with resPQ.
 */

const CARRIER_MODES: readonly CarrierMode[] = ['https', 'https-lanes', 'websocket', 'websocket-lanes'];
const BRIDGE_PATTERN = /const relayBase=("(?:[^"\\]|\\.)*"),bootstrap=("(?:[^"\\]|\\.)*"),carrierMode=("(?:[^"\\]|\\.)*")/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const DELETE_BUDGET_MS = 2000;
const USER_AGENT = 'Mozilla/5.0 (compatible; tping)';
const BINARY = 'application/octet-stream';

export class WebProxyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebProxyError';
  }
}

class StreamClosedByRelayError extends WebProxyError {
  constructor() {
    super("Relay closed the stream before Telegram answered (the relay's MTProxy backend rejected the secret or cannot reach Telegram)");
  }
}

interface Bridge {
  readonly bootstrap: string;
  readonly carrier: CarrierMode;
}

/**
 * One logical stream: the Telegram side writes MTProxy bytes into it, the carrier
 * turns them into OPEN/DATA frames and feeds relay DATA back.
 */
class StreamPipe implements Pipe {
  private incoming: Buffer = Buffer.alloc(0);
  private outgoing: Buffer[] = [];
  private opened = false;
  private waiter: (() => void) | null = null;
  private error: Error | null = null;

  constructor(readonly id: number, private readonly onWrite: () => void) {}

  write(data: Buffer): void {
    this.outgoing.push(data);
    this.onWrite();
  }

  takeFrames(): Buffer[] {
    const frames: Buffer[] = [];
    if (this.outgoing.length === 0) {
      return frames;
    }
    if (!this.opened) {
      frames.push(encodeWebFrame(FRAME.OPEN, this.id));
      this.opened = true;
    }
    for (const data of this.outgoing) {
      frames.push(...encodeDataFrames(this.id, data));
    }
    this.outgoing = [];
    return frames;
  }

  deliver(frame: WebFrame): void {
    if (frame.type === FRAME.DATA) {
      this.incoming = Buffer.concat([this.incoming, frame.payload]);
      this.waiter?.();
    } else if (frame.type === FRAME.CLOSE) {
      this.fail(new StreamClosedByRelayError());
    }
  }

  fail(err: Error): void {
    this.error ??= err;
    this.waiter?.();
  }

  read(length: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const tick = (): void => {
        if (this.incoming.length >= length) {
          this.waiter = null;
          const out = this.incoming.subarray(0, length);
          this.incoming = this.incoming.subarray(length);
          resolve(out);
        } else if (this.error) {
          this.waiter = null;
          reject(this.error);
        }
      };
      this.waiter = tick;
      tick();
    });
  }
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

const retryDelay = (response: HttpResponse): number => {
  const seconds = Number(response.headers.get('retry-after'));
  return Number.isFinite(seconds) && seconds >= 0 ? Math.min(seconds * 1000, 30000) : 1000;
};

/**
 * Send a request, honouring 503 + Retry-After with a byte-identical retry (as the bridge does).
 */
const requestWithRetry = async (
  http: HttpConnection,
  deadline: number,
  method: string,
  path: string,
  headers: Readonly<Record<string, string>>,
  body?: Buffer
): Promise<HttpResponse> => {
  for (;;) {
    const response = await http.request(method, path, headers, body);
    if (response.status !== 503) {
      return response;
    }
    const wait = retryDelay(response);
    if (Date.now() + wait >= deadline) {
      throw new WebProxyError('Relay is overloaded (HTTP 503)');
    }
    await sleep(wait);
  }
};

const parseBridgePage = (page: HttpResponse, expectedBase: string): Bridge => {
  if (page.status !== 200) {
    throw new WebProxyError(`Bridge page returned HTTP ${page.status} (wrong secret, hostname or base path)`);
  }
  const match = BRIDGE_PATTERN.exec(page.body.toString('utf8'));
  if (!match) {
    throw new WebProxyError('Server returned a normal website instead of the WEB proxy bridge (wrong secret, hostname or base path)');
  }
  const [relayBase, bootstrap, carrier] = match.slice(1).map((json) => JSON.parse(json) as string);
  if (relayBase !== expectedBase) {
    throw new WebProxyError('Bridge page points to a different relay address');
  }
  if (!TOKEN_PATTERN.test(bootstrap)) {
    throw new WebProxyError('Bridge page has an invalid bootstrap token');
  }
  if (!CARRIER_MODES.includes(carrier as CarrierMode)) {
    throw new WebProxyError(`Bridge page uses an unknown carrier mode "${carrier}"`);
  }
  return { bootstrap, carrier: carrier as CarrierMode };
};

interface Session {
  readonly token: string;
  readonly cursor: string;
}

const createSession = async (http: HttpConnection, base: string, origin: string, bridge: Bridge, deadline: number): Promise<Session> => {
  const response = await requestWithRetry(http, deadline, 'POST', `${base}api/v1/session`, {
    Authorization: `Bearer ${bridge.bootstrap}`,
    'Content-Type': BINARY,
    Origin: origin,
  }, encodeWebFrame(FRAME.HELLO, 0, Buffer.from([0x01])));

  if (response.status !== 200) {
    throw new WebProxyError(`Relay refused to create a session (HTTP ${response.status})`);
  }
  const token = response.headers.get('x-session-token') ?? '';
  if (!TOKEN_PATTERN.test(token)) {
    throw new WebProxyError('Relay returned an invalid session token');
  }
  if (response.headers.get('x-carrier-mode') !== bridge.carrier) {
    throw new WebProxyError('Relay carrier mode does not match the bridge page');
  }
  if (!decodeWebFrames(response.body).some((frame) => frame.type === FRAME.WELCOME)) {
    throw new WebProxyError('Relay did not answer HELLO with WELCOME');
  }
  return { token, cursor: response.headers.get('x-down-cursor') ?? '0' };
};

/**
 * Shared state between streams and carrier loops.
 */
class Mux {
  finished = false;
  private wakers: Array<() => void> = [];
  readonly streams: StreamPipe[] = [];

  constructor(private readonly onFailure: (err: Error) => void) {}

  add(id: number): StreamPipe {
    const stream = new StreamPipe(id, () => this.wakers.splice(0).forEach((wake) => wake()));
    this.streams.push(stream);
    return stream;
  }

  byId(id: number): StreamPipe | undefined {
    return this.streams.find((s) => s.id === id);
  }

  dispatch(frames: readonly WebFrame[], onPing?: (frame: WebFrame) => void): void {
    for (const frame of frames) {
      if (frame.streamId === 0) {
        if (frame.type === FRAME.BYE) {
          this.failAll(new WebProxyError(`Relay ended the session${frame.payload.length ? `: ${frame.payload.toString('utf8')}` : ''}`));
        } else if (frame.type === FRAME.PING) {
          onPing?.(frame);
        }
      } else {
        this.byId(frame.streamId)?.deliver(frame);
      }
    }
  }

  /** Resolves on the next write from any stream. */
  waitForWrite(): Promise<void> {
    return new Promise((resolve) => {
      this.wakers.push(resolve);
    });
  }

  failAll(err: Error): void {
    if (!this.finished) {
      this.streams.forEach((stream) => stream.fail(err));
      this.onFailure(err);
    }
  }

  /** Run a carrier loop; its failure fails every stream it serves. */
  run(loop: () => Promise<void>, streams: readonly StreamPipe[] = this.streams): void {
    loop().catch((err: Error) => {
      if (!this.finished) {
        streams.forEach((stream) => stream.fail(err));
      }
    });
  }
}

/**
 * Serialized HTTPS carrier (`https`), or one lane of `https-lanes`.
 */
const runHttpLane = (
  mux: Mux,
  http: HttpConnection,
  base: string,
  origin: string,
  session: Session,
  deadline: number,
  streams: readonly StreamPipe[],
  laneId?: number
) => async (): Promise<void> => {
  let sequence = 1;
  let cursor = laneId === undefined ? session.cursor : '0';
  const pongs: Buffer[] = [];
  const lane: Record<string, string> = laneId === undefined ? {} : { 'X-Lane-ID': String(laneId) };
  const auth = { Authorization: `Bearer ${session.token}` };

  while (!mux.finished) {
    const frames = [...pongs.splice(0), ...streams.flatMap((stream) => stream.takeFrames())];
    if (frames.length > 0) {
      const ack = String(sequence);
      const response = await requestWithRetry(http, deadline, 'POST', `${base}api/v1/up`, {
        ...auth, 'Content-Type': BINARY, Origin: origin, 'X-Up-Seq': ack, ...lane,
      }, Buffer.concat(frames));
      if (response.status !== 204 || response.headers.get('x-up-ack') !== ack) {
        throw new WebProxyError(`Relay rejected the uplink (HTTP ${response.status})`);
      }
      sequence++;
      continue;
    }

    const response = await requestWithRetry(http, deadline, 'POST', `${base}api/v1/down`, {
      ...auth, Origin: origin, 'X-Down-Cursor': cursor, ...lane,
    });
    if (response.status === 204) {
      if (response.headers.get('x-lane-closed') === '1') {
        streams.forEach((stream) => stream.fail(new StreamClosedByRelayError()));
        return;
      }
      continue;
    }
    const next = response.headers.get('x-down-cursor');
    if (response.status !== 200 || !next || response.body.length === 0) {
      throw new WebProxyError(`Relay rejected the downlink poll (HTTP ${response.status})`);
    }
    cursor = next;
    mux.dispatch(decodeWebFrames(response.body), (ping) => pongs.push(encodeWebFrame(FRAME.PONG, 0, ping.payload)));
  }
};

/**
 * WebSocket carrier (`websocket`), or one lane of `websocket-lanes`.
 */
const runWebSocket = (mux: Mux, socket: WebSocketConnection, streams: readonly StreamPipe[]) => {
  const flush = (): void => {
    const frames = streams.flatMap((stream) => stream.takeFrames());
    if (frames.length > 0) {
      socket.send(Buffer.concat(frames));
    }
  };
  return async (): Promise<void> => {
    flush();
    const sender = (async () => {
      while (!mux.finished) {
        await mux.waitForWrite();
        flush();
      }
    })();
    void sender;
    while (!mux.finished) {
      mux.dispatch(decodeWebFrames(await socket.receive()));
    }
  };
};

const pendingCleanups = new Set<Promise<void>>();

/**
 * Wait for background session deletes (each bounded to 2s), so a short run does not
 * exit before the relay has freed its session slots.
 */
export const waitForWebProxyCleanup = async (): Promise<void> => {
  await Promise.all([...pendingCleanups]);
};

const deleteSession = async (hostname: string, endpoint: TlsEndpoint, base: string, origin: string, token: string): Promise<void> => {
  const cleanup = new Attempt(Date.now() + DELETE_BUDGET_MS);
  try {
    const connection = new HttpConnection((await openTls(cleanup, hostname, endpoint)).stream, hostname);
    await connection.request('DELETE', `${base}api/v1/session`, { Authorization: `Bearer ${token}`, Origin: origin });
  } catch {
    // Best effort: the relay also expires idle sessions.
  } finally {
    cleanup.close();
  }
};

/**
 * Check a WEB proxy through one relay session, with one stream per DC.
 */
export const checkWebProxy = async (proxy: WebProxy, dcs: readonly number[], options: CheckOptions): Promise<DcResult[]> => {
  const secret = Buffer.from(proxy.secret, 'hex');
  const secure = secret.length === 17;
  const key = secure ? secret.subarray(1) : secret;
  const mode: TransportMode = secure ? 'padded' : 'intermediate';
  const hostname = proxy.server;
  const base = basePrefix(proxy.basePath);
  const origin = `https://${hostname}`;
  const endpoint: TlsEndpoint = options.webProxyEndpoint ?? {};
  const deadline = Date.now() + options.timeout;

  const attempt = new Attempt(deadline, options.signal);
  let sessionError: Error | null = null;
  const mux = new Mux((err) => {
    sessionError ??= err;
  });
  let session: Session | undefined;

  try {
    const start = Date.now();
    const main = await openTls(attempt, hostname, endpoint);
    const connected = Date.now();
    const http = new HttpConnection(main.stream, hostname);

    attempt.stage = 'loading the bridge page';
    const page = await http.request('GET', `${base}?bridge=${deriveCapability({ host: hostname, basePath: proxy.basePath }, secret)}`, {
      Accept: 'text/html',
      'User-Agent': USER_AGENT,
    });
    const bridge = parseBridgePage(page, `${origin}${base}`);

    attempt.stage = 'creating the relay session';
    session = await createSession(http, base, origin, bridge, deadline);
    const activeSession = session;

    const streams = dcs.map((_, index) => mux.add(index + 1));
    const lanes: Array<{ readonly stream: StreamPipe; readonly http: HttpConnection }> = [];
    const laneSockets: Array<{ readonly stream: StreamPipe; readonly socket: WebSocketConnection }> = [];
    let socket: WebSocketConnection | undefined;

    attempt.stage = `opening the ${bridge.carrier} carrier`;
    const openConnection = async (): Promise<HttpConnection> =>
      new HttpConnection((await openTls(attempt, hostname, endpoint)).stream, hostname);

    switch (bridge.carrier) {
      case 'https':
        break;
      case 'https-lanes':
        for (const stream of streams) {
          lanes.push({ stream, http: await openConnection() });
        }
        break;
      case 'websocket':
        socket = await WebSocketConnection.open(await openConnection(), `${base}api/v1/ws`, `tproxy-v1.${activeSession.token}`, origin);
        break;
      case 'websocket-lanes':
        // A lane that cannot be established fails the whole carrier, as in the bridge.
        for (const stream of streams) {
          const protocol = `tproxy-lane-v1.${activeSession.token}.${stream.id}`;
          laneSockets.push({ stream, socket: await WebSocketConnection.open(await openConnection(), `${base}api/v1/ws`, protocol, origin) });
        }
        break;
    }
    const negotiated = Date.now();

    attempt.stage = STAGE_WAITING;
    // Streams write their MTProxy bytes synchronously here, before any carrier loop runs.
    const results = Promise.all(dcs.map(async (dc, index): Promise<DcResult> => {
      const stream = streams[index];
      const streamStart = Date.now();
      try {
        await exchangeReqPq(new ObfuscatedPipe(stream, createObfuscation(dc, mode, key)), mode);
        const end = Date.now();
        const timings = { connect: connected - start, handshake: negotiated - connected, rtt: end - streamStart };
        return { dc, success: true, latency: end - start, timings, via: bridge.carrier };
      } catch (err) {
        if (err instanceof AbortedError) {
          throw err;
        }
        return { dc, success: false, error: describeError(sessionError ?? err, attempt.stage), via: bridge.carrier };
      }
    }));

    switch (bridge.carrier) {
      case 'https':
        mux.run(runHttpLane(mux, http, base, origin, activeSession, deadline, streams));
        break;
      case 'https-lanes':
        for (const lane of lanes) {
          mux.run(runHttpLane(mux, lane.http, base, origin, activeSession, deadline, [lane.stream], lane.stream.id), [lane.stream]);
        }
        break;
      case 'websocket':
        mux.run(runWebSocket(mux, socket!, streams));
        break;
      case 'websocket-lanes':
        for (const lane of laneSockets) {
          mux.run(runWebSocket(mux, lane.socket, [lane.stream]), [lane.stream]);
        }
        break;
    }

    // Failures of individual streams are reported per DC; abort fails all of them.
    const settled = await results;
    mux.finished = true;
    return settled;
  } catch (err) {
    mux.finished = true;
    if (err instanceof AbortedError) {
      throw err;
    }
    const error = describeError(err, attempt.stage);
    return dcs.map((dc) => ({ dc, success: false, error }));
  } finally {
    mux.finished = true;
    attempt.close();
    if (session) {
      // Free the relay's session slot right away; not part of the measurement.
      const cleanup: Promise<void> = deleteSession(hostname, endpoint, base, origin, session.token)
        .finally(() => pendingCleanups.delete(cleanup));
      pendingCleanups.add(cleanup);
    }
  }
};

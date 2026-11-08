/**
 * Proxy types supported by the official Telegram clients.
 * `http` is Telegram Desktop only; `web` (WEB-Proxy) is recognized but not checked.
 */
export type ProxyType = 'mtproto' | 'socks5' | 'http' | 'web';

export interface BaseProxy {
  readonly type: ProxyType;
  readonly server: string;
  readonly port: number;
}

export interface MTProtoProxy extends BaseProxy {
  readonly type: 'mtproto';
  readonly secret: string;
}

export interface SOCKS5Proxy extends BaseProxy {
  readonly type: 'socks5';
  readonly username?: string;
  readonly password?: string;
}

export interface HTTPProxy extends BaseProxy {
  readonly type: 'http';
  readonly username?: string;
  readonly password?: string;
}

export interface WebProxy extends BaseProxy {
  readonly type: 'web';
  readonly secret: string;
}

export type TelegramProxy = MTProtoProxy | SOCKS5Proxy | HTTPProxy | WebProxy;

/**
 * Time spent in each phase of one check, in milliseconds.
 */
export interface Timings {
  /** TCP connect to the proxy. */
  readonly connect: number;
  /** Fake TLS / SOCKS5 / HTTP CONNECT negotiation (0 when there is none). */
  readonly handshake: number;
  /** req_pq_multi -> resPQ round trip through the proxy to the Telegram DC. */
  readonly rtt: number;
}

/**
 * Result of checking one proxy against one DC.
 */
export interface DcResult {
  readonly dc: number;
  readonly success: boolean;
  /** Total time, from TCP connect to resPQ (what the official clients show as ping). */
  readonly latency?: number;
  readonly timings?: Timings;
  /** Set when the HTTP proxy only worked with the HTTP transport. */
  readonly via?: 'http-transport';
  readonly error?: string;
}

export interface CheckResult {
  readonly proxy: TelegramProxy;
  /** True only when every requested DC answered. */
  readonly success: boolean;
  /** Slowest DC latency when successful. */
  readonly latency?: number;
  readonly dcs: readonly DcResult[];
  readonly error?: string;
  /** The check was interrupted (Ctrl+C) and must not count in statistics. */
  readonly aborted?: boolean;
}

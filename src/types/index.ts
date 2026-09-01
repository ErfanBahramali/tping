/**
 * Type of Telegram proxy.
 */
export type ProxyType = 'mtproto' | 'socks5' | 'http';

/**
 * Base proxy interface.
 */
export interface BaseProxy {
    readonly type: ProxyType;
    readonly server: string;
    readonly port: number;
}

/**
 * MTProto proxy configuration.
 */
export interface MTProtoProxy extends BaseProxy {
    readonly type: 'mtproto';
    readonly secret: string;
}

/**
 * SOCKS5 proxy configuration.
 */
export interface SOCKS5Proxy extends BaseProxy {
    readonly type: 'socks5';
    readonly username?: string;
    readonly password?: string;
}

/**
 * HTTP proxy configuration.
 */
export interface HTTPProxy extends BaseProxy {
    readonly type: 'http';
    readonly username?: string;
    readonly password?: string;
}

/**
 * Union type for all proxy types.
 */
export type TelegramProxy = MTProtoProxy | SOCKS5Proxy | HTTPProxy;

/**
 * Result of a proxy check operation.
 */
export interface CheckResult {
    readonly proxy: TelegramProxy;
    readonly success: boolean;
    readonly latency?: number;
    readonly error?: string;
}

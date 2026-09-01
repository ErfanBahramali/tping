import type { TelegramProxy, CheckResult } from '../types/index.js';
import { MTProtoConnection } from '../mtproto/connection.js';
import { SOCKS5Client } from '../mtproto/socks5.js';

/**
 * Ping an MTProto proxy with a real MTProto handshake (req_pq -> ResPQ).
 * Latency includes TCP + obfuscation (+ fake TLS) handshake + the MTProto round trip.
 */
const pingMTProtoProxy = async (
  proxy: TelegramProxy,
  timeout: number
): Promise<CheckResult> => {
  if (proxy.type !== 'mtproto' || !proxy.secret) {
    return { proxy, success: false, error: 'Invalid MTProto configuration' };
  }

  try {
    const latency = await MTProtoConnection.pingOnce(
      {
        host: proxy.server,
        port: proxy.port,
        secret: proxy.secret,
        timeout,
      },
      timeout
    );
    return { proxy, success: true, latency };
  } catch (err) {
    return {
      proxy,
      success: false,
      error: err instanceof Error ? err.message : 'Connection failed',
    };
  }
};

/**
 * Ping a SOCKS5 proxy by connecting through it to a Telegram datacenter.
 */
const pingSOCKS5Proxy = async (
  proxy: TelegramProxy,
  timeout: number
): Promise<CheckResult> => {
  if (proxy.type !== 'socks5') {
    return { proxy, success: false, error: 'Invalid SOCKS5 configuration' };
  }

  try {
    const client = new SOCKS5Client({
      host: proxy.server,
      port: proxy.port,
      username: proxy.username,
      password: proxy.password,
      timeout,
    });

    const start = Date.now();
    await client.connect();
    const ok = await client.testConnection();
    client.close();

    if (!ok) {
      return { proxy, success: false, error: 'Connection test failed' };
    }
    return { proxy, success: true, latency: Date.now() - start };
  } catch (err) {
    return {
      proxy,
      success: false,
      error: err instanceof Error ? err.message : 'Connection failed',
    };
  }
};

/**
 * Ping any proxy type.
 */
export const checkProxy = async (
  proxy: TelegramProxy,
  timeout: number = 10000
): Promise<CheckResult> => {
  if (proxy.type === 'mtproto') {
    return pingMTProtoProxy(proxy, timeout);
  }
  if (proxy.type === 'socks5') {
    return pingSOCKS5Proxy(proxy, timeout);
  }
  return { proxy, success: false, error: 'Unsupported proxy type' };
};

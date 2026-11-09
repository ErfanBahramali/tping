import { readFileSync, statSync } from 'fs';
import type { TelegramProxy } from '../types/index.js';
import { decodeWebSecret, parseWebProxyServer } from '../webproxy/link.js';

/**
 * Supported inputs:
 *   https://t.me/proxy?server=..&port=..&secret=..      (also telegram.me, telegram.dog, www., http://, no scheme)
 *   tg://proxy?server=..&port=..&secret=..              (also tg:proxy)
 *   https://t.me/socks?server=..&port=..&user=..&pass=.. / tg://socks?...
 *   tg://webproxy?server=host[/path]&secret=.. / https://t.me/webproxy?...   (WEB proxy, port 443)
 *   socks5://user:pass@host:port                        (also socks://, socks5h://)
 *   http://user:pass@host:port                          (HTTP proxy, Telegram Desktop)
 */

const TELEGRAM_HOSTS = new Set([
  't.me',
  'telegram.me',
  'telegram.dog',
  'www.t.me',
  'www.telegram.me',
  'www.telegram.dog',
]);

export interface ParseIssue {
  readonly input: string;
  readonly reason: string;
}

export interface ParseResult {
  readonly proxies: readonly TelegramProxy[];
  readonly issues: readonly ParseIssue[];
}

type Outcome = { readonly proxy: TelegramProxy } | { readonly reason: string };

const normalize = (token: string): string => {
  // Strip shell-escape backslashes before URL punctuation (e.g. t.me/proxy\?...\&...).
  let value = token.replace(/\\([?=&#])/g, '$1').trim();
  if (/^tg:(?!\/\/)/i.test(value)) {
    value = `tg://${value.slice(3)}`;
  }
  if (/^(www\.)?(t\.me|telegram\.me|telegram\.dog)\//i.test(value)) {
    value = `https://${value}`;
  }
  return value;
};

const parsePort = (value: string | null | undefined, fallback?: number): number | string => {
  if (!value) {
    return fallback ?? 'port is missing';
  }
  if (!/^\d+$/.test(value)) {
    return `invalid port "${value}"`;
  }
  const port = Number(value);
  return port >= 1 && port <= 65535 ? port : `port ${port} is out of range`;
};

const cleanServer = (value: string | null): string => (value ?? '').trim().replace(/^\[(.*)\]$/, '$1');

const decodeUserInfo = (value: string): string | undefined => {
  if (!value) {
    return undefined;
  }
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

const fromWebQuery = (params: URLSearchParams): Outcome => {
  const server = (params.get('server') ?? params.get('host') ?? '').trim();
  if (!server) {
    return { reason: 'server is missing' };
  }
  const address = parseWebProxyServer(server);
  if (typeof address === 'string') {
    return { reason: address };
  }
  const secretText = params.get('secret')?.trim();
  if (!secretText) {
    return { reason: 'secret is missing' };
  }
  const secret = decodeWebSecret(secretText, address.basePath !== '');
  if (typeof secret === 'string') {
    return { reason: secret };
  }
  return {
    proxy: { type: 'web', server: address.host, port: 443, basePath: address.basePath, secret: secret.toString('hex') },
  };
};

const fromQuery = (kind: string, params: URLSearchParams): Outcome => {
  if (kind === 'webproxy') {
    return fromWebQuery(params);
  }

  const server = cleanServer(params.get('server'));
  if (!server) {
    return { reason: 'server is missing' };
  }

  const port = parsePort(params.get('port')?.trim());
  if (typeof port === 'string') {
    return { reason: port };
  }

  if (kind === 'proxy') {
    const secret = params.get('secret')?.trim();
    if (!secret) {
      return { reason: 'secret is missing' };
    }
    return { proxy: { type: 'mtproto', server, port, secret } };
  }

  if (kind === 'socks') {
    return {
      proxy: {
        type: 'socks5',
        server,
        port,
        username: params.get('user') || undefined,
        password: params.get('pass') || undefined,
      },
    };
  }

  return { reason: `unknown link type "${kind}"` };
};

const fromAuthority = (type: 'socks5' | 'http', url: URL, defaultPort: number): Outcome => {
  const server = cleanServer(url.hostname);
  if (!server) {
    return { reason: 'server is missing' };
  }
  const port = parsePort(url.port, defaultPort);
  if (typeof port === 'string') {
    return { reason: port };
  }
  return {
    proxy: {
      type,
      server,
      port,
      username: decodeUserInfo(url.username),
      password: decodeUserInfo(url.password),
    },
  };
};

export const parseProxyString = (token: string): Outcome => {
  const value = normalize(token);

  let url: URL;
  try {
    // URLSearchParams turns "+" into a space; keep it for base64 secrets.
    url = new URL(value.replace(/\+/g, '%2B'));
  } catch {
    return { reason: value.includes(':') ? 'not a valid proxy link' : 'not a proxy link, and no such file' };
  }

  const protocol = url.protocol.toLowerCase();
  const host = url.hostname.toLowerCase();

  if (protocol === 'tg:') {
    return fromQuery(host, url.searchParams);
  }
  if ((protocol === 'https:' || protocol === 'http:') && TELEGRAM_HOSTS.has(host)) {
    return fromQuery(url.pathname.replace(/^\/+|\/+$/g, '').toLowerCase(), url.searchParams);
  }
  if (protocol === 'socks5:' || protocol === 'socks5h:' || protocol === 'socks:') {
    return fromAuthority('socks5', url, 1080);
  }
  if (protocol === 'http:') {
    return fromAuthority('http', url, 80);
  }
  return { reason: 'unsupported link (expected t.me/proxy, t.me/socks, tg://..., socks5:// or http://)' };
};

const readInput = (input: string): string => {
  if (input === '-') {
    return readFileSync(0, 'utf-8');
  }
  try {
    if (statSync(input).isFile()) {
      return readFileSync(input, 'utf-8');
    }
  } catch {
    // Not a file: treat as proxy text.
  }
  return input;
};

/**
 * Parse proxies from a file path, "-" (stdin), or proxy text.
 * Proxies may be separated by newlines or whitespace; lines starting with "#" are comments.
 */
export const parseProxies = (input: string): ParseResult => {
  const proxies: TelegramProxy[] = [];
  const issues: ParseIssue[] = [];

  for (const rawLine of readInput(input).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }
    for (const token of line.split(/\s+/)) {
      if (token.startsWith('#')) {
        break;
      }
      const outcome = parseProxyString(token);
      if ('proxy' in outcome) {
        proxies.push(outcome.proxy);
      } else {
        issues.push({ input: token, reason: outcome.reason });
      }
    }
  }

  return { proxies, issues };
};

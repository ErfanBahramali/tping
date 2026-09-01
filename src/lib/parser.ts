import { readFileSync, existsSync } from 'fs';
import type { TelegramProxy } from '../types/index.js';

/**
 * Valid Telegram proxy URL prefixes
 */
const TELEGRAM_PROXY_PREFIXES = [
  'https://t.me/proxy?',
  'https://telegram.me/proxy?',
  'https://telegram.dog/proxy?',
  'tg://proxy?',
];

const TELEGRAM_SOCKS_PREFIXES = [
  'https://t.me/socks?',
  'https://telegram.me/socks?',
  'https://telegram.dog/socks?',
  'tg://socks?',
];

/**
 * Parse proxy string in Telegram URL format.
 */
const parseProxyString = (line: string): TelegramProxy | null => {
  // Strip shell-escape backslashes before URL punctuation (e.g. t.me/proxy\?...\&...)
  const trimmed = line
    .replace(/\\([?=&#])/g, '$1')
    .replace(/\+/g, '%2B')
    .trim();

  if (!trimmed || trimmed.startsWith('#')) {
    return null;
  }

  try {
    const url = new URL(trimmed);

    // Check if it's MTProto proxy
    if (TELEGRAM_PROXY_PREFIXES.some((prefix) => trimmed.startsWith(prefix))) {
      const server = url.searchParams.get('server');
      const port = url.searchParams.get('port');
      const secret = url.searchParams.get('secret');

      if (server && port && secret) {
        return {
          type: 'mtproto',
          server,
          port: parseInt(port, 10),
          secret,
        };
      }
    }

    // Check if it's SOCKS5 proxy
    if (TELEGRAM_SOCKS_PREFIXES.some((prefix) => trimmed.startsWith(prefix))) {
      const server = url.searchParams.get('server');
      const port = url.searchParams.get('port');
      const user = url.searchParams.get('user');
      const pass = url.searchParams.get('pass');

      if (server && port) {
        return {
          type: 'socks5',
          server,
          port: parseInt(port, 10),
          username: user || undefined,
          password: pass || undefined,
        };
      }
    }
  } catch {
    return null;
  }

  return null;
};

/**
 * Parse proxies from input string or file.
 * Automatically detects if input is a file path or proxy text.
 */
export const parseProxies = (input: string): readonly TelegramProxy[] => {
  let content: string;

  // Check if input is a file path
  if (existsSync(input)) {
    try {
      content = readFileSync(input, 'utf-8');
    } catch {
      content = input;
    }
  } else {
    content = input;
  }

  // Parse each line
  const proxies: TelegramProxy[] = [];
  const lines = content.split(/\r?\n/);

  for (const line of lines) {
    const proxy = parseProxyString(line);
    if (proxy) {
      proxies.push(proxy);
    }
  }

  return proxies;
};

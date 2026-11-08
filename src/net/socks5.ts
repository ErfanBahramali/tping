import { isIPv4, isIPv6 } from 'net';
import type { SocketStream } from './stream.js';

export class Socks5Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Socks5Error';
  }
}

const REPLY_MESSAGES: Readonly<Record<number, string>> = {
  0x01: 'general SOCKS server failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused by destination',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
};

export interface Socks5Credentials {
  readonly username?: string;
  readonly password?: string;
}

const encodeAddress = (host: string): Buffer => {
  if (isIPv4(host)) {
    return Buffer.from([0x01, ...host.split('.').map(Number)]);
  }
  if (isIPv6(host)) {
    const groups = expandIPv6(host);
    const out = Buffer.alloc(17);
    out[0] = 0x04;
    groups.forEach((group, i) => out.writeUInt16BE(group, 1 + i * 2));
    return out;
  }
  const name = Buffer.from(host, 'utf8');
  if (name.length > 255) {
    throw new Socks5Error('Destination host name too long');
  }
  return Buffer.concat([Buffer.from([0x03, name.length]), name]);
};

const expandIPv6 = (address: string): number[] => {
  const [head, tail] = address.split('::');
  const parse = (part: string | undefined): number[] =>
    part ? part.split(':').filter(Boolean).map((group) => parseInt(group, 16)) : [];
  const left = parse(head);
  const right = parse(tail);
  const zeros = tail === undefined ? [] : new Array(8 - left.length - right.length).fill(0);
  return [...left, ...zeros, ...right];
};

const toLengthByte = (value: string, label: string): Buffer => {
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length > 255) {
    throw new Socks5Error(`SOCKS5 ${label} is longer than 255 bytes`);
  }
  return Buffer.concat([Buffer.from([bytes.length]), bytes]);
};

/**
 * SOCKS5 handshake + CONNECT (RFC 1928 / RFC 1929), as Telegram clients do it:
 * offer username/password auth only when credentials are set, and connect to
 * the DC by IP address.
 */
export const socks5Connect = async (
  stream: SocketStream,
  host: string,
  port: number,
  credentials: Socks5Credentials,
  onStage: (stage: string) => void = () => {}
): Promise<void> => {
  const hasAuth = Boolean(credentials.username || credentials.password);

  onStage('SOCKS5 greeting');
  stream.write(Buffer.from(hasAuth ? [0x05, 0x02, 0x00, 0x02] : [0x05, 0x01, 0x00]));
  const choice = await stream.read(2);
  if (choice[0] !== 0x05) {
    throw new Socks5Error('Not a SOCKS5 server');
  }

  if (choice[1] === 0x02) {
    if (!hasAuth) {
      throw new Socks5Error('SOCKS5 proxy requires a username and password');
    }
    onStage('SOCKS5 authentication');
    stream.write(Buffer.concat([
      Buffer.from([0x01]),
      toLengthByte(credentials.username ?? '', 'username'),
      toLengthByte(credentials.password ?? '', 'password'),
    ]));
    const status = await stream.read(2);
    if (status[1] !== 0x00) {
      throw new Socks5Error('SOCKS5 authentication failed (wrong username or password)');
    }
  } else if (choice[1] === 0xff) {
    throw new Socks5Error(hasAuth
      ? 'SOCKS5 proxy rejected all authentication methods'
      : 'SOCKS5 proxy requires authentication');
  } else if (choice[1] !== 0x00) {
    throw new Socks5Error(`SOCKS5 proxy chose unsupported auth method 0x${choice[1].toString(16)}`);
  }

  onStage('SOCKS5 connect');
  const portBuffer = Buffer.alloc(2);
  portBuffer.writeUInt16BE(port, 0);
  stream.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), encodeAddress(host), portBuffer]));

  const reply = await stream.read(4);
  if (reply[0] !== 0x05) {
    throw new Socks5Error('Invalid SOCKS5 connect reply');
  }
  if (reply[1] !== 0x00) {
    throw new Socks5Error(`SOCKS5 connect to Telegram failed: ${REPLY_MESSAGES[reply[1]] ?? `error 0x${reply[1].toString(16)}`}`);
  }

  // Skip the bound address.
  switch (reply[3]) {
    case 0x01:
      await stream.read(4 + 2);
      break;
    case 0x04:
      await stream.read(16 + 2);
      break;
    case 0x03:
      await stream.read((await stream.read(1))[0] + 2);
      break;
    default:
      throw new Socks5Error('Invalid address type in SOCKS5 reply');
  }
};

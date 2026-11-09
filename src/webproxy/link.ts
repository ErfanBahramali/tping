import { createHmac } from 'crypto';
import { isIP } from 'net';
import { domainToASCII } from 'url';

/**
 * WEB proxy addressing and secrets, per telegramdesktop/tproxy-server
 * (PROTOCOL.md, BASE_PATH.md).
 */

const MAX_BASE_PATH = 128;
const PATH_MARKER = 0x70;

export interface WebProxyAddress {
  /** Lowercase ASCII (IDNA A-label) hostname. */
  readonly host: string;
  /** Base path without leading/trailing slash; empty for a root deployment. */
  readonly basePath: string;
}

const toAscii = (host: string): string => domainToASCII(host.toLowerCase());

export const validateHostname = (host: string): string | null => {
  if (!host || host.length > 253 || host.endsWith('.') || /[:/@?#[\]]/.test(host)) {
    return 'must be a DNS hostname without scheme, port, path, query or trailing dot';
  }
  if (isIP(host) || !host.includes('.')) {
    return 'IP addresses and single-label names are not allowed';
  }
  for (const label of host.split('.')) {
    if (!label || label.length > 63 || label.startsWith('-') || label.endsWith('-') || !/^[a-z0-9-]+$/.test(label)) {
      return 'invalid DNS label';
    }
  }
  return null;
};

export const validateBasePath = (path: string): string | null => {
  if (path === '') {
    return null;
  }
  if (path.length > MAX_BASE_PATH) {
    return `base path must be at most ${MAX_BASE_PATH} characters`;
  }
  return path.split('/').every((segment) => /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(segment))
    ? null
    : 'base path segments must match [A-Za-z0-9][A-Za-z0-9_-]*';
};

/**
 * Parse the `server` field: `host` or `host/base/path`.
 */
export const parseWebProxyServer = (value: string): WebProxyAddress | string => {
  const trimmed = value.trim();
  const slash = trimmed.indexOf('/');
  const rawHost = slash === -1 ? trimmed : trimmed.slice(0, slash);
  const basePath = slash === -1 ? '' : trimmed.slice(slash + 1);

  const host = toAscii(rawHost);
  const hostError = host ? validateHostname(host) : 'invalid hostname';
  if (hostError) {
    return `server ${hostError}`;
  }
  if (slash !== -1 && basePath === '') {
    return 'base path must not be empty';
  }
  const pathError = validateBasePath(basePath);
  return pathError ?? { host, basePath };
};

const decodeRaw = (value: string): Buffer | null => {
  const text = value.trim();
  if ((text.length === 32 || text.length === 34) && /^[0-9a-fA-F]+$/.test(text)) {
    return Buffer.from(text, 'hex');
  }
  if (/^[A-Za-z0-9_-]+={0,2}$/.test(text) || /^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    const decoded = Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, ''), 'base64');
    return decoded.length > 0 ? decoded : null;
  }
  return null;
};

/**
 * Decode a WEB proxy secret. A link with a base path must carry the marked
 * form (0x70 || secret, base64url); the marker is stripped.
 *
 * @returns the MTProxy secret bytes (16, or 17 starting with 0xdd), or an error message
 */
export const decodeWebSecret = (value: string, hasBasePath: boolean): Buffer | string => {
  if (/^ee[0-9a-f]{34,}$/i.test(value.trim())) {
    return 'WEB proxies do not support Fake TLS (ee) secrets';
  }
  let bytes = decodeRaw(value);
  if (!bytes) {
    return 'secret is neither hex nor base64url';
  }
  const marked = bytes.length >= 17 && bytes[0] === PATH_MARKER;
  if (marked) {
    bytes = bytes.subarray(1);
  }
  if (hasBasePath && !marked) {
    return 'a WEB proxy link with a base path must use the marked secret form';
  }
  if (bytes.length > 17 && bytes[0] === 0xee) {
    return 'WEB proxies do not support Fake TLS (ee) secrets';
  }
  if (bytes.length === 16 || (bytes.length === 17 && bytes[0] === 0xdd)) {
    return Buffer.from(bytes);
  }
  return 'WEB proxy secret must be 16 bytes, optionally prefixed with dd';
};

/**
 * Bridge capability: base64url(HMAC-SHA256(secret, context)), where context
 * binds the hostname (v1) or the hostname and base path (v2).
 */
export const deriveCapability = (address: WebProxyAddress, secret: Buffer): string => {
  const context = address.basePath === ''
    ? `tdesktop-web-proxy-bridge-v1\n${address.host}`
    : `tdesktop-web-proxy-bridge-v2\n${address.host}\n${address.basePath}`;
  return createHmac('sha256', secret).update(context, 'utf8').digest('base64url');
};

/** Path prefix of every relay endpoint: "/" or "/<base>/". */
export const basePrefix = (basePath: string): string => (basePath === '' ? '/' : `/${basePath}/`);

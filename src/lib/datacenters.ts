/**
 * Production Telegram datacenter addresses (same defaults as the official clients).
 * Only needed for SOCKS5/HTTP proxies; MTProto proxies pick the DC from the DC id.
 */
export interface DcAddress {
  readonly host: string;
  readonly port: number;
}

const DATACENTERS: Readonly<Record<number, { readonly ipv4: string; readonly ipv6: string }>> = {
  1: { ipv4: '149.154.175.50', ipv6: '2001:b28:f23d:f001::a' },
  2: { ipv4: '149.154.167.51', ipv6: '2001:67c:4e8:f002::a' },
  3: { ipv4: '149.154.175.100', ipv6: '2001:b28:f23d:f003::a' },
  4: { ipv4: '149.154.167.91', ipv6: '2001:67c:4e8:f004::a' },
  5: { ipv4: '149.154.171.5', ipv6: '2001:b28:f23f:f005::a' },
};

export const DC_IDS: readonly number[] = [1, 2, 3, 4, 5];
export const DEFAULT_DC = 2;

/**
 * @param transport - 'tcp' uses port 443, 'http' (HTTP transport) uses port 80
 */
export const resolveDatacenter = (dcId: number, ipv6: boolean, transport: 'tcp' | 'http'): DcAddress => {
  const dc = DATACENTERS[Math.abs(dcId)];
  if (!dc) {
    throw new Error(`Unknown DC ${dcId}`);
  }
  return { host: ipv6 ? dc.ipv6 : dc.ipv4, port: transport === 'http' ? 80 : 443 };
};

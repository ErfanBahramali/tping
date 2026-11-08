import type { TelegramProxy, CheckResult } from '../types/index.js';
import { checkProxy } from './checker.js';
import { formatPingLine, printPingStatistics } from '../utils/format.js';

export interface PingOptions {
  readonly count?: number;
  readonly interval: number;
  readonly timeout: number;
  readonly dcs: readonly number[];
  readonly ipv6: boolean;
  readonly verbose: boolean;
}

const sleep = (ms: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const done = (): void => {
      clearTimeout(timer);
      signal.removeEventListener('abort', done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener('abort', done, { once: true });
  });

/**
 * Ping all proxies in rounds, like `ping`. Returns every non-aborted result per proxy.
 *
 * On a TTY with enough rows the lines of a round are updated in place;
 * otherwise (pipes, files, many proxies) each result is printed when it arrives.
 */
export const pingProxies = async (
  proxies: readonly TelegramProxy[],
  options: PingOptions,
  signal: AbortSignal
): Promise<readonly CheckResult[][]> => {
  const out = process.stdout;
  const live = Boolean(out.isTTY) && proxies.length < (out.rows ?? 24) - 2;
  const allResults: CheckResult[][] = proxies.map(() => []);

  for (let sequence = 1; options.count === undefined || sequence <= options.count; sequence++) {
    if (signal.aborted) {
      break;
    }

    if (live) {
      proxies.forEach((_, i) => out.write(`${formatPingLine(i, proxies, sequence, undefined, options.verbose)}\n`));
    }

    await Promise.all(
      proxies.map(async (proxy, i) => {
        const result = await checkProxy(proxy, {
          timeout: options.timeout,
          dcs: options.dcs,
          ipv6: options.ipv6,
          signal,
        });
        if (!result.aborted) {
          allResults[i].push(result);
        }

        const line = formatPingLine(i, proxies, sequence, result, options.verbose);
        if (live) {
          const up = proxies.length - i;
          out.write(`\x1b[${up}A\r\x1b[2K${line}\x1b[${up}B\r`);
        } else if (!result.aborted) {
          out.write(`${line}\n`);
        }
      })
    );

    if (options.count === undefined || sequence < options.count) {
      await sleep(options.interval, signal);
    }
  }

  printPingStatistics(proxies, allResults);
  return allResults;
};

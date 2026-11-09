import chalk from 'chalk';
import Table from 'cli-table3';
import type { CheckResult, DcResult, TelegramProxy } from '../types/index.js';
import { describeSecretKind, parseSecret } from '../mtproto/secret.js';

const ANSI_PATTERN = /\x1b\[[0-9;]*m/g;

const visibleLength = (text: string): number => text.replace(ANSI_PATTERN, '').length;

/** padEnd that ignores ANSI color codes. */
export const padVisible = (text: string, width: number): string =>
  text + ' '.repeat(Math.max(0, width - visibleLength(text)));

export const formatLatency = (latency: number): string => {
  if (latency < 100) {
    return chalk.green(`${latency}ms`);
  }
  if (latency < 300) {
    return chalk.yellow(`${latency}ms`);
  }
  return chalk.red(`${latency}ms`);
};

export const formatProxyType = (proxy: TelegramProxy): string => {
  switch (proxy.type) {
    case 'mtproto': {
      let variant = '';
      try {
        variant = ` · ${describeSecretKind(parseSecret(proxy.secret).kind)}`;
      } catch {
        variant = ' · invalid secret';
      }
      return chalk.cyan(`MTProto${variant}`);
    }
    case 'socks5':
      return chalk.magenta('SOCKS5');
    case 'http':
      return chalk.blue('HTTP');
    default:
      return chalk.yellow(`WEB · ${proxy.secret.length === 34 ? 'dd' : 'simple'}`);
  }
};

const shorten = (text: string): string => (text.length > 30 ? `${text.substring(0, 27)}...` : text);

export const formatProxyAddress = (proxy: TelegramProxy): string => {
  if (proxy.type === 'web') {
    return shorten(proxy.basePath ? `${proxy.server}/${proxy.basePath}` : proxy.server);
  }
  const server = shorten(proxy.server);
  return `${server.includes(':') ? `[${server}]` : server}:${proxy.port}`;
};

const formatTimings = (dc: DcResult): string => {
  if (!dc.timings) {
    return '';
  }
  const { connect, handshake, rtt } = dc.timings;
  const parts = [`tcp ${connect}`];
  if (handshake > 0) {
    parts.push(`handshake ${handshake}`);
  }
  parts.push(`rtt ${rtt}`);
  return chalk.gray(` (${parts.join(' · ')}ms)`);
};

const formatSuccess = (result: CheckResult, verbose: boolean): string => {
  const carrier = result.dcs.find((dc) => dc.via)?.via;
  const via = carrier ? chalk.gray(` via ${carrier === 'http-transport' ? 'HTTP transport' : carrier}`) : '';
  if (result.dcs.length <= 1) {
    const dc = result.dcs[0];
    return `${formatLatency(result.latency ?? 0)}${verbose && dc ? formatTimings(dc) : ''}${via}`;
  }
  const perDc = result.dcs
    .map((dc) => `DC${dc.dc} ${dc.latency}ms${verbose ? formatTimings(dc) : ''}`)
    .join(chalk.gray(' · '));
  return `${formatLatency(result.latency ?? 0)} ${chalk.gray('[')}${perDc}${chalk.gray(']')}${via}`;
};

const formatFailure = (result: CheckResult): string => {
  if (result.dcs.length <= 1) {
    return chalk.red(result.error ?? 'Failed');
  }
  return result.dcs
    .map((dc) => (dc.success ? chalk.green(`DC${dc.dc} ${dc.latency}ms`) : chalk.red(`DC${dc.dc}: ${dc.error}`)))
    .join(chalk.gray(' · '));
};

/**
 * One result line. `result` is undefined while the check is running.
 */
export const formatPingLine = (
  index: number,
  proxies: readonly TelegramProxy[],
  sequence: number,
  result: CheckResult | undefined,
  verbose: boolean
): string => {
  const proxy = proxies[index];
  const label = proxies.length > 1 ? `[${index + 1}] ${formatProxyAddress(proxy)}` : formatProxyAddress(proxy);
  const separator = chalk.gray('│');
  const head = `${chalk.gray(`#${sequence}`)} ${separator} ${padVisible(chalk.white(label), 36)} ${separator} ${padVisible(formatProxyType(proxy), 20)} ${separator}`;

  if (!result) {
    return `${chalk.cyan('⏳')} ${head} ${chalk.cyan('testing...')}`;
  }
  if (result.aborted) {
    return `${chalk.yellow('⏹')}  ${head} ${chalk.yellow('aborted')}`;
  }
  if (result.success) {
    return `${chalk.green('✅')} ${head} ${formatSuccess(result, verbose)}`;
  }
  return `${chalk.red('❌')} ${head} ${formatFailure(result)}`;
};

const truncate = (text: string, max: number): string => (text.length > max ? `${text.slice(0, max - 1)}…` : text);

/**
 * Print the statistics table (like `ping`'s summary) for all proxies.
 */
export const printPingStatistics = (
  proxies: readonly TelegramProxy[],
  allResults: readonly (readonly CheckResult[])[]
): void => {
  console.log();
  console.log(chalk.bold.cyan('📊 Statistics'));
  console.log();

  const table = new Table({
    head: ['Proxy', 'Type', 'Sent', 'Recv', 'Loss', 'Min', 'Avg', 'Max', 'Mdev', 'Last error'].map((h) => chalk.bold(h)),
    style: chalk.level > 0 ? { head: ['cyan'], border: ['gray'] } : { head: [], border: [] },
  });

  proxies.forEach((proxy, index) => {
    const results = allResults[index];
    const sent = results.length;
    const latencies = results.filter((r) => r.success && r.latency !== undefined).map((r) => r.latency as number);
    const received = latencies.length;
    const loss = sent > 0 ? Math.round(((sent - received) / sent) * 100) : 0;

    let min = '-';
    let avg = '-';
    let max = '-';
    let mdev = '-';
    if (received > 0) {
      const mean = latencies.reduce((a, b) => a + b, 0) / received;
      const deviation = Math.sqrt(latencies.reduce((a, b) => a + (b - mean) ** 2, 0) / received);
      min = formatLatency(Math.min(...latencies));
      avg = formatLatency(Math.round(mean));
      max = formatLatency(Math.max(...latencies));
      mdev = chalk.gray(`${Math.round(deviation)}ms`);
    }

    const lastError = [...results].reverse().find((r) => !r.success)?.error;
    const lossColor = sent === 0 ? chalk.gray : loss === 0 ? chalk.green : chalk.red;

    table.push([
      formatProxyAddress(proxy),
      formatProxyType(proxy),
      chalk.white(sent),
      chalk.green(received),
      lossColor(`${loss}%`),
      min,
      avg,
      max,
      mdev,
      lastError ? chalk.red(truncate(lastError, 40)) : chalk.gray('-'),
    ]);
  });

  console.log(table.toString());
  console.log();
};

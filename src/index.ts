#!/usr/bin/env node

import { createRequire } from 'module';
import chalk from 'chalk';
import { InvalidArgumentError, Option, program } from 'commander';
import { parseProxies } from './lib/parser.js';
import { pingProxies } from './lib/ping.js';
import { DC_IDS, DEFAULT_DC } from './lib/datacenters.js';

const { version } = createRequire(import.meta.url)('../package.json') as { version: string };

const integer = (name: string, min: number) => (value: string): number => {
  const number = Number(value);
  if (!/^\d+$/.test(value.trim()) || !Number.isSafeInteger(number) || number < min) {
    throw new InvalidArgumentError(`${name} must be an integer >= ${min}.`);
  }
  return number;
};

const parseDcs = (value: string): number[] => {
  if (value.trim().toLowerCase() === 'all') {
    return [...DC_IDS];
  }
  const ids = value.split(',').map((part) => Number(part.trim()));
  if (ids.length === 0 || ids.some((id) => !DC_IDS.includes(id))) {
    throw new InvalidArgumentError(`DC must be "all" or a comma-separated list of ${DC_IDS.join(', ')}.`);
  }
  return [...new Set(ids)];
};

interface CliOptions {
  count?: number;
  interval: number;
  timeout: number;
  dc: number[];
  ipv6: boolean;
  verbose: boolean;
}

program
  .name('tping')
  .description('Ping for Telegram Proxies')
  .version(version, '-v, --version')
  .argument('[proxies...]', 'Proxy links, file paths, or "-" for stdin')
  .option('-c, --count <n>', 'Number of pings to send (default: unlimited)', integer('count', 1))
  .option('-i, --interval <ms>', 'Interval between pings in milliseconds', integer('interval', 0), 1000)
  .option('-t, --timeout <ms>', 'Timeout for each ping (connect + handshake + reply) in milliseconds', integer('timeout', 100), 10000)
  .addOption(
    new Option('-d, --dc <ids>', 'Telegram DC(s) to test through the proxy: 1-5, comma-separated, or "all"')
      .argParser(parseDcs)
      .default([DEFAULT_DC], String(DEFAULT_DC))
  )
  .option('-6, --ipv6', 'Use IPv6 DC addresses for SOCKS5/HTTP proxies', false)
  .option('-V, --verbose', 'Show the time spent in each phase (tcp, handshake, rtt)', false)
  .showHelpAfterError('(add --help for additional information)')
  .addHelpText('after', `
Supported proxy formats:
  MTProto:  https://t.me/proxy?server=...&port=...&secret=...   (also tg://proxy?...)
            secret: 32 hex (simple), dd + 32 hex (secure), ee + 32 hex + domain hex (Fake TLS),
            or the same bytes in base64 / base64url
  SOCKS5:   https://t.me/socks?server=...&port=...&user=...&pass=...   (also tg://socks?...)
            socks5://user:pass@host:port
  HTTP:     http://user:pass@host:port   (Telegram Desktop only)

A ping succeeds only when a Telegram datacenter answers through the proxy.
Exit status: 0 if every proxy answered at least once, 1 otherwise, 2 on bad input.

Examples:
  $ tping "https://t.me/proxy?server=proxy.example.com&port=443&secret=0123456789abcdef0123456789abcdef"
  $ tping -c 5 "https://t.me/socks?server=proxy.example.com&port=1080"
  $ tping -c 10 -i 500 --dc all proxies.txt
  $ cat proxies.txt | tping -c 1 -
`)
  .action(async (inputs: string[], options: CliOptions) => {
    if (inputs.length === 0) {
      program.help();
    }

    const parsed = inputs.map(parseProxies);
    const proxies = parsed.flatMap((p) => p.proxies);
    const issues = parsed.flatMap((p) => p.issues);

    for (const issue of issues) {
      const shown = issue.input.length > 60 ? `${issue.input.slice(0, 57)}...` : issue.input;
      console.error(chalk.yellow(`⚠️  Skipped "${shown}": ${issue.reason}`));
    }
    if (proxies.length === 0) {
      console.error(chalk.red('Error: no valid proxy found (pass a proxy link or a file path)'));
      process.exit(2);
    }

    console.log();
    console.log(chalk.bold.cyan('🏓 TPing'));
    console.log(chalk.gray('━'.repeat(50)));
    console.log(chalk.cyan(`📡 Proxies:  ${chalk.white(proxies.length)}`));
    console.log(chalk.cyan(`🎯 Count:    ${chalk.white(options.count ?? 'unlimited')}`));
    console.log(chalk.cyan(`⏰ Interval: ${chalk.white(`${options.interval}ms`)}`));
    console.log(chalk.cyan(`⏳ Timeout:  ${chalk.white(`${options.timeout}ms`)}`));
    console.log(chalk.cyan(`🌐 DC:       ${chalk.white(options.dc.join(', '))}`));
    console.log(chalk.gray('━'.repeat(50)));
    console.log();

    const abortController = new AbortController();
    const handleSignal = (): void => {
      if (abortController.signal.aborted) {
        process.exit(130);
      }
      abortController.abort();
      process.stderr.write(chalk.yellow('\n⏸️  Stopping... (press Ctrl+C again to force quit)\n'));
    };
    process.on('SIGINT', handleSignal);
    process.on('SIGTERM', handleSignal);

    const results = await pingProxies(
      proxies,
      {
        count: options.count,
        interval: options.interval,
        timeout: options.timeout,
        dcs: options.dc,
        ipv6: options.ipv6,
        verbose: options.verbose,
      },
      abortController.signal
    );

    const allAnswered = results.every((list) => list.some((r) => r.success));
    process.exit(allAnswered ? 0 : 1);
  });

await program.parseAsync();

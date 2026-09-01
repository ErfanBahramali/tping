#!/usr/bin/env node

import chalk from 'chalk';
import { program } from 'commander';
import { parseProxies } from './lib/parser.js';
import { pingProxy } from './lib/ping.js';

program
    .name('tping')
    .description('Ping for Telegram Proxies')
    .version('1.0.0', '-v, --version')
    .argument('[proxy]', 'Proxy URL or file path (supports MTProto, SOCKS5)')
    .option('-c, --count <n>', 'Number of pings to send (default: unlimited)', parseInt)
    .option('-i, --interval <ms>', 'Interval between pings in milliseconds (default: 1000)', parseInt)
    .option('-t, --timeout <ms>', 'Timeout for each ping in milliseconds (default: 10000)', parseInt)
    .showHelpAfterError('(add --help for additional information)')
    .addHelpText('after', `
Supported proxy formats:
  MTProto:  "https://t.me/proxy?server=...&port=...&secret=..."
  MTProto:  "tg://proxy?server=...&port=...&secret=..."
  SOCKS5:   "https://t.me/socks?server=...&port=...&user=...&pass=..."
  SOCKS5:   "tg://socks?server=...&port=...&user=...&pass=..."

Examples:
  $ tping "https://t.me/proxy?server=proxy.example.com&port=443&secret=0123456789abcdef"
  $ tping -c 5 "https://t.me/socks?server=proxy.example.com&port=1080"
  $ tping -c 10 -i 500 "tg://socks?server=proxy.example.com&port=1080&user=admin&pass=secret"
  $ tping proxies.txt
`)
    .action(async (proxyInput: string | undefined, options: {
        count?: number;
        interval?: number;
        timeout?: number;
    }) => {
        if (!proxyInput) {
            program.help();
        }

        // Parse proxies
        const proxies = parseProxies(proxyInput);

        if (proxies.length === 0) {
            console.log(chalk.red('Error: Invalid proxy format'));
            process.exit(1);
        }

        options.interval = options.interval || 1000;
        options.timeout = options.timeout || 10000;

        // Print header
        console.log();
        console.log(chalk.bold.cyan('🏓 TPing'));
        console.log(chalk.gray('━'.repeat(50)));
        console.log(chalk.cyan(`📡 Proxies: ${chalk.white(proxies.length)}`));
        console.log(chalk.cyan(`🎯 Count: ${chalk.white(options.count || 'unlimited')}`));
        console.log(chalk.cyan(`⏰ Interval: ${chalk.white(options.interval + 'ms')}`));
        console.log(chalk.cyan(`⏳ Timeout: ${chalk.white(options.timeout + 'ms')}`));
        console.log(chalk.gray('━'.repeat(50)));
        console.log();

        // Setup abort controller for Ctrl+C
        const abortController = new AbortController();
        let isAborting = false;

        const handleAbort = async () => {
            if (isAborting) {
                return;
            }
            isAborting = true;
            abortController.abort();
            console.log(chalk.yellow('\n⏸️  Stopping... (Press Ctrl+C again to force quit)'));
        };

        process.on('SIGINT', handleAbort);
        process.on('SIGTERM', handleAbort);

        await pingProxy(
            proxies,
            options,
            abortController.signal
        );

        process.exit(0);
    }).parse();

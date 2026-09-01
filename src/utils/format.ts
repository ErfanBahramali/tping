import chalk from 'chalk';
import Table from 'cli-table3';
import readline from 'readline';
import type { TelegramProxy, CheckResult } from '../types/index.js';

/**
 * Format latency with color.
 */
export const formatLatency = (latency: number): string => {
    if (latency < 100) {
        return chalk.green(`${latency}ms`);
    } else if (latency < 300) {
        return chalk.yellow(`${latency}ms`);
    } else {
        return chalk.red(`${latency}ms`);
    }
};

/**
 * Format proxy type with color.
 */
export const formatProxyType = (type: string): string => {
    switch (type) {
        case 'mtproto':
            return chalk.cyan('MTProto');
        case 'socks5':
            return chalk.magenta('SOCKS5');
        case 'http':
            return chalk.blue('HTTP');
        default:
            return chalk.dim(type);
    }
};

/**
 * Format proxy address.
 */
export const formatProxyAddress = (proxy: TelegramProxy): string => {
    const server = proxy.server.length > 30 ? proxy.server.substring(0, 27) + '...' : proxy.server;
    return `${server}:${proxy.port}`;
};

/**
 * Print live result with in-place update.
 */
export const printPingResult = (proxyIndex: number, proxies: readonly TelegramProxy[], sequence: number, status: 'testing' | 'done', result?: CheckResult): void => {
    const proxy = result?.proxy || proxies[proxyIndex];
    const proxyLabel = proxies.length > 1 ? `[${proxyIndex + 1}] ${formatProxyAddress(proxy)}` : formatProxyAddress(proxy);
    const typeStr = formatProxyType(proxy.type);
    const seqStr = chalk.gray(`#${sequence.toString()}`);

    let line = '';
    if (status === 'testing') {
        const icon = chalk.cyan('⏳');
        line = `${icon} ${seqStr} ${chalk.gray('│')} ${chalk.white(proxyLabel.padEnd(35))} ${chalk.gray('│')} ${typeStr.padEnd(17)} ${chalk.gray('│')} ${chalk.cyan('testing...')}`;
    } else if (result) {
        if (result.success && result.latency !== undefined) {
            const icon = chalk.green.bold('✅');
            const latencyStr = formatLatency(result.latency);
            line = `${icon} ${seqStr} ${chalk.gray('│')} ${chalk.white(proxyLabel.padEnd(35))} ${chalk.gray('│')} ${typeStr.padEnd(17)} ${chalk.gray('│')} ${latencyStr}`;
        } else {
            const icon = chalk.red.bold('❌');
            const errorStr = result.error || 'timeout';
            line = `${icon} ${seqStr} ${chalk.gray('│')} ${chalk.white(proxyLabel.padEnd(35))} ${chalk.gray('│')} ${typeStr.padEnd(17)} ${chalk.gray('│')} ${chalk.red(errorStr)}`;
        }
    }

    // Move cursor to start, clear line, and write new content
    readline.clearLine(process.stdout, 0);
    readline.cursorTo(process.stdout, 0);
    process.stdout.write(line);
};

/**
 * Print statistics table for all proxies.
 */
export const printPingStatistics = (proxies: readonly TelegramProxy[], allResults: readonly (readonly CheckResult[])[]): void => {
    console.log();
    console.log(chalk.gray('━'.repeat(50)));
    console.log();
    console.log(chalk.bold.cyan('📊 Statistics'));
    console.log();

    const table = new Table({
        head: [
            chalk.bold('Proxy'),
            chalk.bold('Type'),
            chalk.bold('Sent'),
            chalk.bold('Recv'),
            chalk.bold('Loss'),
            chalk.bold('Min'),
            chalk.bold('Avg'),
            chalk.bold('Max')
        ],
        style: {
            head: ['cyan'],
            border: ['gray']
        }
    });

    proxies.forEach((proxy, index) => {
        const results = allResults[index];
        const proxyStr = formatProxyAddress(proxy);
        const typeStr = formatProxyType(proxy.type);
        const transmitted = results.length;
        const received = results.filter((r) => r.success).length;
        const loss = transmitted > 0 ? Math.round(((transmitted - received) / transmitted) * 100) : 0;

        let minStr = '-';
        let avgStr = '-';
        let maxStr = '-';

        if (received > 0) {
            const latencies = results.filter((r) => r.success && r.latency !== undefined).map((r) => r.latency!);
            if (latencies.length > 0) {
                const min = Math.min(...latencies);
                const max = Math.max(...latencies);
                const avg = Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length);
                minStr = formatLatency(min);
                avgStr = formatLatency(avg);
                maxStr = formatLatency(max);
            }
        }

        const lossColor = loss === 0 ? chalk.green : chalk.red;

        table.push([
            proxyStr,
            typeStr,
            chalk.white(transmitted),
            chalk.green(received),
            lossColor(`${loss}%`),
            minStr,
            avgStr,
            maxStr
        ]);
    });

    console.log(table.toString());
    console.log();
};
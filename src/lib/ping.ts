import type { TelegramProxy, CheckResult } from '../types/index.js';
import { checkProxy } from './checker.js';
import { printPingResult, printPingStatistics } from '../utils/format.js';

/**
 * Ping proxies continuously.
 */
export const pingProxy = async (
    proxies: readonly TelegramProxy[],
    options: {
        count?: number;
        interval?: number;
        timeout?: number;
    },
    signal?: AbortSignal
): Promise<readonly CheckResult[][]> => {
    const { count, interval = 1000, timeout = 10000 } = options;
    let shouldStop = false;

    // Handle abort signal
    if (signal) {
        signal.addEventListener('abort', () => {
            shouldStop = true;
        });
    }

    const sleep = (ms: number): Promise<void> => {
        return new Promise((resolve) => setTimeout(resolve, ms));
    };

    // Initialize results array for each proxy
    const allResults: CheckResult[][] = proxies.map(() => []);
    let sequence = 1;

    // Main ping loop - all proxies tested together
    while (!shouldStop) {
        // Check if we've reached the count limit
        if (count !== undefined && sequence > count) {
            break;
        }

        // Show testing status for all proxies
        for (let i = 0; i < proxies.length; i++) {
            printPingResult(i, proxies, sequence, 'testing');
            process.stdout.write('\n');
        }

        // Ping all proxies in parallel with real-time updates
        await Promise.all(
            proxies.map(async (proxy, i) => {
                const result = await checkProxy(proxy, timeout);
                allResults[i].push(result);

                // Move cursor to the correct line and update
                const lineOffset = proxies.length - i;
                process.stdout.write(`\x1b[${lineOffset}A`); // Move up
                printPingResult(i, proxies, sequence, 'done', result);
                process.stdout.write(`\x1b[${lineOffset}B`); // Move back down
            })
        );

        // Move to position after all lines
        process.stdout.write('\n');

        sequence++;

        // Check if aborted or should stop
        if (shouldStop) {
            break;
        }

        // Wait for interval before next ping (unless it's the last one)
        if (count === undefined || sequence <= count) {
            if (!shouldStop) {
                await sleep(interval);
            }
        }
    }

    printPingStatistics(proxies, allResults);

    return allResults;
};

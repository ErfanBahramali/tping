import type { Pipe } from '../net/stream.js';
import { encodeFrame, readFrame, type TransportMode } from './transport.js';
import { buildReqPqMulti, parseResPQ } from './messages.js';

export class InvalidResponseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidResponseError';
  }
}

/**
 * Send req_pq_multi and wait for a resPQ with our nonce.
 */
export const exchangeReqPq = async (pipe: Pipe, mode: TransportMode): Promise<void> => {
  const { message, nonce } = buildReqPqMulti();
  pipe.write(encodeFrame(mode, message));
  const reply = parseResPQ(await readFrame(mode, pipe));
  if (!reply || !reply.nonce.equals(nonce)) {
    throw new InvalidResponseError('Invalid reply from Telegram (not a resPQ with our nonce)');
  }
};

import { randomBytes } from 'crypto';

const P = (1n << 255n) - 19n;
const A = 486662n;

const mod = (value: bigint): bigint => {
  const result = value % P;
  return result < 0n ? result + P : result;
};

const modPow = (base: bigint, exponent: bigint): bigint => {
  let result = 1n;
  let b = mod(base);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % P;
    }
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
};

/** y^2 = x^3 + A*x^2 + x on Curve25519. */
const curveY2 = (x: bigint): bigint => mod(((x + A) * x + 1n) * x);

export const isQuadraticResidue = (value: bigint): boolean =>
  value === 0n || modPow(value, (P - 1n) / 2n) === 1n;

/** x-coordinate of 2*point (Montgomery doubling). */
const doubleX = (x: bigint): bigint => {
  const numerator = mod(x * x - 1n);
  const denominator = mod(4n * curveY2(x));
  return mod(numerator * numerator * modPow(denominator, P - 2n));
};

export const bufferToBigInt = (buffer: Buffer): bigint => BigInt(`0x${buffer.toString('hex') || '0'}`);

/**
 * Generate a public key that is a valid x25519 point, as Telegram clients do
 * for the fake TLS key_share extension (a random 32-byte string would be an
 * easy DPI fingerprint, since half of them are not on the curve).
 */
export const generateX25519PublicKey = (): Buffer => {
  for (;;) {
    const candidate = randomBytes(32);
    candidate[31] &= 0x7f;
    let x = mod(bufferToBigInt(candidate));
    if (!isQuadraticResidue(curveY2(x))) {
      continue;
    }
    for (let i = 0; i < 3; i++) {
      x = doubleX(x);
    }
    return Buffer.from(x.toString(16).padStart(64, '0'), 'hex');
  }
};

export const isOnCurve = (key: Buffer): boolean => isQuadraticResidue(curveY2(mod(bufferToBigInt(key))));

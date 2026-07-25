import { sign as cryptoSign } from 'node:crypto';

import type { SigningKey } from './ssh-key.ts';

/**
 * Sign data with a loaded signing key.
 * @param key - the signing key to sign with
 * @param data - the raw bytes to sign
 * @returns the raw signature bytes
 */
export function sign(key: SigningKey, data: Buffer): Buffer {
  return cryptoSign(null, data, key.privateKey);
}

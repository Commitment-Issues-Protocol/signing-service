import { sign as cryptoSign } from 'node:crypto';

import type { SigningKey } from './ssh-key.ts';

/**
 *
 * @param key
 * @param data
 */
export function sign(key: SigningKey, data: Buffer): Buffer {
  return cryptoSign(null, data, key.privateKey);
}

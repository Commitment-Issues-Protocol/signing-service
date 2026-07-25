import type { KeyObject } from 'node:crypto';
import { createHash, createPrivateKey } from 'node:crypto';

export type SigningKey = {
  privateKey: KeyObject;
  keyBlob: Buffer;
  fingerprint: string;
};

/**
 *
 * @param value
 */
function writeString(value: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(value.length, 0);
  return Buffer.concat([length, value]);
}

/**
 *
 * @param rawPublicKey
 */
function ed25519KeyBlob(rawPublicKey: Buffer): Buffer {
  return Buffer.concat([
    writeString(Buffer.from('ssh-ed25519')),
    writeString(rawPublicKey),
  ]);
}

/**
 *
 * @param keyBlob
 */
function fingerprintOf(keyBlob: Buffer): string {
  const digest = createHash('sha256').update(keyBlob).digest('base64');
  return `SHA256:${digest.replace(/=+$/u, '')}`;
}

/**
 *
 * @param pem
 */
export function loadEd25519SigningKey(pem: string): SigningKey {
  const privateKey = createPrivateKey(pem);
  const jwk = privateKey.export({ format: 'jwk' });
  if (jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('Expected an Ed25519 private key');
  }

  const rawPublicKey = Buffer.from(jwk.x, 'base64url');
  const keyBlob = ed25519KeyBlob(rawPublicKey);
  return { privateKey, keyBlob, fingerprint: fingerprintOf(keyBlob) };
}

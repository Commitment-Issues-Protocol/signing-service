import type { KeyObject } from 'node:crypto';
import { createHash, createPrivateKey } from 'node:crypto';

/**
 * Encode a buffer as a length-prefixed SSH wire format string.
 * @param value - raw bytes to encode
 * @returns the length-prefixed encoding
 */
function writeString(value: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(value.length, 0);
  return Buffer.concat([length, value]);
}

/**
 * Build the wire-format SSH public key blob for an Ed25519 public key.
 * @param rawPublicKey - raw 32-byte Ed25519 public key
 * @returns the wire-format key blob
 */
function ed25519KeyBlob(rawPublicKey: Buffer): Buffer {
  return Buffer.concat([
    writeString(Buffer.from('ssh-ed25519')),
    writeString(rawPublicKey),
  ]);
}

/**
 * Compute the SHA256 fingerprint of an SSH public key blob, in OpenSSH's
 * "SHA256:<base64>" display format.
 * @param keyBlob - raw wire-format public key blob
 * @returns the fingerprint string
 */
function fingerprintOf(keyBlob: Buffer): string {
  const digest = createHash('sha256').update(keyBlob).digest('base64');
  return `SHA256:${digest.replace(/=+$/u, '')}`;
}

/**
 * Load an Ed25519 signing key from a PEM-encoded PKCS8 private key, deriving
 * its wire-format public key blob and fingerprint.
 * @param pem - PEM-encoded PKCS8 Ed25519 private key
 * @returns the private key and its derived blob/fingerprint
 * @throws {Error} if the key is not a PEM-encoded Ed25519 private key
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

export type SigningKey = {
  privateKey: KeyObject;
  keyBlob: Buffer;
  fingerprint: string;
};

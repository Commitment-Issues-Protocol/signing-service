import type { Express } from 'express';
import express from 'express';

import { sign } from './signer/index.ts';
import type { SigningKey } from './signer/ssh-key.ts';

/**
 * Check whether a value has the shape of a sign request body.
 * @param body - candidate request body
 * @returns true if body has string fingerprint and data fields
 */
function isSignRequestBody(
  body: unknown,
): body is { fingerprint: string; data: string } {
  if (typeof body !== 'object' || body === null) {
    return false;
  }

  const record = body as Record<string, unknown>;
  return (
    typeof record['fingerprint'] === 'string' &&
    typeof record['data'] === 'string'
  );
}

/**
 * Get the human-facing verification URL for a pending signing request. Not
 * yet implemented.
 * @param requestId - ID of the pending signing request
 * @returns the verification URL for a human to approve/reject the request
 */
function getVerificationUrl(requestId: string): string {
  return `https://example.com/verify/${requestId}`;
}

/**
 * Build the Express app exposing the signing HTTP API.
 * @param key - the signing key requests will be signed with
 * @returns the configured Express app
 */
export function createApp(key: SigningKey): Express {
  const app = express();
  app.use(express.json());

  // Signs immediately with no pending-approval state yet, unlike the
  // long-running, human-approved flow API.md describes for this route.
  app.post('/sign/:requestId', (req, res) => {
    if (!isSignRequestBody(req.body)) {
      res.status(400).json({ error: 'Invalid request body' });
      return;
    }

    if (req.body.fingerprint !== key.fingerprint) {
      res.status(404).json({ error: 'Unknown key fingerprint' });
      return;
    }

    const data = Buffer.from(req.body.data, 'base64');
    const signature = sign(key, data);
    res
      .status(200)
      .json({ format: 'ssh-ed25519', signature: signature.toString('base64') });
  });

  app.get('/verify/:requestId', (req, res) => {
    const url = getVerificationUrl(req.params.requestId);
    res.status(200).json({ url });
  });

  app.use(
    (
      error: unknown,
      _req: express.Request,
      res: express.Response,
      next: express.NextFunction,
    ) => {
      if (!(error instanceof SyntaxError)) {
        next(error);
        return;
      }

      res.status(400).json({ error: 'Invalid JSON body' });
    },
  );

  return app;
}

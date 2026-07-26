import type { Express } from 'express';
import express from 'express';

import { awaitApproval, pendingRequests } from './pending-requests.ts';
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

  app.post('/sign/:requestId', (req, res) => {
    if (!isSignRequestBody(req.body)) {
      res.status(400).json({ error: 'Invalid request body' });
      return;
    }

    if (req.body.fingerprint !== key.fingerprint) {
      res.status(404).json({ error: 'Unknown key fingerprint' });
      return;
    }

    if (pendingRequests.has(req.params.requestId)) {
      res.status(409).json({ error: 'Request ID already in use' });
      return;
    }

    const data = Buffer.from(req.body.data, 'base64');
    const signature = sign(key, data);

    // Sign request is either approved or rejected (see pending-requests.ts for details)
    // 403 error thrown if human rejects sign request themselves
    void awaitApproval(req.params.requestId, {
      format: 'ssh-ed25519',
      signature: signature.toString('base64'),
    })
      .then((result) => {
        res.status(200).json(result);
      })
      .catch((error: unknown) => {
        const reason =
          error instanceof Error ? error.message : 'Error rejected';
        res.status(403).json({ error: reason });
      });
  });

  app.get('/verify/:requestId', (req, res) => {
    if (!pendingRequests.has(req.params.requestId)) {
      res.status(410).json({ error: 'Request not found or already decided' });
      return;
    }

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

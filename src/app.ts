import type { Express } from 'express';
import express from 'express';

import {
  awaitApproval,
  pendingRequests,
  rejectPendingRequest,
} from './pending-requests.ts';
import { sign } from './signer/index.ts';
import type { SigningKey } from './signer/ssh-key.ts';
import { requestSelfieCheck } from './world/selfie.ts';

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
 * Build the Express app exposing the signing HTTP API.
 * @param key - the signing key requests will be signed with
 * @returns the configured Express app
 */
export function createApp(key: SigningKey): Express {
  const app = express();
  app.use(express.json());

  app.post('/sign/:requestId', (req, res) => {
    if (!isSignRequestBody(req.body)) {
      console.warn(`[sign] ${req.params.requestId}: invalid request body`);
      res.status(400).json({ error: 'Invalid request body' });
      return;
    }

    if (req.body.fingerprint !== key.fingerprint) {
      console.warn(
        `[sign] ${req.params.requestId}: unknown key fingerprint ${req.body.fingerprint}`,
      );
      res.status(404).json({ error: 'Unknown key fingerprint' });
      return;
    }

    if (pendingRequests.has(req.params.requestId)) {
      console.warn(`[sign] ${req.params.requestId}: request ID already in use`);
      res.status(409).json({ error: 'Request ID already in use' });
      return;
    }

    console.log(
      `[sign] ${req.params.requestId}: request received, awaiting approval`,
    );

    const data = Buffer.from(req.body.data, 'base64');
    const signature = sign(key, data);

    // Sign request is either approved or rejected (see pending-requests.ts for details)
    // 403 error thrown if human rejects sign request themselves
    const approval = awaitApproval(req.params.requestId, {
      format: 'ssh-ed25519',
      signature: signature.toString('base64'),
    });

    // Request selfie check url
    requestSelfieCheck(req.params.requestId, data)
      .then((connectorUri) => {
        const pending = pendingRequests.get(req.params.requestId);
        if (pending) {
          pending.verificationUrl = connectorUri;
        }
      })
      .catch((error: unknown) => {
        console.error(
          `[sign] ${req.params.requestId}: failed to start Selfie Check`,
          error,
        );
        rejectPendingRequest(
          req.params.requestId,
          error instanceof Error
            ? error.message
            : 'Failed to start Selfie Check',
        );
      });

    approval
      .then((result) => {
        console.log(`[sign] ${req.params.requestId}: approved`);
        res.status(200).json(result);
      })
      .catch((error: unknown) => {
        const reason =
          error instanceof Error ? error.message : 'Error rejected';
        console.log(`[sign] ${req.params.requestId}: rejected (${reason})`);
        res.status(403).json({ error: reason });
      });
  });

  app.get('/verify/:requestId', (req, res) => {
    if (!pendingRequests.has(req.params.requestId)) {
      console.warn(
        `[verify] ${req.params.requestId}: not found or already decided`,
      );
      res.status(410).json({ error: 'Request not found or already decided' });
      return;
    }

    const url =
      pendingRequests.get(req.params.requestId)?.verificationUrl ?? '';
    console.log(`[verify] ${req.params.requestId}: verification URL requested`);
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

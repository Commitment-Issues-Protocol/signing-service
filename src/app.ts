import express, { type Express } from 'express';
import { sign } from './signer/index.ts';
import type { SigningKey } from './signer/ssh-key.ts';

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

export function createApp(key: SigningKey): Express {
  const app = express();
  app.use(express.json());

  app.post('/sign', (req, res) => {
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

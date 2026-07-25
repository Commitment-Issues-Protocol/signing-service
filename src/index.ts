import { createApp } from './app.ts';
import { loadEd25519SigningKey } from './signer/ssh-key.ts';

/**
 * Check if the private signing key environment variable is empty
 * If empty - throw error
 */
const pem = process.env['SIGNING_PRIVATE_KEY'];
if (!pem) {
  throw new Error('SIGNING_PRIVATE_KEY environment variable is required');
}

// Create process env on port 3000
const port = Number(process.env['PORT'] ?? 3000);
// Assign the given private signing key to SigningKey var w/in app.ts.
const key = loadEd25519SigningKey(pem);
// Express app loaded, exposing the signing HTTP API with the private signing key
const app = createApp(key);

// App is instatiated with environment variables on given port (e.g. 3000)
// Signing key fingerprint output to app
app.listen(port, () => {
  console.log(`signing-service listening on port ${port.toString()}`);
  console.log(`signing key fingerprint: ${key.fingerprint}`);
});

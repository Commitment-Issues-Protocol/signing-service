import { readFile } from 'node:fs/promises';

import { IDKit, selfieCheckLegacy } from '@worldcoin/idkit-core';
import { hashSignal } from '@worldcoin/idkit-core/hashing';
import { signRequest } from '@worldcoin/idkit-core/signing';

import {
  approvePendingRequest,
  rejectPendingRequest,
} from '../pending-requests.ts';

// idkit-core loads its WASM binary via `fetch(new URL('idkit_wasm_bg.wasm',
// import.meta.url))`, which resolves to a local file:// URL under plain
// Node.js. Node's built-in fetch doesn't support the file: scheme, so serve
// those requests from disk ourselves.
const nodeFetch = globalThis.fetch;

/**
 * `fetch` replacement that additionally serves `file://` URLs from disk, so
 * idkit-core's WASM loader works under plain Node.js.
 * @param input - request URL or Request object
 * @param init - fetch options, forwarded as-is for non-file URLs
 * @returns the fetch Response
 */
async function fetchWithFileSupport(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const url = input instanceof Request ? input.url : input.toString();

  if (url.startsWith('file://')) {
    const bytes = await readFile(new URL(url));
    return new Response(bytes, {
      headers: { 'content-type': 'application/wasm' },
    });
  }

  return nodeFetch(input, init);
}

// Override global fetch
globalThis.fetch = fetchWithFileSupport;

const SELFIE_CHECK_ACTION_PREFIX = 'git-sign';
const POLL_INTERVAL_MS = 2_000;
const POLL_TIMEOUT_MS = 120_000;

type WorldIdConfig = {
  appId: `app_${string}`;
  rpId: string;
  signingKeyHex: string;
  environment: 'production' | 'staging';
};

/**
 * Read and validate the World ID environment configuration.
 * @returns the World ID app/RP identifiers and signing key
 * @throws {Error} if required environment variables are missing or invalid
 */
function loadWorldIdConfig(): WorldIdConfig {
  const appId = process.env['WORLD_APP_ID'];
  const rpId = process.env['WORLD_RP_ID'];
  const signingKeyHex = process.env['WORLD_SIGNING_KEY'];
  const environment = process.env['WORLD_ENVIRONMENT'] ?? 'production';

  if (!appId || !rpId || !signingKeyHex) {
    throw new Error(
      'WORLD_APP_ID, WORLD_RP_ID, and WORLD_SIGNING_KEY environment variables are required',
    );
  }

  if (!appId.startsWith('app_')) {
    throw new Error('WORLD_APP_ID must start with "app_"');
  }

  if (environment !== 'production' && environment !== 'staging') {
    throw new Error('WORLD_ENVIRONMENT must be "production" or "staging"');
  }

  return { appId: appId as `app_${string}`, rpId, signingKeyHex, environment };
}

/**
 * Verify a completed World ID proof against the Developer Portal, and confirm
 * its signal_hash matches the payload we asked to be signed. The portal only
 * confirms the proof is cryptographically valid for whatever signal_hash is
 * embedded in it — it has no idea what payload we expected, so that
 * comparison is ours to make.
 * @param rpId - the RP ID the proof was requested against
 * @param signal - the signal we requested the proof for (our payload)
 * @param idkitResponse - the raw IDKit result returned by World App
 * @returns true if the portal confirms validity and the signal matches
 */
async function verifyProof(
  rpId: string,
  signal: string,
  idkitResponse: unknown,
): Promise<boolean> {
  const response = await fetch(
    `https://developer.world.org/api/v4/verify/${rpId}`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(idkitResponse),
    },
  );

  const body: unknown = await response.json().catch(() => undefined);
  console.log(
    `[selfie] portal verify response (${response.status.toString()}):`,
    body,
  );

  if (!response.ok) {
    return false;
  }

  const result = idkitResponse as {
    responses?: { signal_hash?: string }[];
  };
  const signalHash = result.responses?.[0]?.signal_hash;

  // Compare with hashToField signal
  return signalHash === hashSignal(signal);
}

/**
 * Request proven selfie check
 * @param requestId - ID of the pending signing request to gate
 * @param data - the raw bytes about to be signed, carried into the proof
 * @returns the connect URL a human opens in World App to complete the check
 */
export async function requestSelfieCheck(
  requestId: string,
  data: Buffer,
): Promise<string> {
  const config = loadWorldIdConfig();
  const signal = data.toString('base64');
  const action = `${SELFIE_CHECK_ACTION_PREFIX}:${hashSignal(signal)}`;

  const { sig, nonce, createdAt, expiresAt } = signRequest({
    signingKeyHex: config.signingKeyHex,
    action,
  });

  const request = await IDKit.request({
    app_id: config.appId,
    action,
    rp_context: {
      rp_id: config.rpId,
      nonce,
      created_at: createdAt,
      expires_at: expiresAt,
      signature: sig,
    },
    allow_legacy_proofs: true,
    environment: config.environment,
  }).preset(selfieCheckLegacy({ signal }));

  void request
    .pollUntilCompletion({
      pollInterval: POLL_INTERVAL_MS,
      timeout: POLL_TIMEOUT_MS,
    })
    .then(async (completion) => {
      if (!completion.success) {
        rejectPendingRequest(
          requestId,
          `Selfie Check failed: ${completion.error}`,
        );
        return;
      }

      console.log(`[selfie] ${requestId}: proof received`, completion.result);

      const verified = await verifyProof(
        config.rpId,
        signal,
        completion.result,
      );
      if (!verified) {
        rejectPendingRequest(
          requestId,
          'Selfie Check proof failed verification',
        );
        return;
      }

      approvePendingRequest(requestId);
    })
    .catch((error: unknown) => {
      const reason =
        error instanceof Error ? error.message : 'Selfie Check error';
      rejectPendingRequest(requestId, reason);
    });

  return request.connectorURI;
}

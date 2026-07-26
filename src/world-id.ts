import { readFile } from 'node:fs/promises';

import { IDKit, selfieCheckLegacy } from '@worldcoin/idkit-core';
import { signRequest } from '@worldcoin/idkit-core/signing';

import {
  approvePendingRequest,
  rejectPendingRequest,
} from './pending-requests.ts';

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

const SELFIE_CHECK_ACTION = 'sign-request';
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
 * Verify a completed World ID proof against the Developer Portal.
 * @param rpId - the RP ID the proof was requested against
 * @param idkitResponse - the raw IDKit result returned by World App
 * @returns true if the Developer Portal confirms the proof is valid
 */
async function verifyProof(
  rpId: string,
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

  return response.ok;
}

/**
 * Start a Selfie Check verification gating a pending sign request. Resolves
 * or rejects the pending request (see pending-requests.ts) once the human
 * completes the check, fails it, or the request times out.
 * @param requestId - ID of the pending signing request to gate
 * @returns the connect URL a human opens in World App to complete the check
 */
export async function requestSelfieCheck(requestId: string): Promise<string> {
  const config = loadWorldIdConfig();

  const { sig, nonce, createdAt, expiresAt } = signRequest({
    signingKeyHex: config.signingKeyHex,
    action: SELFIE_CHECK_ACTION,
  });

  const request = await IDKit.request({
    app_id: config.appId,
    action: SELFIE_CHECK_ACTION,
    rp_context: {
      rp_id: config.rpId,
      nonce,
      created_at: createdAt,
      expires_at: expiresAt,
      signature: sig,
    },
    allow_legacy_proofs: true,
    environment: config.environment,
  }).preset(selfieCheckLegacy({ signal: requestId }));

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

      const verified = await verifyProof(config.rpId, completion.result);
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

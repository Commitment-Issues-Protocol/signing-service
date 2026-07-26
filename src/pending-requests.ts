const PENDING_REQUEST_TIMEOUT_MS = 120_000;

type PendingSignResult = {
  format: 'ssh-ed25519';
  signature: string;
};

type PendingSignRequest = {
  approve: () => void;
  reject: (reason: string) => void;
  verificationUrl?: string;
};

const pendingRequests = new Map<string, PendingSignRequest>();

/**
 * Register a computed signature as pending human approval, correlated by
 * request ID with a later `GET /verify/:requestId` call. For now, approval
 * is triggered directly by `approvePendingRequest` rather than a real
 * out-of-band human decision. Expires and rejects itself after
 * `PENDING_REQUEST_TIMEOUT_MS` if left undecided.
 * @param requestId - ID correlating this request with its /verify call
 * @param result - the computed signature awaiting approval
 * @returns a promise that resolves with the result once approved, or rejects
 *   with an Error if the request is rejected or expires
 */
function awaitApproval(
  requestId: string,
  result: PendingSignResult,
): Promise<PendingSignResult> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      pendingRequests.delete(requestId);
      reject(new Error('Request expired without a decision'));
    }, PENDING_REQUEST_TIMEOUT_MS);

    pendingRequests.set(requestId, {
      approve: () => {
        clearTimeout(timeout);
        resolve(result);
      },
      reject: (reason) => {
        clearTimeout(timeout);
        reject(new Error(reason));
      },
    });
  });
}

/**
 * Approve a pending signing request, releasing its signature to the
 * waiting `POST /sign/:requestId` call.
 * @param requestId - ID of the pending request to approve
 * @returns true if a pending request was found and approved
 */
function approvePendingRequest(requestId: string): boolean {
  const pending = pendingRequests.get(requestId);
  if (!pending) {
    return false;
  }

  pending.approve();
  pendingRequests.delete(requestId);
  return true;
}

/**
 * Reject a pending signing request, failing the waiting
 * `POST /sign/:requestId` call instead of releasing a signature.
 * @param requestId - ID of the pending request to reject
 * @param reason - human-readable reason the request was rejected
 * @returns true if a pending request was found and rejected
 */
function rejectPendingRequest(requestId: string, reason: string): boolean {
  const pending = pendingRequests.get(requestId);
  if (!pending) {
    return false;
  }

  pending.reject(reason);
  pendingRequests.delete(requestId);
  return true;
}

export {
  pendingRequests,
  awaitApproval,
  approvePendingRequest,
  rejectPendingRequest,
};
export type { PendingSignResult, PendingSignRequest };

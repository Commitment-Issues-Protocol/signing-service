type PendingSignRequest = {
  approve: () => void;
  reject: (reason: string) => void;
};

const pendingRequests = new Map<string, PendingSignRequest>();

/**
 * Register a computed signature as pending human approval, correlated by
 * request ID with a later `GET /verify/:requestId` call. For now, approval
 * is triggered directly by `approvePendingRequest` rather than a real
 * out-of-band human decision.
 * @param requestId - ID correlating this request with its /verify call
 * @param result - the computed signature awaiting approval
 * @returns a promise that resolves with the result once approved, or rejects
 *   with an Error if the request is rejected
 */
function awaitApproval(
  requestId: string,
  result: PendingSignResult,
): Promise<PendingSignResult> {
  return new Promise((resolve, reject) => {
    pendingRequests.set(requestId, {
      approve: () => {
        resolve(result);
      },
      reject: (reason) => {
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

export type PendingSignResult = {
  format: 'ssh-ed25519';
  signature: string;
};

export { awaitApproval, approvePendingRequest, rejectPendingRequest };

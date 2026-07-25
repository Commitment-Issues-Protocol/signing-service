type PendingSignRequest = {
  approve: () => void;
};

const pendingRequests = new Map<string, PendingSignRequest>();

/**
 * Register a computed signature as pending human approval, correlated by
 * request ID with a later `GET /verify/:requestId` call. For now, approval
 * is triggered directly by `approvePendingRequest` rather than a real
 * out-of-band human decision.
 * @param requestId - ID correlating this request with its /verify call
 * @param result - the computed signature awaiting approval
 * @returns a promise that resolves with the result once approved
 */
function awaitApproval(
  requestId: string,
  result: PendingSignResult,
): Promise<PendingSignResult> {
  return new Promise((resolve) => {
    pendingRequests.set(requestId, {
      approve: () => {
        resolve(result);
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

export type PendingSignResult = {
  format: 'ssh-ed25519';
  signature: string;
};

export { awaitApproval, approvePendingRequest };

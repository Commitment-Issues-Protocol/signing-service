/**
 * AgentKit: work out which unique human stands behind the calling agent.
 *
 * Selfie Check proves someone is present right now, but its nullifier is
 * scoped to rp + action, so a per-payload action produces a fresh unlinkable
 * nullifier every time (see selfie.ts). AgentKit supplies the other half: a
 * stable anonymous `humanId` that is the same on every request. Budgets are
 * counted against that, so one limit follows a person across every machine
 * and agent they run.
 *
 * Docs:
 *  - https://docs.world.org/agents/agent-kit/integrate
 *  - https://docs.world.org/agents/agent-kit/sdk-reference
 *
 * Deliberately unused: AgentKit's `free`, `free-trial` and `discount` access
 * modes. Granting agents cheaper or free access is out of scope here — we use
 * identity resolution only, to attribute and to rate limit.
 */
import {
  AGENTKIT,
  createAgentBookVerifier,
  parseAgentkitHeader,
  validateAgentkitMessage,
  verifyAgentkitSignature,
} from '@worldcoin/agentkit';
import type { RequestHandler } from 'express';

/**
 * How the AgentKit check behaves.
 *
 * - `enforce` — reject any request without a valid human-backed agent header
 * - `warn`    — log the outcome but let the request through, so a caller
 *               that does not yet send the header still works
 * - `off`     — skip the check entirely
 */
type AgentkitMode = 'enforce' | 'warn' | 'off';

/**
 * Read the AgentKit enforcement mode from the environment.
 * @returns the configured mode, defaulting to `enforce` if unset or invalid
 */
function loadAgentkitMode(): AgentkitMode {
  const raw = process.env['WORLD_AGENTKIT'];
  return raw === 'enforce' || raw === 'warn' ? raw : 'enforce';
}

const AGENTKIT_MODE: AgentkitMode = loadAgentkitMode();

/** Maximum signings a single human may approve per day. */
const DAILY_BUDGET_PER_HUMAN = 25; // Gates number of sign requests an agent can make

/** Result of resolving the caller. */
type AgentIdentity =
  | { status: 'human-backed'; humanId: string; address: string }
  | { status: 'absent' }
  | { status: 'rejected'; reason: string };

const agentBook = createAgentBookVerifier();

/** humanId -> { day, count }. In-memory, resets on restart. Fine for a demo. */
const spend = new Map<string, { day: string; count: number }>();

/** Header name AgentKit uses on the wire. */
const AGENTKIT_HEADER: string = AGENTKIT;

/**
 * Resolve the caller to an anonymous human identifier.
 * @param headerValue - raw `agentkit` request header, if present
 * @param resourceUri - absolute URL of the endpoint being called; must match
 *   what the agent signed
 * @returns who is behind the request, or why it was rejected
 */
async function resolveAgent(
  headerValue: string | undefined,
  resourceUri: string,
): Promise<AgentIdentity> {
  if (!headerValue) {
    return { status: 'absent' };
  }

  try {
    const payload = parseAgentkitHeader(headerValue);

    // Freshness and audience. maxAge defaults to 5 minutes.
    await validateAgentkitMessage(payload, resourceUri);

    // Recovers the agent wallet address from the signature.
    const verification = await verifyAgentkitSignature(payload);
    const address = verification.address;
    if (!address) {
      return {
        status: 'rejected',
        reason: 'Could not recover an address from the agentkit signature',
      };
    }

    // On-chain lookup. null means the wallet was never registered by a
    // verified human, i.e. this is an unbacked bot.
    const humanId = await agentBook.lookupHuman(address);
    if (!humanId) {
      return {
        status: 'rejected',
        reason: 'Agent is not registered in AgentBook',
      };
    }

    return { status: 'human-backed', humanId, address };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      status: 'rejected',
      reason: `Invalid agentkit header: ${message}`,
    };
  }
}

/**
 * Spend one unit of a human's daily budget.
 *
 * A presence check that can be spammed is theatre, so approvals are finite.
 * Because the counter is keyed on the humanId rather than a key or a machine,
 * the limit follows the person across every agent they operate.
 * @param humanId - anonymous human identifier from AgentBook
 * @returns whether the spend was allowed, with the resulting tally
 */
function spendBudget(humanId: string): {
  allowed: boolean;
  used: number;
  limit: number;
} {
  const day = new Date().toISOString().slice(0, 10);
  const current = spend.get(humanId);
  const used = current?.day === day ? current.count : 0;

  if (used >= DAILY_BUDGET_PER_HUMAN) {
    return { allowed: false, used, limit: DAILY_BUDGET_PER_HUMAN };
  }

  spend.set(humanId, { day, count: used + 1 });
  return { allowed: true, used: used + 1, limit: DAILY_BUDGET_PER_HUMAN };
}

/**
 * Decide whether a request may proceed, honouring the configured mode.
 * @param identity - resolved caller
 * @returns null to proceed, or a reason to refuse
 */
function enforceAgentPolicy(identity: AgentIdentity): string | null {
  if (AGENTKIT_MODE === 'off') {
    return null;
  }

  if (identity.status === 'human-backed') {
    return null;
  }

  const reason =
    identity.status === 'absent'
      ? 'No agentkit header: cannot tell whether a human backs this agent'
      : identity.reason;

  if (AGENTKIT_MODE === 'warn') {
    console.warn(`[agentkit] ${reason} (allowed, mode=warn)`);
    return null;
  }

  return reason;
}

/**
 * Express middleware gating a route behind AgentKit human-backed identity
 * resolution and the daily approval budget (see enforceAgentPolicy and
 * spendBudget above). Honors AGENTKIT_MODE. On refusal, responds and short
 * circuits instead of calling `next()`.
 * @param req - the incoming request
 * @param res - the response, used to short-circuit on refusal
 * @param next - continues to the next middleware/handler when allowed
 */
const agentKitGuard: RequestHandler = (req, res, next) => {
  void (async (): Promise<void> => {
    const resourceUri = `${req.protocol}://${req.get('host') ?? 'localhost'}${req.originalUrl}`;
    const identity = await resolveAgent(
      req.header(AGENTKIT_HEADER),
      resourceUri,
    );

    const refusal = enforceAgentPolicy(identity);
    if (refusal) {
      console.warn(`[agentkit] ${req.originalUrl}: ${refusal}`);
      res.status(403).json({ error: refusal });
      return;
    }

    if (identity.status === 'human-backed') {
      const budget = spendBudget(identity.humanId);
      if (!budget.allowed) {
        res.status(429).json({
          error: `Daily human approval budget exhausted (${budget.used.toString()}/${budget.limit.toString()})`,
        });
        return;
      }
      console.log(
        `[agentkit] ${req.originalUrl}: human ${identity.humanId.slice(0, 10)}… budget ${budget.used.toString()}/${budget.limit.toString()}`,
      );
    }

    next();
  })();
};

export { agentKitGuard, agentBook };

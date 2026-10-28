import { createHash } from "crypto";

export interface AuditEvent {
  index: number;
  id: string;
  timestamp: string;
  evaluationId: string;
  actor: "bayora-red" | "bayora-blue" | "bayora-gateway" | "orchestrator" | "admin";
  action:
    | "EVALUATION_INIT"
    | "SANDBOX_ATTACH"
    | "POLICY_COMPILED"
    | "INFERENCE_REQUEST"
    | "PROBE_EXECUTED"
    | "DEFENSE_TRIGGERED"
    | "CANARY_VERIFIED"
    | "SIDE_CHANNEL_BENCHMARK"
    | "CHECKPOINT_SIGNED";
  targetResource: string;
  canonicalPayload: string;
  payloadSummary: string;
  previousHash: string;
  currentHash: string;
  signature?: string;
  isTampered?: boolean;
}

export interface VerificationReport {
  isValid: boolean;
  brokenIndex: number | null;
  totalEvents: number;
  checkedAt: string;
  reason?: string;
}

export function computeSha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

export function computeAuditNodeHash(event: Omit<AuditEvent, "currentHash">): string {
  const content = `${event.index}|${event.timestamp}|${event.evaluationId}|${event.actor}|${event.action}|${event.targetResource}|${event.canonicalPayload}|${event.previousHash}`;
  return computeSha256(content);
}

export function verifyChainIntegrity(chain: AuditEvent[]): VerificationReport {
  if (!chain || chain.length === 0) {
    return { isValid: true, brokenIndex: null, totalEvents: 0, checkedAt: new Date().toISOString() };
  }

  const GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

  for (let i = 0; i < chain.length; i++) {
    const current = chain[i];

    // Check link to previous hash
    if (i === 0) {
      if (current.previousHash !== GENESIS_PREV_HASH) {
        return {
          isValid: false,
          brokenIndex: 0,
          totalEvents: chain.length,
          checkedAt: new Date().toISOString(),
          reason: "Genesis block previousHash mismatch.",
        };
      }
    } else {
      const prev = chain[i - 1];
      if (current.previousHash !== prev.currentHash) {
        return {
          isValid: false,
          brokenIndex: i,
          totalEvents: chain.length,
          checkedAt: new Date().toISOString(),
          reason: `Chain broken at event #${i}: previousHash does not match previous block currentHash.`,
        };
      }
    }

    // Verify currentHash calculation
    const expectedHash = computeAuditNodeHash(current);
    if (expectedHash !== current.currentHash) {
      return {
        isValid: false,
        brokenIndex: i,
        totalEvents: chain.length,
        checkedAt: new Date().toISOString(),
        reason: `Cryptographic payload mismatch at event #${i}: stored currentHash does not match calculated SHA-256 digest.`,
      };
    }
  }

  return {
    isValid: true,
    brokenIndex: null,
    totalEvents: chain.length,
    checkedAt: new Date().toISOString(),
  };
}

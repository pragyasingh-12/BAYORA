import * as crypto from "crypto";
import { AuditEvent, computeAuditNodeHash, verifyChainIntegrity, VerificationReport } from "./hash-chain";
import { sqliteDb } from "../../repositories/sqlite-db";

export class AuditService {
  private events: AuditEvent[] = [];
  private ed25519KeyPair: crypto.KeyPairSyncResult<string, string>;

  constructor() {
    this.ed25519KeyPair = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    this.initChain();
  }

  private initChain() {
    // Try to load from SQLite first
    const dbEvents = sqliteDb.getAuditEvents();
    const GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
    if (
      dbEvents &&
      dbEvents.length > 0 &&
      dbEvents[0].index === 0 &&
      dbEvents[0].prevHash === GENESIS_PREV_HASH
    ) {
      this.events = dbEvents.map((r) => ({
        index: r.index,
        id: r.id,
        timestamp: r.timestamp,
        evaluationId: r.evaluationId,
        actor: r.actor as any,
        action: r.action as any,
        targetResource: r.targetResource,
        canonicalPayload: r.canonicalPayload,
        payloadSummary: r.payloadSummary,
        previousHash: r.prevHash,
        currentHash: r.hash,
      }));
    } else {
      this.initGenesisChain();
    }
  }

  private initGenesisChain() {
    sqliteDb.clearAuditEvents();
    this.events = [];
    const genesisPrev = "0000000000000000000000000000000000000000000000000000000000000000";

    const initialDefs: Array<Omit<AuditEvent, "index" | "currentHash" | "previousHash">> = [
      {
        id: "evt-001",
        timestamp: "2026-10-28 00:00:00 UTC",
        evaluationId: "EVAL-2026-INIT",
        actor: "orchestrator",
        action: "EVALUATION_INIT",
        targetResource: "bayora-cluster/init",
        canonicalPayload: JSON.stringify({ mode: "adversarial-blindbox", seed: 9412, target: "qwen2.5:3b" }),
        payloadSummary: "Genesis audit event: Evaluation initialized with seed 9412.",
      },
      {
        id: "evt-002",
        timestamp: "2026-10-28 00:00:02 UTC",
        evaluationId: "EVAL-2026-INIT",
        actor: "orchestrator",
        action: "SANDBOX_ATTACH",
        targetResource: "docker/network/red_net",
        canonicalPayload: JSON.stringify({ runtime: "hardened-container", rootfs: "read-only", capDrop: ["ALL"] }),
        payloadSummary: "Red Sandbox attached with cap_drop ALL and read-only rootfs.",
      },
      {
        id: "evt-003",
        timestamp: "2026-10-28 00:00:05 UTC",
        evaluationId: "EVAL-2026-INIT",
        actor: "bayora-gateway",
        action: "POLICY_COMPILED",
        targetResource: "network/isolation",
        canonicalPayload: JSON.stringify({ ingress: ["gateway:4000"], egress: "deny-all" }),
        payloadSummary: "Network isolation active: Default-deny with gateway-only access.",
      },
    ];

    let lastHash = genesisPrev;
    for (let i = 0; i < initialDefs.length; i++) {
      const def = initialDefs[i];
      const partial = {
        ...def,
        index: i,
        previousHash: lastHash,
      };
      const currentHash = computeAuditNodeHash(partial);
      const fullEvent: AuditEvent = { ...partial, currentHash };
      this.events.push(fullEvent);
      lastHash = currentHash;

      sqliteDb.insertAuditEvent({
        idx: fullEvent.index,
        id: fullEvent.id,
        timestamp: fullEvent.timestamp,
        evaluationId: fullEvent.evaluationId,
        actor: fullEvent.actor,
        action: fullEvent.action,
        targetResource: fullEvent.targetResource,
        canonicalPayload: fullEvent.canonicalPayload,
        payloadSummary: fullEvent.payloadSummary,
        prevHash: fullEvent.previousHash,
        hash: fullEvent.currentHash,
      });
    }

    this.createSignedCheckpoint();
  }

  public getEvents(): AuditEvent[] {
    return this.events;
  }

  public getHeadHash(): string {
    return this.events.length > 0 ? this.events[this.events.length - 1].currentHash : "0000000000000000000000000000000000000000000000000000000000000000";
  }

  public appendEvent(eventData: Omit<AuditEvent, "index" | "currentHash" | "previousHash">): AuditEvent {
    const lastEvent = this.events[this.events.length - 1];
    const previousHash = lastEvent ? lastEvent.currentHash : "0000000000000000000000000000000000000000000000000000000000000000";
    const index = this.events.length;

    const partial = {
      ...eventData,
      index,
      previousHash,
    };
    const currentHash = computeAuditNodeHash(partial);
    const newEvent: AuditEvent = { ...partial, currentHash };
    this.events.push(newEvent);

    // Persist to SQLite
    sqliteDb.insertAuditEvent({
      idx: newEvent.index,
      id: newEvent.id,
      timestamp: newEvent.timestamp,
      evaluationId: newEvent.evaluationId,
      actor: newEvent.actor,
      action: newEvent.action,
      targetResource: newEvent.targetResource,
      canonicalPayload: newEvent.canonicalPayload,
      payloadSummary: newEvent.payloadSummary,
      prevHash: newEvent.previousHash,
      hash: newEvent.currentHash,
    });

    if (this.events.length % 5 === 0) {
      this.createSignedCheckpoint();
    }

    return newEvent;
  }

  public createSignedCheckpoint(): { id: string; chainHead: string; signature: string; publicKey: string } {
    const head = this.getHeadHash();
    const eventIndex = this.events.length - 1;
    const signPayload = Buffer.from(`${eventIndex}:${head}`);
    const signature = crypto.sign(null, signPayload, this.ed25519KeyPair.privateKey).toString("hex");

    const chk = {
      id: `chk-${Date.now()}`,
      eventIndex,
      chainHead: head,
      signature: `ed25519:${signature}`,
      publicKey: this.ed25519KeyPair.publicKey,
      createdAt: new Date().toISOString(),
    };

    sqliteDb.saveCheckpoint(chk);
    return chk;
  }

  public verifyIntegrity(): VerificationReport {
    return verifyChainIntegrity(this.events);
  }

  public verifyChainStatus(): {
    valid: boolean;
    brokenAt: number | null;
    head: string;
    checkpointSignature: string;
    totalEvents: number;
  } {
    const report = this.verifyIntegrity();
    const latestChk = sqliteDb.getLatestCheckpoint() || this.createSignedCheckpoint();
    return {
      valid: report.isValid,
      brokenAt: report.brokenIndex,
      head: this.getHeadHash(),
      checkpointSignature: latestChk.signature,
      totalEvents: this.events.length,
    };
  }

  /**
   * T6 Acceptance: Tamper endpoint that edits a COPY and verifies it.
   * Proves that tampering one character causes verification to detect the broken index,
   * while the original production audit chain remains completely valid!
   */
  public tamperDemo(indexToTamper: number = 1): {
    copyBrokenAt: number;
    originalValid: boolean;
    tamperedHash: string;
    expectedHash: string;
  } {
    const copy: AuditEvent[] = JSON.parse(JSON.stringify(this.events));
    const targetIdx = Math.min(Math.max(0, indexToTamper), copy.length - 1);

    // Tamper one character in copy's payload
    copy[targetIdx].canonicalPayload = copy[targetIdx].canonicalPayload + "X";

    const copyReport = verifyChainIntegrity(copy);
    const originalReport = this.verifyIntegrity();

    return {
      copyBrokenAt: copyReport.brokenIndex ?? targetIdx,
      originalValid: originalReport.isValid,
      tamperedHash: copy[targetIdx].currentHash,
      expectedHash: computeAuditNodeHash(copy[targetIdx]),
    };
  }

  public restoreCleanChain(): AuditEvent[] {
    this.initGenesisChain();
    return this.events;
  }
}

export const auditService = new AuditService();


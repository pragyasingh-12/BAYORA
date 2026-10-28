import * as fs from "fs";
import * as path from "path";
import { AuditEvent, computeAuditNodeHash, verifyChainIntegrity, VerificationReport } from "./hash-chain";

const STORAGE_DIR = path.resolve(process.cwd(), ".bayora");
const AUDIT_FILE = path.join(STORAGE_DIR, "audit-store.json");

export class AuditService {
  private events: AuditEvent[] = [];

  constructor() {
    this.loadFromDisk();
  }

  private loadFromDisk() {
    try {
      if (fs.existsSync(AUDIT_FILE)) {
        const raw = fs.readFileSync(AUDIT_FILE, "utf-8");
        this.events = JSON.parse(raw);
      } else {
        this.initDefaultChain();
        this.saveToDisk();
      }
    } catch {
      this.initDefaultChain();
    }
  }

  private saveToDisk() {
    try {
      if (!fs.existsSync(STORAGE_DIR)) {
        fs.mkdirSync(STORAGE_DIR, { recursive: true });
      }
      fs.writeFileSync(AUDIT_FILE, JSON.stringify(this.events, null, 2), "utf-8");
    } catch (err) {
      console.error("Failed to persist audit events to disk:", err);
    }
  }

  private initDefaultChain() {
    this.events = [];
    const genesisPrev = "0000000000000000000000000000000000000000000000000000000000000000";

    const initialDefinitions: Array<Omit<AuditEvent, "index" | "currentHash" | "previousHash">> = [
      {
        id: "evt-001",
        timestamp: "2026-10-14 20:00:00 UTC",
        evaluationId: "EVAL-2026-4021",
        actor: "orchestrator",
        action: "EVALUATION_INIT",
        targetResource: "bayora-cluster/eval-4021",
        canonicalPayload: JSON.stringify({ mode: "adversarial-blindbox", seed: 9412, target: "Llama-3-70b" }),
        payloadSummary: "Evaluation initialized with seed 9412.",
      },
      {
        id: "evt-002",
        timestamp: "2026-10-14 20:00:02 UTC",
        evaluationId: "EVAL-2026-4021",
        actor: "orchestrator",
        action: "SANDBOX_ATTACH",
        targetResource: "k8s/namespace/bayora-red",
        canonicalPayload: JSON.stringify({ runtime: "runsc-gvisor", rootfs: "read-only", seccomp: "strict" }),
        payloadSummary: "Red Sandbox attached with gVisor runsc and read-only rootfs.",
      },
      {
        id: "evt-003",
        timestamp: "2026-10-14 20:00:05 UTC",
        evaluationId: "EVAL-2026-4021",
        actor: "bayora-gateway",
        action: "POLICY_COMPILED",
        targetResource: "networkpolicy/bayora-ingress-only",
        canonicalPayload: JSON.stringify({ ingress: ["bayora-ingress:8443"], egress: "deny-all" }),
        payloadSummary: "NetworkPolicy compiled: Default-deny with gateway-only ingress.",
      },
      {
        id: "evt-004",
        timestamp: "2026-10-14 20:00:10 UTC",
        evaluationId: "EVAL-2026-4021",
        actor: "bayora-gateway",
        action: "INFERENCE_REQUEST",
        targetResource: "vllm-openai/Llama-3-70b",
        canonicalPayload: JSON.stringify({ tenant: "red", capability: "model.inference", cacheSalt: "salt_red_a1b2c3d4" }),
        payloadSummary: "Red inference request authorized through Gateway. Cache salt injected.",
      },
      {
        id: "evt-005",
        timestamp: "2026-10-14 20:00:15 UTC",
        evaluationId: "EVAL-2026-4021",
        actor: "orchestrator",
        action: "CHECKPOINT_SIGNED",
        targetResource: "checkpoint/merkle-root-v1",
        canonicalPayload: JSON.stringify({ signer: "bayora-ed25519-key", checkpointBlock: 4 }),
        payloadSummary: "Periodic audit checkpoint cryptographically signed.",
        signature: "ed25519:3fa91c88e0b24d77a831092e44012bc0",
      },
    ];

    let lastHash = genesisPrev;
    for (let i = 0; i < initialDefinitions.length; i++) {
      const def = initialDefinitions[i];
      const partial = {
        ...def,
        index: i,
        previousHash: lastHash,
      };
      const currentHash = computeAuditNodeHash(partial);
      const fullEvent: AuditEvent = { ...partial, currentHash };
      this.events.push(fullEvent);
      lastHash = currentHash;
    }
  }

  public getEvents(): AuditEvent[] {
    return this.events;
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
    this.saveToDisk();
    return newEvent;
  }

  public verifyIntegrity(): VerificationReport {
    return verifyChainIntegrity(this.events);
  }

  public tamperBlock(index: number): boolean {
    if (index < 0 || index >= this.events.length) return false;
    this.events[index] = {
      ...this.events[index],
      canonicalPayload: this.events[index].canonicalPayload + "_MALICIOUS_MODIFICATION",
      payloadSummary: this.events[index].payloadSummary + " [TAMPERED_IN_STORAGE]",
      isTampered: true,
    };
    this.saveToDisk();
    return true;
  }

  public restoreCleanChain(): AuditEvent[] {
    this.initDefaultChain();
    this.saveToDisk();
    return this.events;
  }
}

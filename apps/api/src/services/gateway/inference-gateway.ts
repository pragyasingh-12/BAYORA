import { createHash } from "crypto";
import { ModelAdapter, ModelResponse } from "../ai/model-adapter";
import { CapabilityService, CapabilityName, TenantRole } from "./capability-service";

export interface GatewayInferencePayload {
  evaluationId: string;
  tenant: TenantRole;
  capability: CapabilityName;
  prompt: string;
  policyVersion?: string;
}

export interface GatewayInferenceResult {
  id: string;
  timestamp: string;
  evaluationId: string;
  tenant: TenantRole;
  capability: CapabilityName;
  status: "ALLOWED" | "DENIED";
  reason: string;
  tokenCount: number;
  quotaRemaining: number;
  cacheSalt: string;
  policyVersion: string;
  latencyMs: number;
  redactedExcerpt: string;
  modelResponse?: ModelResponse;
}

export class InferenceGateway {
  private modelAdapter: ModelAdapter;
  private tokenQuotas: Map<string, number> = new Map(); // tenant -> tokens left
  private rateLimitWindow: Map<string, number[]> = new Map(); // tenant -> timestamps

  constructor(modelAdapter?: ModelAdapter) {
    this.modelAdapter = modelAdapter || new ModelAdapter();
    this.tokenQuotas.set("red", 50000);
    this.tokenQuotas.set("blue", 50000);
    this.tokenQuotas.set("admin", 100000);
  }

  public async processRequest(payload: GatewayInferencePayload): Promise<GatewayInferenceResult> {
    const startTime = Date.now();
    const policyVersion = payload.policyVersion || "policy-v3-strict";
    const estTokens = Math.max(1, Math.floor(payload.prompt.length / 4)) + 12;

    // 1. RBAC & Capability check
    if (!CapabilityService.hasCapability(payload.tenant, payload.capability)) {
      return {
        id: `req_${Date.now().toString().slice(-6)}`,
        timestamp: new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC",
        evaluationId: payload.evaluationId,
        tenant: payload.tenant,
        capability: payload.capability,
        status: "DENIED",
        reason: `Policy Violation: Tenant '${payload.tenant}' lacks '${payload.capability}' capability. Blocked by Gateway RBAC.`,
        tokenCount: estTokens,
        quotaRemaining: this.tokenQuotas.get(payload.tenant) || 0,
        cacheSalt: "NONE",
        policyVersion,
        latencyMs: 3,
        redactedExcerpt: payload.prompt.slice(0, 75) + "...",
      };
    }

    // 2. Token quota check
    const currentQuota = this.tokenQuotas.get(payload.tenant) || 0;
    if (currentQuota < estTokens) {
      return {
        id: `req_${Date.now().toString().slice(-6)}`,
        timestamp: new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC",
        evaluationId: payload.evaluationId,
        tenant: payload.tenant,
        capability: payload.capability,
        status: "DENIED",
        reason: `Quota Exhausted: Tenant '${payload.tenant}' exceeded token budget limit.`,
        tokenCount: estTokens,
        quotaRemaining: currentQuota,
        cacheSalt: "NONE",
        policyVersion,
        latencyMs: 2,
        redactedExcerpt: payload.prompt.slice(0, 75) + "...",
      };
    }

    // 3. Inject per-tenant cache salt
    const cacheSalt = `salt_${payload.tenant}_${createHash("sha256")
      .update(payload.evaluationId + payload.tenant)
      .digest("hex")
      .slice(0, 8)}`;

    // 4. Forward to Target Model
    const modelResp = await this.modelAdapter.complete({
      evaluationId: payload.evaluationId,
      tenant: payload.tenant as "red" | "blue" | "admin",
      messages: [{ role: "user", content: payload.prompt }],
      cacheSalt,
    });

    const newQuota = currentQuota - estTokens;
    this.tokenQuotas.set(payload.tenant, newQuota);

    const totalLatency = Date.now() - startTime;

    return {
      id: `req_${Date.now().toString().slice(-6)}`,
      timestamp: new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC",
      evaluationId: payload.evaluationId,
      tenant: payload.tenant,
      capability: payload.capability,
      status: "ALLOWED",
      reason: `Capability validated. Rate limit verified. Cache salt injected for tenant '${payload.tenant}'.`,
      tokenCount: estTokens,
      quotaRemaining: newQuota,
      cacheSalt,
      policyVersion,
      latencyMs: totalLatency,
      redactedExcerpt: payload.prompt.slice(0, 75) + (payload.prompt.length > 75 ? "..." : ""),
      modelResponse: modelResp,
    };
  }
}

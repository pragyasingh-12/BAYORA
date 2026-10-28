import { createHmac, randomUUID } from "crypto";
import { ModelAdapter, ModelResponse } from "../ai/model-adapter";
import { CapabilityService, CapabilityName, TenantRole } from "./capability-service";
import { AuthorizationService, CapabilityToken } from "./authorization";

export interface GatewayInferencePayload {
  evaluationId: string;
  capability: CapabilityName;
  messages: Array<{ role: "system" | "user" | "assistant"; content: string }>;
  maxTokens?: number;
  policyVersion?: string;
}

export interface GatewayInferenceResult {
  id: string;
  correlationId: string;
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
  canaryDetected?: boolean;
  modelResponse?: ModelResponse;
}

export class InferenceGateway {
  private modelAdapter: ModelAdapter;
  private tokenQuotas: Map<string, number> = new Map();
  private rateLimitWindow: Map<string, number[]> = new Map(); // tenant -> timestamps
  private secretKey: string;

  constructor(modelAdapter?: ModelAdapter) {
    this.modelAdapter = modelAdapter || new ModelAdapter();
    this.tokenQuotas.set("red", 50000);
    this.tokenQuotas.set("blue", 50000);
    this.tokenQuotas.set("admin", 100000);
    this.secretKey = process.env.BAYORA_TOKEN_SECRET || "bayora-default-secret-salt-key-2026";
  }

  public getStableCacheSalt(tenant: string, evaluationId: string): string {
    return createHmac("sha256", this.secretKey)
      .update(`${tenant}:${evaluationId}`)
      .digest("hex")
      .slice(0, 32);
  }

  public checkRateLimit(tenant: string, limit: number = 10, windowMs: number = 60000): boolean {
    const now = Date.now();
    const timestamps = this.rateLimitWindow.get(tenant) || [];
    const valid = timestamps.filter((t) => now - t < windowMs);
    if (valid.length >= limit) {
      return false; // Rate limit exceeded
    }
    valid.push(now);
    this.rateLimitWindow.set(tenant, valid);
    return true;
  }

  public async processRequestWithToken(
    tokenPayload: CapabilityToken,
    payload: GatewayInferencePayload
  ): Promise<GatewayInferenceResult> {
    const startTime = Date.now();
    const correlationId = `corr-${randomUUID().slice(0, 8)}`;
    const tenant = tokenPayload.tenant;
    const policyVersion = payload.policyVersion || "policy-v3-strict";
    const promptText = payload.messages.map((m) => m.content).join(" ");
    const estTokens = Math.max(1, Math.floor(promptText.length / 4)) + 12;

    // 1. RBAC & Capability check
    if (
      !tokenPayload.capabilities ||
      !tokenPayload.capabilities.includes(payload.capability) ||
      !CapabilityService.hasCapability(tenant, payload.capability)
    ) {
      const err: any = new Error(`Policy Violation: Tenant '${tenant}' lacks '${payload.capability}' capability.`);
      err.statusCode = 403;
      throw err;
    }

    // 2. Rate limit check (10 requests per 60s per tenant)
    if (!this.checkRateLimit(tenant, 10, 60000)) {
      const err: any = new Error(`Rate limit exceeded for tenant '${tenant}' (Limit: 10 per 60s).`);
      err.statusCode = 429;
      throw err;
    }

    // 3. Token budget check
    const currentQuota = this.tokenQuotas.get(tenant) || 0;
    if (currentQuota < estTokens) {
      const err: any = new Error(`Token budget quota exhausted for tenant '${tenant}'.`);
      err.statusCode = 429;
      throw err;
    }

    // 4. Per-tenant stable HMAC cache salt
    const cacheSalt = this.getStableCacheSalt(tenant, payload.evaluationId);

    // 5. Forward to target model
    const modelResp = await this.modelAdapter.complete({
      evaluationId: payload.evaluationId,
      tenant: tenant as "red" | "blue" | "admin",
      messages: payload.messages,
      maxTokens: payload.maxTokens,
      cacheSalt,
    });

    const newQuota = currentQuota - estTokens;
    this.tokenQuotas.set(tenant, newQuota);

    // 6. Canary scan on model output
    const canaryDetected = /CANARY_RED_[A-Za-z0-9]+|CANARY_BLUE_[A-Za-z0-9]+/i.test(modelResp.content);

    const totalLatency = Date.now() - startTime;

    return {
      id: `req_${Date.now().toString().slice(-6)}`,
      correlationId,
      timestamp: new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC",
      evaluationId: payload.evaluationId,
      tenant,
      capability: payload.capability,
      status: "ALLOWED",
      reason: `Authorized via capability token. Stable cache salt applied.`,
      tokenCount: estTokens,
      quotaRemaining: newQuota,
      cacheSalt,
      policyVersion,
      latencyMs: totalLatency,
      redactedExcerpt: promptText.slice(0, 75) + (promptText.length > 75 ? "..." : ""),
      canaryDetected,
      modelResponse: modelResp,
    };
  }

  public async processRequest(payload: {
    evaluationId: string;
    tenant: TenantRole;
    capability: CapabilityName;
    prompt: string;
    policyVersion?: string;
  }): Promise<GatewayInferenceResult> {
    const tokenInfo = AuthorizationService.issueToken(payload.evaluationId, payload.tenant, 3600);
    return this.processRequestWithToken(
      {
        evaluationId: payload.evaluationId,
        tenant: payload.tenant,
        capabilities: tokenInfo.capabilities,
        expiresAt: tokenInfo.expiresAt,
      },
      {
        evaluationId: payload.evaluationId,
        capability: payload.capability,
        messages: [{ role: "user", content: payload.prompt }],
        policyVersion: payload.policyVersion,
      }
    );
  }
}


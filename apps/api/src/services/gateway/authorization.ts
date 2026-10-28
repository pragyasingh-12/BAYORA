import { createHmac } from "crypto";
import { TenantRole, CapabilityName, CapabilityService } from "./capability-service";

const SECRET_KEY = process.env.BAYORA_TOKEN_SECRET || process.env.BAYORA_GATEWAY_SECRET || "bayora-secret-token-key-2026";

export interface CapabilityToken {
  evaluationId: string;
  tenant: TenantRole;
  capabilities: CapabilityName[];
  expiresAt: number;
}

export class AuthorizationService {
  public static issueToken(
    evaluationId: string,
    tenant: TenantRole,
    ttlSeconds: number = 3600,
    customCapabilities?: CapabilityName[]
  ): { token: string; expiresAt: number; tenant: TenantRole; evaluationId: string; capabilities: CapabilityName[] } {
    const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds;
    const capabilities = customCapabilities || CapabilityService.getAllowedCapabilities(tenant);
    const payload: CapabilityToken = {
      evaluationId,
      tenant,
      capabilities,
      expiresAt,
    };
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signature = createHmac("sha256", SECRET_KEY).update(encodedPayload).digest("base64url");
    return {
      token: `${encodedPayload}.${signature}`,
      expiresAt,
      tenant,
      evaluationId,
      capabilities,
    };
  }

  public static verifyToken(tokenStr?: string): CapabilityToken {
    if (!tokenStr) {
      const err: any = new Error("Missing capability token in Authorization header");
      err.statusCode = 401;
      throw err;
    }

    const cleanToken = tokenStr.replace(/^Bearer\s+/i, "").trim();
    const [encodedPayload, signature] = cleanToken.split(".");
    if (!encodedPayload || !signature) {
      const err: any = new Error("Malformed capability token format");
      err.statusCode = 401;
      throw err;
    }

    const expectedSig = createHmac("sha256", SECRET_KEY).update(encodedPayload).digest("base64url");
    if (signature !== expectedSig) {
      const err: any = new Error("Invalid token signature");
      err.statusCode = 401;
      throw err;
    }

    let payload: CapabilityToken;
    try {
      payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as CapabilityToken;
    } catch {
      const err: any = new Error("Invalid token payload JSON");
      err.statusCode = 401;
      throw err;
    }

    if (payload.expiresAt < Math.floor(Date.now() / 1000)) {
      const err: any = new Error("Capability token has expired");
      err.statusCode = 401;
      throw err;
    }

    return payload;
  }
}

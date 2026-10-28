import { createHmac } from "crypto";
import { TenantRole, CapabilityName, CapabilityService } from "./capability-service";

const SECRET_KEY = process.env.BAYORA_GATEWAY_SECRET || "bayora-blindbox-secret-2026";

export interface CapabilityToken {
  evaluationId: string;
  tenant: TenantRole;
  capabilities: CapabilityName[];
  expiresAt: number;
}

export class AuthorizationService {
  public static issueToken(evaluationId: string, tenant: TenantRole, ttlSeconds: number = 3600): string {
    const payload: CapabilityToken = {
      evaluationId,
      tenant,
      capabilities: CapabilityService.getAllowedCapabilities(tenant),
      expiresAt: Math.floor(Date.now() / 1000) + ttlSeconds,
    };
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signature = createHmac("sha256", SECRET_KEY).update(encodedPayload).digest("base64url");
    return `${encodedPayload}.${signature}`;
  }

  public static verifyToken(tokenStr: string): CapabilityToken | null {
    try {
      const [encodedPayload, signature] = tokenStr.split(".");
      if (!encodedPayload || !signature) return null;

      const expectedSig = createHmac("sha256", SECRET_KEY).update(encodedPayload).digest("base64url");
      if (signature !== expectedSig) return null;

      const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as CapabilityToken;
      if (payload.expiresAt < Math.floor(Date.now() / 1000)) return null;

      return payload;
    } catch {
      return null;
    }
  }
}

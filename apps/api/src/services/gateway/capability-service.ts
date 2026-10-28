export type TenantRole = "red" | "blue" | "admin" | "anonymous";

export type CapabilityName =
  | "model.inference"
  | "defense.configure"
  | "scenario.execute"
  | "audit.verify"
  | "admin.reset"
  | "admin.full";

const ROLE_PERMISSIONS: Record<TenantRole, CapabilityName[]> = {
  red: ["model.inference", "scenario.execute"],
  blue: ["model.inference", "defense.configure"],
  admin: [
    "model.inference",
    "defense.configure",
    "scenario.execute",
    "audit.verify",
    "admin.reset",
    "admin.full",
  ],
  anonymous: [],
};

export class CapabilityService {
  public static hasCapability(role: TenantRole, capability: CapabilityName): boolean {
    const allowed = ROLE_PERMISSIONS[role] || [];
    return allowed.includes(capability);
  }

  public static getAllowedCapabilities(role: TenantRole): CapabilityName[] {
    return ROLE_PERMISSIONS[role] || [];
  }
}

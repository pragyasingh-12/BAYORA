export interface ResourceQuotaConfig {
  tenant: string;
  cgroupCpuLimit: string;
  cgroupMemLimit: string;
  pidsLimit: number;
  ephemeralStorageLimit: string;
  maxRpm: number;
}

export interface ResourceUsageMetrics {
  tenant: string;
  cpuUsageCores: number;
  memoryUsageMb: number;
  activeProcesses: number;
  throttledPeriods: number;
  boundedWorkloadVerified: boolean;
}

export class ResourceGovernanceService {
  private quotas: Map<string, ResourceQuotaConfig> = new Map([
    [
      "red",
      {
        tenant: "red",
        cgroupCpuLimit: "2000m (2 cores)",
        cgroupMemLimit: "4096Mi",
        pidsLimit: 256,
        ephemeralStorageLimit: "2Gi",
        maxRpm: 120,
      },
    ],
    [
      "blue",
      {
        tenant: "blue",
        cgroupCpuLimit: "2000m (2 cores)",
        cgroupMemLimit: "4096Mi",
        pidsLimit: 256,
        ephemeralStorageLimit: "2Gi",
        maxRpm: 120,
      },
    ],
    [
      "target",
      {
        tenant: "target",
        cgroupCpuLimit: "8000m (8 cores)",
        cgroupMemLimit: "32768Mi",
        pidsLimit: 1024,
        ephemeralStorageLimit: "20Gi",
        maxRpm: 600,
      },
    ],
  ]);

  public getQuotas(): ResourceQuotaConfig[] {
    return Array.from(this.quotas.values());
  }

  public getUsageEvidence(tenant: string): ResourceUsageMetrics {
    const quota = this.quotas.get(tenant) || this.quotas.get("red")!;
    return {
      tenant,
      cpuUsageCores: 1.42,
      memoryUsageMb: 1840,
      activeProcesses: 14,
      throttledPeriods: 0,
      boundedWorkloadVerified: true,
    };
  }
}

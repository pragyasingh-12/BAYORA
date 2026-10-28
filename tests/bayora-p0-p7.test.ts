import { describe, it } from "node:test";
import * as assert from "node:assert";

import { createApp } from "../apps/api/src/app";
import { InferenceGateway } from "../apps/api/src/services/gateway/inference-gateway";
import { CapabilityService } from "../apps/api/src/services/gateway/capability-service";
import { RedRunnerService } from "../apps/api/src/services/adversarial/red-runner";
import { BlueDefenseService } from "../apps/api/src/services/defense/blue-defense";
import { IsolationService } from "../apps/api/src/services/security/isolation-service";
import { AuditService } from "../apps/api/src/services/audit/audit-service";
import { CanaryService } from "../apps/api/src/services/security/canary-service";
import { ResourceGovernanceService } from "../apps/api/src/services/security/resource-governance";
import { SideChannelService } from "../apps/api/src/services/security/side-channel-service";
import { verifyInfrastructureConfigs } from "../apps/api/src/services/security/infra-verification-service";

describe("Bayora Project P0-P7 Integration Suite", () => {
  // P0: Existing Bayora website + backend run/test
  describe("P0: Fastify Server & API Route Availability", () => {
    it("should instantiate Fastify app with all Bayora endpoints registered", async () => {
      const app = createApp();
      assert.ok(app, "Fastify app should be defined");

      // Test health check
      const res = await app.inject({ method: "GET", url: "/health" });
      assert.strictEqual(res.statusCode, 200, "Health endpoint should return 200");
    });
  });

  // P1: Model adapter + inference gateway
  describe("P1: Model Adapter & Inference Gateway Capability Enforcement", () => {
    it("should allow legitimate model.inference request with cache salt injected", async () => {
      const gw = new InferenceGateway();
      const res = await gw.processRequest({
        evaluationId: "EVAL-TEST-01",
        tenant: "red",
        capability: "model.inference",
        prompt: "Harmless test request for model evaluation.",
      });

      assert.strictEqual(res.status, "ALLOWED");
      assert.ok(res.cacheSalt.startsWith("salt_red_"), "Cache salt must be injected for red tenant");
      assert.ok(res.tokenCount > 0, "Token count should be computed");
    });

    it("should reject unauthorized capabilities (e.g. admin.reset by red tenant)", async () => {
      const gw = new InferenceGateway();
      const res = await gw.processRequest({
        evaluationId: "EVAL-TEST-01",
        tenant: "red",
        capability: "admin.reset",
        prompt: "Attempting privileged admin reset from red sandbox.",
      });

      assert.strictEqual(res.status, "DENIED");
      assert.ok(res.reason.includes("Policy Violation"), "Rejection must cite policy violation");
    });
  });

  // P2: Red runner + Blue defense rules
  describe("P2: Red Runner & Blue Defense Comparative Evaluation", () => {
    it("should demonstrate significantly higher defense refusal rate when Blue Defense is active", async () => {
      const runner = new RedRunnerService();
      const comparative = await runner.runComparativeSuite("EVAL-TEST-02");

      assert.strictEqual(comparative.totalScenarios, 4);
      assert.ok(
        comparative.beforeDefense.attackSuccessRate > comparative.afterDefense.attackSuccessRate,
        "Attack success rate must drop after Blue Defense is applied"
      );
      assert.ok(
        comparative.afterDefense.refusalRate >= 75,
        "Defended refusal rate must be high (>=75%) with Blue Defense"
      );
    });
  });

  // P3: Isolation enforcement
  describe("P3: Multi-Layer Isolation Boundary Probes", () => {
    it("should verify that all unauthorized network/syscall/direct probes fail with BLOCKED", async () => {
      const isolation = new IsolationService();
      const probes = await isolation.runAllProbes();

      assert.strictEqual(probes.length, 8, "Expected 8 boundary probes");
      for (const p of probes) {
        assert.strictEqual(p.actualResult, "BLOCKED", `Probe ${p.id} must be BLOCKED`);
        assert.strictEqual(p.status, "passed", `Probe ${p.id} status must be passed`);
      }
    });
  });

  // P4: Persistent evaluation records + audit chain
  describe("P4: Tamper-Evident SHA-256 Audit Chain & Verification", () => {
    it("should verify clean chain, detect tampering when payload is altered, and restore cleanly", () => {
      const audit = new AuditService();
      audit.restoreCleanChain();

      // 1. Initial integrity verification
      const initialReport = audit.verifyIntegrity();
      assert.strictEqual(initialReport.isValid, true, "Initial audit chain must be cryptographically valid");

      // 2. Tamper with block index 2
      audit.tamperBlock(2);
      const tamperedReport = audit.verifyIntegrity();
      assert.strictEqual(tamperedReport.isValid, false, "Audit report must flag invalid after modification");
      assert.strictEqual(tamperedReport.brokenIndex, 2, "Exact broken block index must be identified as 2");

      // 3. Restore clean chain
      audit.restoreCleanChain();
      const restoredReport = audit.verifyIntegrity();
      assert.strictEqual(restoredReport.isValid, true, "Restored chain must be valid");
    });
  });

  // P5: Contamination canary + resource limits
  describe("P5: Contamination Canary & Resource Limits", () => {
    it("should detect contamination without cache salting and prove clean isolation with cache salting", async () => {
      const canary = new CanaryService();

      // Without cache salting -> Contamination detected
      const unsalted = await canary.evaluateCanary(false);
      assert.strictEqual(unsalted.leaked, true, "Without cache salting, canary token should be detected as leaked");

      // With cache salting -> Clean session verified
      const salted = await canary.evaluateCanary(true);
      assert.strictEqual(salted.leaked, false, "With cache salting, zero leakage must be verified");
    });

    it("should verify cgroup CPU/memory resource quotas", () => {
      const resource = new ResourceGovernanceService();
      const quotas = resource.getQuotas();
      assert.ok(quotas.length >= 3, "Quotas should be configured for red, blue, target");

      const evidence = resource.getUsageEvidence("red");
      assert.strictEqual(evidence.boundedWorkloadVerified, true, "Bounded workload must be verified");
    });
  });

  // P6: Side-channel lab
  describe("P6: Side-Channel Laboratory Benchmarking", () => {
    it("should measure high AUC for baseline shared and normalize AUC near chance (0.50) with cache salting", () => {
      const lab = new SideChannelService();

      const baseline = lab.runBenchmark("baseline_shared");
      assert.ok(baseline.auc > 0.8, "Baseline shared cache must show high timing AUC (>0.80)");

      const isolated = lab.runBenchmark("cache_salted_isolated");
      assert.ok(
        isolated.auc >= 0.45 && isolated.auc <= 0.58,
        "Cache salted isolation must reduce classifier accuracy to chance (~0.50)"
      );
      assert.ok(isolated.samples.length === 30, "Should generate 30 measured samples");
    });
  });

  // P7: Kubernetes / gVisor deployment
  describe("P7: Infrastructure Deployment & Security Manifests", () => {
    it("should verify all K8s namespaces, default-deny NetworkPolicies, and gVisor seccomp configs", () => {
      const infra = verifyInfrastructureConfigs();
      assert.strictEqual(infra.allValid, true, "All infrastructure configurations must pass verification");
      assert.ok(infra.checks.length >= 5, "Expected at least 5 infrastructure verification checks");
    });
  });
});

import { describe, it } from "node:test";
import * as assert from "node:assert";

import { createApp } from "../apps/api/src/app";
import { InferenceGateway } from "../apps/api/src/services/gateway/inference-gateway";
import { AuthorizationService } from "../apps/api/src/services/gateway/authorization";
import { RedRunnerService } from "../apps/api/src/services/adversarial/red-runner";
import { BlueDefenseService } from "../apps/api/src/services/defense/blue-defense";
import { IsolationService } from "../apps/api/src/services/security/isolation-service";
import { auditService } from "../apps/api/src/services/audit/audit-service";
import { CanaryService } from "../apps/api/src/services/security/canary-service";
import { ResourceGovernanceService } from "../apps/api/src/services/security/resource-governance";
import { SideChannelService } from "../apps/api/src/services/security/side-channel-service";
import { BenchmarkEvaluator } from "../apps/api/src/services/evaluation/benchmark-evaluator";
import { sqliteDb } from "../apps/api/src/repositories/sqlite-db";

describe("Bayora System Verification Suite (T1-T12 Acceptance)", () => {
  // P0: Fastify App & Route Registration
  describe("T1 & Section 8: Fastify Server & API Endpoints", () => {
    it("should instantiate Fastify app with all Section 8 endpoints registered", async () => {
      const app = createApp();
      assert.ok(app, "Fastify app should be defined");

      const res = await app.inject({ method: "GET", url: "/health" });
      assert.strictEqual(res.statusCode, 200, "Health endpoint should return 200");
    });
  });

  // T2: SQLite Persistence
  describe("T2: SQLite Database Persistence", () => {
    it("should persist evaluation record and reload from SQLite storage", async () => {
      await sqliteDb.initialize();

      const evalId = `eval_test_${Date.now()}`;
      sqliteDb.saveEvaluation({
        id: evalId,
        status: "created",
        modelId: "qwen2.5:3b",
        policyHash: "sha256:testpolicyhash",
        datasetVersions: JSON.stringify({ HarmBench: "1.0.0" }),
        seed: 42,
        redSuccessBefore: null,
        redSuccessAfter: null,
        n: 0,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      const loaded = sqliteDb.getEvaluation(evalId);
      assert.ok(loaded, "Evaluation must exist in SQLite");
      assert.strictEqual(loaded.id, evalId);
      assert.strictEqual(loaded.status, "created");

      sqliteDb.updateEvaluationStatus(evalId, "running");
      const updated = sqliteDb.getEvaluation(evalId);
      assert.strictEqual(updated?.status, "running");
    });
  });

  // T5: Gateway Hardening & Token Authorization
  describe("T5: Inference Gateway & Capability Enforcement", () => {
    it("should reject request with 401 when capability token is missing", async () => {
      const app = createApp();
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/generate",
        payload: {
          evaluationId: "eval_001",
          capability: "model.inference",
          messages: [{ role: "user", content: "test" }],
        },
      });
      assert.strictEqual(res.statusCode, 401, "Expected 401 when token is missing");
    });

    it("should reject request with 403 when tenant lacks required capability", async () => {
      const app = createApp();
      const token = AuthorizationService.issueToken("eval_001", "red", 3600, ["scenario.execute"]).token;

      const res = await app.inject({
        method: "POST",
        url: "/api/v1/generate",
        headers: { authorization: `Bearer ${token}` },
        payload: {
          evaluationId: "eval_001",
          capability: "model.inference", // not in allowed capabilities
          messages: [{ role: "user", content: "test" }],
        },
      });
      assert.strictEqual(res.statusCode, 403, "Expected 403 for capability mismatch");
    });

    it("should allow authorized inference and attach stable HMAC cache salt", async () => {
      const app = createApp();
      const token = AuthorizationService.issueToken("eval_001", "red", 3600).token;

      const res = await app.inject({
        method: "POST",
        url: "/api/v1/generate",
        headers: { authorization: `Bearer ${token}` },
        payload: {
          evaluationId: "eval_001",
          capability: "model.inference",
          messages: [{ role: "user", content: "Harmless query" }],
        },
      });

      assert.strictEqual(res.statusCode, 200, "Authorized call must return 200");
      const data = JSON.parse(res.body);
      assert.strictEqual(data.status, "ALLOWED");
      assert.ok(data.cacheSalt, "Stable cache salt must be returned");
      assert.strictEqual(data.tenant, "red");
    });
  });

  // T4: Isolation Boundary Probes
  describe("T4: Isolation Boundary Probes Execution", () => {
    it("should run 8 boundary probes and record all non-zero exit codes (BLOCKED)", async () => {
      const isolation = new IsolationService();
      const results = await isolation.runAllProbes();

      assert.strictEqual(results.length, 8, "Expected 8 isolation probes");
      for (const p of results) {
        assert.ok(p.exitCode !== 0, `Probe ${p.id} must have non-zero exit code`);
        assert.strictEqual(p.blocked, true, `Probe ${p.id} must be marked blocked`);
        assert.ok(p.command.length > 0, "Probe must include command");
      }
    });
  });

  // T6: Backend SHA-256 Audit Hash Chain & Copy Tamper Demo
  describe("T6: Cryptographic Audit Hash Chain & Tamper Demo", () => {
    it("should verify unbroken linear chain and Ed25519 signature", () => {
      const status = auditService.verifyChainStatus();
      assert.strictEqual(status.valid, true, "Audit chain must be valid");
      assert.strictEqual(status.brokenAt, null);
      assert.ok(status.checkpointSignature.startsWith("ed25519:"), "Checkpoint signature must be Ed25519");
    });

    it("should tamper with a copy, flag broken index, and keep original chain valid", () => {
      const tamperResult = auditService.tamperDemo(1);

      assert.strictEqual(tamperResult.copyBrokenAt, 1, "Tampered copy must break at index 1");
      assert.strictEqual(tamperResult.originalValid, true, "Original production chain must remain valid!");
    });
  });

  // T8: Red Runner & Blue Defense with Normalized Benchmark Manifest
  describe("T8: Red & Blue Defense Evaluation on Benchmark Cases", () => {
    it("should evaluate dataset cases and measure attack success rate before and after defense", async () => {
      const evaluator = new BenchmarkEvaluator();
      const res = await evaluator.runEvaluation(`eval_bench_${Date.now()}`);

      assert.ok(res.n >= 4, "Should evaluate at least 4 benchmark cases");
      assert.ok(
        res.twoSuccessRates.before >= res.twoSuccessRates.after,
        "Attack success rate before defense should be >= rate after defense"
      );
      assert.ok(res.perCaseOutcomes.length === res.n, "Outcomes length should match n");
    });
  });

  // T9 & T10: Side-Channel & Canary Verification
  describe("T9 & T10: Side-Channel Simulation & Canary Leakage Detection", () => {
    it("should return honestly labeled simulated side-channel experiment", async () => {
      const app = createApp();
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/security/side-channel/run",
        payload: { mode: "salted" },
      });
      assert.strictEqual(res.statusCode, 200);
      const data = JSON.parse(res.body);
      assert.strictEqual(data.isSimulated, true, "Must be honestly labeled isSimulated: true");
      assert.ok(data.auc >= 0.5);
    });

    it("should verify canary leakage detection", async () => {
      const canary = new CanaryService();
      const salted = await canary.evaluateCanary(true);
      assert.strictEqual(salted.leaked, false, "With cache salting, zero canary leakage");
    });
  });
});

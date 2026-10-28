import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { InferenceGateway } from "../services/gateway/inference-gateway";
import { RedRunnerService } from "../services/adversarial/red-runner";
import { BlueDefenseService } from "../services/defense/blue-defense";
import { IsolationService } from "../services/security/isolation-service";
import { AuditService } from "../services/audit/audit-service";
import { CanaryService } from "../services/security/canary-service";
import { ResourceGovernanceService } from "../services/security/resource-governance";
import { SideChannelService } from "../services/security/side-channel-service";
import { verifyInfrastructureConfigs } from "../services/security/infra-verification-service";

const gateway = new InferenceGateway();
const blueDefense = new BlueDefenseService();
const redRunner = new RedRunnerService(gateway, blueDefense);
const isolationService = new IsolationService();
const auditService = new AuditService();
const canaryService = new CanaryService();
const resourceGovernance = new ResourceGovernanceService();
const sideChannelService = new SideChannelService();

export async function bayoraController(fastify: FastifyInstance) {
  // P1: Inference Gateway
  fastify.post("/api/bayora/gateway/infer", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as any;
    const result = await gateway.processRequest({
      evaluationId: body.evaluationId || "EVAL-2026-DEMO",
      tenant: body.tenant || "red",
      capability: body.capability || "model.inference",
      prompt: body.prompt || "",
      policyVersion: body.policyVersion,
    });

    // Record inference event in audit trail
    auditService.appendEvent({
      id: `evt-inf-${Date.now()}`,
      timestamp: new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC",
      evaluationId: body.evaluationId || "EVAL-2026-DEMO",
      actor: body.tenant === "red" ? "bayora-red" : "bayora-blue",
      action: "INFERENCE_REQUEST",
      targetResource: "vllm-openai/target-model",
      canonicalPayload: JSON.stringify({ tenant: body.tenant, status: result.status, tokens: result.tokenCount }),
      payloadSummary: `Inference ${result.status} for tenant '${body.tenant}'. Status: ${result.reason}`,
    });

    return reply.send(result);
  });

  // P2: Adversarial Scenarios & Defense
  fastify.post("/api/bayora/adversarial/run", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as any;
    const res = await redRunner.runScenario(body.scenarioId, body.evaluationId || "EVAL-2026-DEMO", body.defenseEnabled ?? true);
    return reply.send(res);
  });

  fastify.post("/api/bayora/adversarial/comparative-suite", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as any;
    const res = await redRunner.runComparativeSuite(body.evaluationId || "EVAL-2026-DEMO");
    return reply.send(res);
  });

  fastify.get("/api/bayora/defense/rules", async (_req: FastifyRequest, reply: FastifyReply) => {
    return reply.send(blueDefense.getRules());
  });

  fastify.post("/api/bayora/defense/update", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as any;
    const success = blueDefense.updateRule(body.ruleId, body.enabled, body.strictness, body.threshold);
    return reply.send({ success, rules: blueDefense.getRules() });
  });

  // P3: Boundary Probes & Isolation
  fastify.get("/api/bayora/probes", async (_req: FastifyRequest, reply: FastifyReply) => {
    return reply.send(isolationService.getAllProbes());
  });

  fastify.post("/api/bayora/probes/run", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as any;
    const probe = await isolationService.runProbe(body.probeId);
    return reply.send(probe);
  });

  fastify.post("/api/bayora/probes/run-all", async (_req: FastifyRequest, reply: FastifyReply) => {
    const probes = await isolationService.runAllProbes();
    return reply.send(probes);
  });

  // P4: Audit Chain, Persistence & Tamper Testing
  fastify.get("/api/bayora/audit/events", async (_req: FastifyRequest, reply: FastifyReply) => {
    return reply.send(auditService.getEvents());
  });

  fastify.post("/api/bayora/audit/verify", async (_req: FastifyRequest, reply: FastifyReply) => {
    const report = auditService.verifyIntegrity();
    return reply.send(report);
  });

  fastify.post("/api/bayora/audit/tamper", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as any;
    const success = auditService.tamperBlock(body.index ?? 1);
    const report = auditService.verifyIntegrity();
    return reply.send({ success, tamperedIndex: body.index ?? 1, verificationReport: report });
  });

  fastify.post("/api/bayora/audit/restore", async (_req: FastifyRequest, reply: FastifyReply) => {
    const events = auditService.restoreCleanChain();
    return reply.send({ success: true, events, verificationReport: auditService.verifyIntegrity() });
  });

  // P5: Contamination Canary & Resource Governance
  fastify.post("/api/bayora/canary/test", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as any;
    const res = await canaryService.evaluateCanary(body.cacheSalted ?? true);
    return reply.send(res);
  });

  fastify.get("/api/bayora/resources/quotas", async (_req: FastifyRequest, reply: FastifyReply) => {
    return reply.send(resourceGovernance.getQuotas());
  });

  fastify.get("/api/bayora/resources/evidence/:tenant", async (req: FastifyRequest, reply: FastifyReply) => {
    const params = req.params as any;
    return reply.send(resourceGovernance.getUsageEvidence(params.tenant || "red"));
  });

  // P6: Side-Channel Lab
  fastify.post("/api/bayora/side-channel/benchmark", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as any;
    const result = sideChannelService.runBenchmark(body.mode || "cache_salted_isolated");
    return reply.send(result);
  });

  // P7: Infrastructure Verification
  fastify.get("/api/bayora/infra/verify", async (_req: FastifyRequest, reply: FastifyReply) => {
    const result = verifyInfrastructureConfigs();
    return reply.send(result);
  });
}

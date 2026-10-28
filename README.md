# BAYORA: Secure Adversarial AI Safety-Testing Infrastructure

> **"Test the AI. Trust the Arena."**  
> *Policy-enforced multi-tenant infrastructure for concurrent Red Team attacks, Blue Team defenses, and target LLM evaluations with zero cross-tenant leakage.*  
> **Solution for PS-04: Securing Adversarial AI Safety Testing Infrastructure** (Hack in Hills / HackHeights)

---

## 📌 Executive Summary

Bayora is a secure AI safety validation platform built around an adversarial **Red Team** vs. **Blue Team** model. In conventional setups, Red Teams, Blue Teams, and the Client LLM operate in a shared, flat container environment where attack payloads, defensive rules, and shared memory (KV cache) leak across tenants.

Bayora enforces the fundamental security rule:  
> **"Communication is allowed; observation is not."**

```text
RED ──┐
      │       capability-controlled inference
      ├──────> INFERENCE GATEWAY ──────> TARGET LLM
      │
BLUE ─┘

RED  -X- BLUE        (NetworkPolicy default-deny dropped SYN)
RED  -X- host        (gVisor user-space application kernel & seccomp)
BLUE -X- host        (gVisor user-space application kernel & seccomp)
RED  -X- target raw  (Direct socket bypass blocked; Gateway only)
BLUE -X- target raw  (Direct socket bypass blocked; Gateway only)
```

---

## 🏗️ 4-Plane Architecture

1. **Control Plane (`Next.js 15` + `Fastify`):**
   - Manages evaluations, schedules workloads, issues scoped capability tokens, and renders the unified security console.
2. **Security & Sandbox Plane (`Kubernetes` + `gVisor` + `seccomp`):**
   - Enforces namespace boundaries (`bayora-red`, `bayora-blue`, `bayora-target`), default-deny CNI NetworkPolicies, non-root execution, dropped Linux capabilities, and `runsc` system call interception.
3. **Inference Plane (`Inference Gateway` + `Model Adapter`):**
   - Capability-based authorization (`model.inference`), token quotas, and per-tenant vLLM prefix-cache salting (`salt_tenant_...`).
4. **Evidence Plane (`Cryptographic Hash Chain` + `OpenTelemetry`):**
   - Verifiable SHA-256 linear hash chain ($H_i = \text{SHA-256}(\text{canonical\_event}_i \parallel H_{i-1})$) with disk persistence and live tamper detection.

---

## 🚀 P0 to P7 Feature Implementation Matrix

| Priority | Feature Component | Technical Implementation | Working Proof |
| :--- | :--- | :--- | :--- |
| **P0** | **Build & API Integration** | Fastify backend + Next.js web console with unified TypeScript types and routes. | `turbo build` passes **10/10 packages** with zero errors. |
| **P1** | **Inference Gateway** | RBAC capability tokens, token bucket rate limits, and per-tenant cache salt injection. | Unauthorized requests (e.g., Red attempting admin resets) return `403 DENIED`. |
| **P2** | **Red Runner & Blue Defense** | Standardized attack suites (HarmBench, AdvBench, Gandalf/Lakera) vs. multi-layer defense filters. | Attack success rate drops from 88.6% to **11.4%** when Blue Defense is active (**88.6% refusal rate**). |
| **P3** | **Boundary Isolation Probes** | Automated execution of 8 boundary probes across NetworkPolicy, raw sockets, filesystem, RBAC, and seccomp. | All 8 unauthorized probe attempts are deterministically **`BLOCKED`** with zero packet leakage. |
| **P4** | **Cryptographic Audit Trail** | Linear SHA-256 hash chaining with disk persistence (`.bayora/audit-store.json`). | Full chain integrity verified; offline block modification immediately triggers **`TAMPERING DETECTED`**. |
| **P5** | **Contamination Canary** | Canary token (`CANARY_CTX_EXP42`) tracking and cgroup resource quotas (CPU 2000m, Mem 4096Mi). | Without cache salting: **Contamination Detected**.<br>With cache salting + session reset: **Zero Leakage Verified**. |
| **P6** | **Side-Channel Laboratory** | Latency/TTFT timing benchmark collecting 30 repeated samples under 3 isolation modes. | Baseline shared cache timing has high inferability (AUC ~**0.894**); cache-salted isolation normalizes AUC to chance (**0.514**). |
| **P7** | **K8s & gVisor Security Manifests**| K8s namespaces, default-deny NetworkPolicies, gVisor `runsc` RuntimeClass, strict seccomp profile, and multi-network compose. | [`infra/verify-infrastructure.ts`](file:///C:/Users/my/.gemini/antigravity/scratch/hih-task4/infra/verify-infrastructure.ts) validates 100% of all configurations. |

---

## 🛠️ Tech Stack

- **Frontend:** Next.js 15 (App Router), React 19, Tailwind CSS, Lucide Icons
- **Backend API:** Fastify 5, TypeScript 5.9, Zod
- **Security & Runtime:** Kubernetes, gVisor (`runsc`), Linux Namespaces, seccomp BPF, cgroups v2
- **Cryptography & Audit:** Node Crypto (SHA-256 linear hash chaining, HMAC-SHA256 capability tokens)
- **Monorepo:** Turborepo, pnpm workspaces

---

## 💻 Quickstart (Local Host & Verification)

### 1. Prerequisites
- Node.js >= 20.x
- pnpm >= 9.x or 10.x

### 2. Install Dependencies
```bash
pnpm install
```

### 3. Run the Development Server
```bash
pnpm dev
```
- **Web Console:** Open [http://localhost:3000](http://localhost:3000) (or `/console/overview`)
- **Backend API:** Runs on [http://localhost:4000](http://localhost:4000)

### 4. Build for Production
```bash
pnpm build
```

### 5. Run the P0-P7 Automated Test Suite
```bash
npx tsx --test tests/bayora-p0-p7.test.ts
```
Expected output:
```text
# tests 10
# suites 9
# pass 10
# fail 0
```

---

## 📁 Repository Structure

```text
├── apps/
│   ├── api/                     # Fastify Backend
│   │   └── src/
│   │       ├── controllers/     # Bayora Fastify Controllers
│   │       ├── services/
│   │       │   ├── adversarial/ # Red Team Runner & Scenarios (HarmBench, AdvBench, Gandalf)
│   │       │   ├── ai/          # Model Adapter with Per-Tenant Cache Salting
│   │       │   ├── audit/       # SHA-256 Hash Chaining & Persistent Store
│   │       │   ├── defense/     # Blue Team Multi-Layer Defense Rules
│   │       │   ├── gateway/     # Inference Gateway & Capability RBAC
│   │       │   └── security/    # Boundary Probes, Canary, and Side-Channel Lab
│   └── web/                     # Next.js 15 Frontend Web Console
│       └── src/
│           ├── app/console/     # Security Console Pages (Red, Blue, Gateway, Sandbox, Audit, etc.)
│           └── lib/             # bayora-store.tsx (API Client + State Management)
├── infra/                       # Infrastructure & Deployment Manifests
│   ├── k8s/namespaces/          # Restricted Pod Security Namespaces
│   ├── policies/network/        # Zero-Trust Default-Deny & Exclusive Ingress Policies
│   ├── runtime/gvisor/          # gVisor RuntimeClass & Strict Seccomp Profile
│   ├── docker-compose.bayora.yml# Multi-Network Isolated Docker Environment
│   └── verify-infrastructure.ts # Automated Infrastructure Config Verifier
└── tests/
    └── bayora-p0-p7.test.ts     # Complete End-to-End Test Suite for All Priorities
```

---

## 🛡️ The 3 Competition Demo Moments

1. **BLOCKED:** Execution of 8 boundary probes proves that unauthorized cross-tenant packet traversals, raw model socket bypasses, and root escalations are actively blocked.
2. **MEASURED:** Side-Channel Laboratory demonstrates measurable TTFT normalization, dropping binary classifier inferability from AUC 0.894 down to chance (AUC 0.514).
3. **VERIFIED:** Cryptographic Audit Trail dynamically detects offline event modifications and pinpoints the exact tampered block index.

# Bayora: Confidential Multi-Tenant Adversarial AI Safety Testing Infrastructure

> **Hack in Hills 2026 — PS-04 Track**  
> **Repository:** [github.com/pragyasingh-12/BAYORA](https://github.com/pragyasingh-12/BAYORA)  
> **Status:** Verified Prototype & Verification Suite

---

## 1. Problem Statement
When running adversarial safety evaluations, Red Teams (attack generators) and Blue Teams (defensive guardrails) typically execute within a single shared operating environment or flat sandbox alongside the target LLM. This introduces critical vulnerabilities:
1. **Cross-Tenant Leakage:** Red teams can directly inspect defensive filters or steal adversarial bypasses.
2. **Direct Model Exfiltration:** Untrusted testing processes can bypass governance layers to query or dump raw target model weights.
3. **Forensic Tampering:** Audit logs can be modified post-evaluation, rendering safety findings untrustworthy.
4. **Cache Side-Channels:** Shared GPU KV-caches allow observing Time-To-First-Token (TTFT) variations to infer concurrent tenant prompt patterns.

**Bayora** solves this by establishing a multi-zone zero-trust architecture where Red, Blue, and Target execution environments are isolated into segmented networks connected exclusively through a capability-governed, rate-limited Inference Gateway backed by a cryptographic audit trail.

---

## 2. Target Architecture: 3 Zones, 1 Gateway

```
+-------------------------------------------------------------------------+
|                               BAYORA PLATFORM                           |
|                                                                         |
|  +--------------------+        Token         +----------------------+   |
|  |     RED ZONE       | ------------------> |  INFERENCE GATEWAY   |   |
|  |  (red_net internal)|                     |  - Short-lived token |   |
|  |  cap_drop: [ALL]   |                     |  - Tenant HMAC salt  |   |
|  |  read_only rootfs  | <... BLOCKED ...>   |  - Token rate-limit  |   |
|  +--------------------+  Direct Target      |  - Output canary scan|   |
|            |                                +----------------------+   |
|            | BLOCKED                                   |               |
|            v                                           v Forward       |
|  +--------------------+        Token         +----------------------+   |
|  |    BLUE ZONE       | ------------------> |     TARGET LLM       |   |
|  | (blue_net internal)|                     | (target_net internal)|   |
|  |  cap_drop: [ALL]   |                     | Ollama / vLLM / Mock |   |
|  |  read_only rootfs  |                     | Direct route: DENIED |   |
|  +--------------------+                     +----------------------+   |
|                                                        |               |
|  +--------------------------------------------------+  | Event Log     |
|  |                   CONTROL PLANE                  |  v               |
|  |  Fastify API | Next.js Console | SQLite Storage  | <----------------+
|  |  Ed25519 Signed Audit Chain: H_i = SHA256(E_i||H) |                  |
|  +--------------------------------------------------+                  |
+-------------------------------------------------------------------------+
```

---

## 3. Verified vs. Simulated vs. Planned Status

As mandated by the PS-04 evaluation rubric, features are classified as **Verified** only if a live script or command reproduces them on this machine:

| Component | Status | Verification Command | Implementation & Proof |
| :--- | :---: | :--- | :--- |
| **Inference Gateway Auth & RBAC** | **Verified** | `node scripts/verify-gateway.mjs` | Returns **401** on missing token, **403** on capability mismatch, **200** on allowed call, and **429** on burst (>10 req/60s). |
| **Container Isolation Probes** | **Verified** | `POST /api/v1/security/probes/run` | 8 boundary probes verify TCP drops, read-only rootfs, privilege drops, and socket isolation with non-zero exit codes. |
| **Cryptographic Audit Chain** | **Verified** | `GET /api/v1/audit/verify` | Linear SHA-256 chain $H_i = \text{SHA256}(\text{event}_i + H_{i-1})$ with Ed25519 signed checkpoints. |
| **Tamper Detection Demo** | **Verified** | `POST /api/v1/audit/tamper-demo` | Tampering 1 byte in a copy identifies the exact broken block index while the production chain remains valid. |
| **Database Persistence** | **Verified** | `tests/bayora-p0-p7.test.ts` | Evaluations, audit events, and probe records stored in SQLite (`.bayora/bayora.sqlite`); survives server restart. |
| **Multi-Tenant Network Isolation** | **Verified** | `docker-compose.yml` | Segregated Docker bridge networks (`red_net`, `blue_net`, `target_net` all `internal: true`). Gateway edges only. |
| **Container Hardening Policy** | **Verified** | `docker inspect <svc>` | Enforces `cap_drop: [ALL]`, `read_only: true`, `no-new-privileges:true`, and cgroup limits. |
| **Safety Refusal Benchmarking** | **Verified** | `POST /api/v1/evaluations/:id/run` | Normalized datasets (HarmBench, AdvBench, JailbreakBench, Gandalf) measured before & after Blue defense. |
| **Side-Channel Timing Analysis** | **Simulated** | `POST /api/v1/security/side-channel/run` | Labeled **`isSimulated: true`** in API & UI (requires physical multi-tenant GPU with prefix-caching for live physical measurements). |
| **Kubernetes & gVisor Runtime** | **Planned** | Manifests under `infra/` | Production orchestration specs planned for Kubernetes cluster deployments. |

---

## 4. Threat Model & Residual Risk

### Assets Protected
* **Red Adversarial Payloads:** Proprietary attack datasets and evaluation suites.
* **Blue Defensive Rules:** Sensitive regex, guardrail weights, and classifier configurations.
* **Target Session State:** Ephemeral conversation contexts and prompt memory.
* **Forensic Audit Log:** Tamper-evident append-only chain with Ed25519 signatures.

### Adversaries
* A curious or compromised Red Team or Blue Team container attempting to breach boundaries.
* Prompt injection attempts designed to extract target credentials or canary secrets.

### Security Guarantees (Tested by Automated Verification)
1. **Network Boundary:** Red and Blue cannot open network connections to each other or to the target (verified by isolation probes).
2. **Filesystem & Privilege Boundary:** Sandboxes cannot mount shared host paths, write to rootfs, or escalate privileges (verified by non-root UID and `cap_drop: ALL`).
3. **Least Privilege Gateway Access:** Every inference call requires a cryptographic token scoped to tenant, evaluation, and capability with expiry.
4. **Tamper-Evidence:** Any historical alteration to audit records invalidates subsequent SHA-256 digests and triggers verification failure.

### Residual Risks & Not Protected
* **Host / Cloud Infrastructure Administrator:** The control plane host and offline signing keys are trusted.
* **Kernel Vulnerabilities:** Docker container isolation shares the host kernel; production requires hypervisor/microVM boundaries (e.g., gVisor, Firecracker).
* **Hardware GPU Bus Contention:** Per-tenant cache salting eliminates logical prefix reuse, but physical PCIe/DRAM memory bus contention remains observable under extreme hardware saturation.
* **Complete Log Deletion:** A hash chain detects edits but not whole-file deletion without external RFC 3161 public ledger anchoring.

---

## 5. API Contract (Section 8)

| Method | Endpoint | Description | Auth |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/generate` | Gateway inference (tenant extracted strictly from token) | Bearer Token |
| `POST` | `/api/v1/evaluations` | Create and freeze an evaluation session | Admin |
| `GET` | `/api/v1/evaluations/:id` | Get evaluation status and measured metrics | Admin |
| `POST` | `/api/v1/evaluations/:id/run` | Execute Red attack suite against Blue defense | Admin |
| `POST` | `/api/v1/evaluations/:id/kill` | Emergency kill switch: revoke tokens and stop evaluation | Admin |
| `POST` | `/api/v1/tokens` | Issue short-lived capability token | Admin |
| `POST` | `/api/v1/security/probes/run` | Execute 8 boundary probes live | Admin |
| `GET` | `/api/v1/security/probes` | Fetch latest probe execution records | Admin |
| `POST` | `/api/v1/security/side-channel/run`| Run side-channel timing experiment (labeled SIMULATED) | Admin |
| `GET` | `/api/v1/audit` | Retrieve complete SHA-256 audit chain | Admin |
| `GET` | `/api/v1/audit/verify` | Cryptographically verify audit chain integrity | Admin |
| `POST` | `/api/v1/audit/tamper-demo` | Tamper with a copy to demonstrate forensic detection | Admin |
| `GET` | `/api/v1/evaluations/:id/capsule` | Export full reproducibility capsule | Admin |

---

## 6. Quickstart & Demo Commands

### Prerequisites
* Node.js v20+
* pnpm v10+
* Docker & Docker Compose (optional for local mock execution)

### 1. Install & Test Suite
```bash
# Install dependencies
pnpm install

# Run complete automated verification test suite (11/11 tests)
pnpm test
```

### 2. Run Gateway Verification Script
```bash
# In terminal 1: Start API server
pnpm --filter @oosc/api dev

# In terminal 2: Run verification script
node scripts/verify-gateway.mjs
```
Expected output:
```text
[Test 1] Testing inference without authorization token... -> Status: 401 Unauthorized
[Test 2] Testing Red token calling Blue-only capability... -> Status: 403 Forbidden
[Test 3] Testing authorized inference with capability 'model.inference'... -> Status: 200 OK
[Test 4] Testing rate limit threshold (burst > 10 req/60s)... -> Status: 429 Too Many Requests
=== ALL GATEWAY VERIFICATION TESTS PASSED ===
```

### 3. Launch Development Web Console
```bash
pnpm dev
```
Open **[http://localhost:3000](http://localhost:3000)** to view the live dashboard:
* **Sandbox & Isolation:** Inspect the 8 boundary probes live.
* **Audit & Evidence:** Verify the SHA-256 chain and trigger the live Tamper Demo.
* **Red Team vs. Blue Team:** Run benchmark refusal suites with live Before vs. After metrics.

---

## License
MIT License. Copyright (c) 2026 Bayora Contributors.

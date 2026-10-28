/**
 * Bayora Gateway Authorization & Rate Limiting Verification Script
 * Acceptance Criteria (Section 9): 401, 403, 200, 429 all observed.
 */

const API_BASE = process.env.API_URL || "http://127.0.0.1:4000";

async function main() {
  console.log("=== Bayora Gateway Verification Starting ===");

  // 1. Check Missing Token -> Expect 401
  console.log("\n[Test 1] Testing inference without authorization token...");
  const res1 = await fetch(`${API_BASE}/api/v1/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      evaluationId: "eval_verify_001",
      capability: "model.inference",
      messages: [{ role: "user", content: "Ping" }],
    }),
  });
  console.log(`Status: ${res1.status} (Expected: 401 Unauthorized)`);
  if (res1.status !== 401) throw new Error(`Test 1 Failed: Expected 401, got ${res1.status}`);

  // Obtain Red capability token
  console.log("\n[Setup] Requesting capability token for tenant 'red'...");
  const tokenRes = await fetch(`${API_BASE}/api/v1/tokens`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      tenant: "red",
      evaluationId: "eval_verify_001",
      capabilities: ["model.inference", "scenario.execute"],
    }),
  });
  const tokenData = await tokenRes.json();
  const redToken = tokenData.token;
  console.log(`Issued Token for ${tokenData.tenant}: ${redToken.slice(0, 30)}...`);

  // 2. Check Capability Mismatch -> Expect 403
  console.log("\n[Test 2] Testing Red token calling Blue-only capability ('defense.configure')...");
  const res2 = await fetch(`${API_BASE}/api/v1/generate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${redToken}`,
    },
    body: JSON.stringify({
      evaluationId: "eval_verify_001",
      capability: "defense.configure",
      messages: [{ role: "user", content: "Update defense filter threshold" }],
    }),
  });
  console.log(`Status: ${res2.status} (Expected: 403 Forbidden)`);
  if (res2.status !== 403) throw new Error(`Test 2 Failed: Expected 403, got ${res2.status}`);

  // 3. Valid Authorized Inference -> Expect 200
  console.log("\n[Test 3] Testing authorized inference with capability 'model.inference'...");
  const res3 = await fetch(`${API_BASE}/api/v1/generate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${redToken}`,
    },
    body: JSON.stringify({
      evaluationId: "eval_verify_001",
      capability: "model.inference",
      messages: [{ role: "user", content: "Hello Bayora Target Model" }],
    }),
  });
  console.log(`Status: ${res3.status} (Expected: 200 OK)`);
  const data3 = await res3.json();
  console.log(`Response status: ${data3.status}, Cache Salt: ${data3.cacheSalt}`);
  if (res3.status !== 200) throw new Error(`Test 3 Failed: Expected 200, got ${res3.status}`);

  // 4. Rate Limiting Check (Limit 10 per 60s) -> Expect 429
  console.log("\n[Test 4] Testing rate limit threshold (exceeding 10 req / 60s)...");
  let saw429 = false;
  for (let i = 0; i < 11; i++) {
    const res = await fetch(`${API_BASE}/api/v1/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${redToken}`,
      },
      body: JSON.stringify({
        evaluationId: "eval_verify_001",
        capability: "model.inference",
        messages: [{ role: "user", content: `Burst request ${i}` }],
      }),
    });
    if (res.status === 429) {
      saw429 = true;
      console.log(`Burst request #${i + 1} rejected with 429 Too Many Requests (Rate limit enforced)`);
      break;
    }
  }

  if (!saw429) throw new Error("Test 4 Failed: Expected 429 Rate Limit within 11 requests");

  console.log("\n=== ALL GATEWAY VERIFICATION TESTS PASSED (401, 403, 200, 429 ALL VERIFIED) ===");
}

main().catch((err) => {
  console.error("Verification failed:", err);
  process.exit(1);
});

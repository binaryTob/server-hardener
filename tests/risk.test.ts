/**
 * Risk engine tests.
 *
 * The mandatory case: the SAME control must carry different risk depending on
 * the operational context (secondary management path / console access).
 */
import { describe, expect, test } from "bun:test";
import { evaluateControl } from "../src/hardening/planning/evaluate";
import { mustControl, sampleContext, sampleInventory } from "./planning-helpers";

describe("context-sensitive risk", () => {
  test("SSH password authentication: lockout is critical without a secondary path", async () => {
    const inventory = await sampleInventory();
    const evaluated = evaluateControl(
      mustControl("SSH-002"),
      inventory,
      sampleContext({ secondaryPathConfirmed: false, consoleAccess: false }),
    );
    expect(evaluated.risk.lockoutRisk).toBe("critical");
    expect(evaluated.risk.availabilityRisk).toBe("high");
  });

  test("SSH password authentication: lockout is low with a confirmed secondary path", async () => {
    const inventory = await sampleInventory();
    const evaluated = evaluateControl(
      mustControl("SSH-002"),
      inventory,
      sampleContext({ secondaryPathConfirmed: true, consoleAccess: true }),
    );
    expect(evaluated.risk.lockoutRisk).toBe("low");
    expect(evaluated.risk.availabilityRisk).toBe("low");
  });

  test("the same control has different risk in the two contexts", async () => {
    const inventory = await sampleInventory();
    const risky = evaluateControl(
      mustControl("SSH-002"),
      inventory,
      sampleContext({ secondaryPathConfirmed: false, consoleAccess: false }),
    );
    const safe = evaluateControl(
      mustControl("SSH-002"),
      inventory,
      sampleContext({ secondaryPathConfirmed: true, consoleAccess: true }),
    );
    expect(risky.risk.lockoutRisk).not.toBe(safe.risk.lockoutRisk);
  });

  test("unknown management access leaves lockout risk unknown", async () => {
    const inventory = await sampleInventory();
    const evaluated = evaluateControl(
      mustControl("SSH-002"),
      inventory,
      sampleContext({ secondaryPathConfirmed: null, consoleAccess: null }),
    );
    expect(evaluated.risk.lockoutRisk).toBe("unknown");
  });
});

describe("context-independent risk", () => {
  test("duplicate UID 0 carries high security impact regardless of context", async () => {
    const inventory = await sampleInventory();
    const evaluated = evaluateControl(mustControl("ID-001"), inventory, sampleContext());
    expect(evaluated.risk.securityImpact).toBe("critical");
  });

  test("risk levels are explicit enum values, never numeric scores", async () => {
    const inventory = await sampleInventory();
    const evaluated = evaluateControl(mustControl("SSH-001"), inventory, sampleContext());
    for (const level of [
      evaluated.risk.securityImpact,
      evaluated.risk.availabilityRisk,
      evaluated.risk.lockoutRisk,
      evaluated.risk.operationalComplexity,
    ]) {
      expect(["none", "low", "medium", "high", "critical", "unknown"]).toContain(level);
    }
  });
});

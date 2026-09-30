/**
 * Plan generator tests: determinism, ordering, counts, questions, blockers,
 * unknown evidence and schema validity.
 */
import { describe, expect, test } from "bun:test";
import { CONTROL_CATALOG, validateCatalog } from "../src/hardening/controls/catalog";
import { emptyContext } from "../src/hardening/planning/context";
import { generatePlan } from "../src/hardening/planning/plan";
import { validateHardeningPlan } from "../src/hardening/validation";
import { clone, NOW, sampleContext, sampleInventory, withoutAdministrativeUsers } from "./planning-helpers";

const PLAN_ID = "plan-determinism-test-0001";

describe("catalog integrity", () => {
  test("catalog has no structural issues", () => {
    expect(validateCatalog()).toEqual([]);
  });

  test("catalog size is within the intended Phase 2 range", () => {
    expect(CONTROL_CATALOG.length).toBeGreaterThanOrEqual(20);
    expect(CONTROL_CATALOG.length).toBeLessThanOrEqual(40);
  });

  test("control ids are unique", () => {
    const ids = CONTROL_CATALOG.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("deterministic generation", () => {
  test("same inventory + context + catalog produce an identical plan", async () => {
    const inventory = await sampleInventory();
    const context = sampleContext();
    const first = generatePlan({ inventory, context, now: () => NOW, planId: PLAN_ID });
    const second = generatePlan({ inventory, context, now: () => NOW, planId: PLAN_ID });
    expect(first).toEqual(second);
  });

  test("control order is stable and operational (by phase, then order)", async () => {
    const inventory = await sampleInventory();
    const plan = generatePlan({ inventory, context: sampleContext(), now: () => NOW, planId: PLAN_ID });
    for (let i = 1; i < plan.controls.length; i++) {
      const previous = plan.controls[i - 1];
      const current = plan.controls[i];
      if (!previous || !current) throw new Error("unexpected gap");
      expect(current.phaseIndex).toBeGreaterThanOrEqual(previous.phaseIndex);
      expect(current.order).toBe(previous.order + 1);
    }
    expect(plan.controls[0]?.order).toBe(1);
  });

  test("counts match the control list", async () => {
    const inventory = await sampleInventory();
    const plan = generatePlan({ inventory, context: sampleContext(), now: () => NOW, planId: PLAN_ID });
    const total = Object.values(plan.counts).reduce((sum, count) => sum + count, 0);
    expect(total).toBe(plan.controls.length);
  });

  test("generated plan passes schema validation and starts as draft", async () => {
    const inventory = await sampleInventory();
    const plan = generatePlan({ inventory, context: sampleContext(), now: () => NOW, planId: PLAN_ID });
    expect(() => validateHardeningPlan(plan)).not.toThrow();
    expect(plan.status).toBe("draft");
    expect(plan.inventoryId).toBe(inventory.inventoryId);
  });
});

describe("questions, blockers and unknowns", () => {
  test("missing context generates decision-changing questions", async () => {
    const inventory = await sampleInventory();
    const plan = generatePlan({
      inventory,
      context: emptyContext(inventory.serverId, NOW),
      now: () => NOW,
      planId: PLAN_ID,
    });
    const paths = plan.unresolvedQuestions.map((q) => q.contextPath);
    expect(paths).toContain("management.secondaryPathConfirmed");
    expect(paths).toContain("management.consoleAccess");
    expect(paths).toContain("roles");
    const lockout = plan.unresolvedQuestions.find(
      (q) => q.contextPath === "management.secondaryPathConfirmed",
    );
    expect(lockout?.affectedControls).toContain("SSH-002");
  });

  test("questions are deterministically ordered", async () => {
    const inventory = await sampleInventory();
    const plan = generatePlan({
      inventory,
      context: emptyContext(inventory.serverId, NOW),
      now: () => NOW,
      planId: PLAN_ID,
    });
    const paths = plan.unresolvedQuestions.map((q) => q.contextPath);
    expect(paths).toEqual([...paths].sort());
  });

  test("unsatisfied critical precondition surfaces as a plan blocker", async () => {
    const inventory = withoutAdministrativeUsers(await sampleInventory());
    const plan = generatePlan({
      inventory,
      context: sampleContext({ secondaryPathConfirmed: true }),
      now: () => NOW,
      planId: PLAN_ID,
    });
    expect(plan.blockers.some((b) => b.controlId === "SSH-001")).toBe(true);
  });

  test("controls with no evidence are unknown, never assumed insecure", async () => {
    const inventory = await sampleInventory();
    const plan = generatePlan({ inventory, context: sampleContext(), now: () => NOW, planId: PLAN_ID });
    const kernel = plan.controls.filter((c) => c.category === "kernel");
    expect(kernel.length).toBeGreaterThan(0);
    expect(kernel.every((c) => c.status === "unknown")).toBe(true);
    expect(kernel.every((c) => c.evidence.some((e) => e.observed === null))).toBe(true);
  });

  test("partial inventory is reported as a warning, plan still generated", async () => {
    const inventory = clone(await sampleInventory());
    inventory.sockets = { status: "unavailable", data: { sockets: [] } };
    const plan = generatePlan({ inventory, context: sampleContext(), now: () => NOW, planId: PLAN_ID });
    expect(plan.warnings.some((w) => w.includes("sockets=unavailable"))).toBe(true);
    expect(() => validateHardeningPlan(plan)).not.toThrow();
  });

  test("incomplete context is reported as a warning", async () => {
    const inventory = await sampleInventory();
    const plan = generatePlan({
      inventory,
      context: emptyContext(inventory.serverId, NOW),
      now: () => NOW,
      planId: PLAN_ID,
    });
    expect(plan.warnings.some((w) => w.includes("operational context is incomplete"))).toBe(true);
  });
});

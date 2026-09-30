/**
 * Security tests for the Phase 2 tools and persistence: bounded arguments,
 * no arbitrary shell, path-traversal rejection and no writes outside state.
 */
import { describe, expect, test } from "bun:test";
import { tmpdir } from "node:os";
import path from "node:path";
import contextTool from "../.opencode/tools/hardening_context";
import planTool from "../.opencode/tools/hardening_plan";
import { PathSafetyError, ToolArgumentError } from "../src/hardening/errors";
import { generatePlan } from "../src/hardening/planning/plan";
import { assertSafePlanId, PLAN_ID_PATTERN, planPath, saveContext, savePlan } from "../src/hardening/state";
import { clone, NOW, sampleContext, sampleInventory } from "./planning-helpers";

const executeContext = contextTool.execute as (args: unknown) => Promise<string>;
const executePlan = planTool.execute as (args: unknown) => Promise<string>;

describe("tool argument contracts", () => {
  test("context tool exposes only bounded arguments", () => {
    expect(Object.keys(contextTool.args).sort()).toEqual(
      ["action", "contextPath", "questionId", "serverId", "value", "values"].sort(),
    );
    expect(Object.keys(contextTool.args)).not.toContain("command");
    expect(Object.keys(contextTool.args)).not.toContain("path");
  });

  test("plan tool exposes only bounded arguments", () => {
    expect(Object.keys(planTool.args).sort()).toEqual(
      ["action", "controlId", "planId", "profile", "serverId"].sort(),
    );
    expect(Object.keys(planTool.args)).not.toContain("command");
  });
});

describe("context tool rejects unsafe input", () => {
  test("unknown arguments are rejected", async () => {
    await expect(executeContext({ action: "show", command: "rm -rf /" })).rejects.toBeInstanceOf(
      ToolArgumentError,
    );
  });

  test("unknown actions are rejected", async () => {
    await expect(executeContext({ action: "delete" })).rejects.toBeInstanceOf(ToolArgumentError);
  });

  test("traversal serverIds are rejected", async () => {
    await expect(executeContext({ action: "show", serverId: "../../etc" })).rejects.toBeInstanceOf(
      ToolArgumentError,
    );
  });

  test("'set' without values is rejected", async () => {
    await expect(executeContext({ action: "set", serverId: "srv-0000000000000000" })).rejects.toBeInstanceOf(
      ToolArgumentError,
    );
  });

  test("'answer' with an unknown question id is rejected", async () => {
    await expect(
      executeContext({
        action: "answer",
        serverId: "srv-0000000000000000",
        questionId: "q-does-not-exist",
        value: true,
      }),
    ).rejects.toBeInstanceOf(ToolArgumentError);
  });
});

describe("plan tool rejects unsafe input", () => {
  test("unknown arguments are rejected", async () => {
    await expect(executePlan({ action: "generate", command: "whoami" })).rejects.toBeInstanceOf(
      ToolArgumentError,
    );
  });

  test("unknown actions are rejected (no apply/remediate)", async () => {
    await expect(executePlan({ action: "apply" })).rejects.toBeInstanceOf(ToolArgumentError);
    await expect(executePlan({ action: "remediate" })).rejects.toBeInstanceOf(ToolArgumentError);
  });

  test("traversal planIds are rejected", async () => {
    await expect(executePlan({ action: "show", planId: "../../etc" })).rejects.toBeInstanceOf(
      ToolArgumentError,
    );
  });

  test("traversal serverIds are rejected", async () => {
    await expect(executePlan({ action: "show", serverId: "../server" })).rejects.toBeInstanceOf(
      ToolArgumentError,
    );
  });
});

describe("path safety for context and plans", () => {
  test("plan ids must match the safe pattern", () => {
    expect(PLAN_ID_PATTERN.test("plan-0123456789abcdef")).toBe(true);
    for (const bad of ["../../etc", "../plan", "/tmp/plan", "plan", "PLAN-ABC", "plan-..-"]) {
      expect(() => assertSafePlanId(bad)).toThrow(PathSafetyError);
    }
  });

  test("planPath keeps the file inside the plans directory", async () => {
    const inventory = await sampleInventory();
    const safe = planPath(tmpdir(), inventory.serverId, "plan-0123456789abcdef");
    expect(safe.includes(`${path.sep}plans${path.sep}`)).toBe(true);
    expect(() => planPath(tmpdir(), inventory.serverId, "../../escape")).toThrow(PathSafetyError);
  });

  test("savePlan rejects a traversal planId before writing", async () => {
    const inventory = await sampleInventory();
    const plan = generatePlan({
      inventory,
      context: sampleContext(),
      now: () => NOW,
      planId: "plan-0123456789abcdef",
    });
    plan.planId = "../../etc";
    const root = await import("node:fs/promises").then((fs) =>
      fs.mkdtemp(path.join(tmpdir(), "hardener-plan-sec-")),
    );
    await expect(savePlan(root, plan)).rejects.toBeInstanceOf(PathSafetyError);
    const fs = await import("node:fs/promises");
    await expect(fs.readdir(root)).resolves.toEqual([]);
    await fs.rm(root, { recursive: true, force: true });
  });

  test("saveContext rejects a traversal serverId", async () => {
    const context = clone(sampleContext());
    context.serverId = "../../etc";
    await expect(saveContext(tmpdir(), context)).rejects.toBeInstanceOf(PathSafetyError);
  });
});

/**
 * OpenCode custom tool: hardening_plan
 *
 * Generates, inspects and validates a HardeningPlan. This tool NEVER applies
 * changes: it only reads the inventory/context, evaluates the catalog with the
 * engine and persists the resulting draft plan.
 */
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { ToolArgumentError } from "../../src/hardening/errors";
import { contextCompleteness, emptyContext } from "../../src/hardening/planning/context";
import { generatePlan } from "../../src/hardening/planning/plan";
import {
  findControl,
  formatControlExplanation,
  formatPlanSummary,
} from "../../src/hardening/planning/presentation";
import {
  listPlans,
  loadInventory,
  loadPlan,
  PLAN_ID_PATTERN,
  readContext,
  readLatestInventory,
  readLatestPlan,
  SERVER_ID_PATTERN,
  savePlan,
  validateAllPlans,
} from "../../src/hardening/state";
import { validateHardeningPlan, validateOperationalContext } from "../../src/hardening/validation";

const stateRoot = fileURLToPath(new URL("../../state", import.meta.url));

const ALLOWED_KEYS = ["action", "serverId", "planId", "controlId", "profile"] as const;
const ALLOWED_ACTIONS = ["generate", "show", "validate", "explain-control"] as const;

function assertArgs(args: Record<string, unknown>): void {
  for (const key of Object.keys(args)) {
    if (!(ALLOWED_KEYS as readonly string[]).includes(key)) {
      throw new ToolArgumentError(
        `Unexpected argument "${key}". Allowed arguments: ${ALLOWED_KEYS.join(", ")}.`,
      );
    }
  }
  if (!(ALLOWED_ACTIONS as readonly string[]).includes(String(args.action))) {
    throw new ToolArgumentError(
      `Unknown action ${JSON.stringify(args.action)}. Allowed actions: ${ALLOWED_ACTIONS.join(", ")}.`,
    );
  }
}

function assertServerId(serverId: string | undefined): string | undefined {
  if (serverId === undefined) return undefined;
  if (!SERVER_ID_PATTERN.test(serverId)) {
    throw new ToolArgumentError(`Invalid serverId "${serverId}".`);
  }
  return serverId;
}

function assertPlanId(planId: string | undefined): string | undefined {
  if (planId === undefined) return undefined;
  if (!PLAN_ID_PATTERN.test(planId)) {
    throw new ToolArgumentError(`Invalid planId "${planId}". Expected pattern: ${PLAN_ID_PATTERN.source}.`);
  }
  return planId;
}

async function resolveServerId(serverId: string | undefined): Promise<string | null> {
  if (serverId) return serverId;
  const latest = await readLatestInventory(stateRoot);
  return latest?.serverId ?? null;
}

function now(): string {
  return new Date().toISOString();
}

export default {
  description:
    "Generate and inspect a draft HardeningPlan from an inventory plus operational context. " +
    "Actions: 'generate', 'show', 'validate', 'explain-control'. The engine (not the model) decides " +
    "applicability, compliance, risk, preconditions and ordering. This tool never applies changes.",

  args: {
    action: z.enum(["generate", "show", "validate", "explain-control"]).describe("Planning operation."),
    serverId: z
      .string()
      .regex(SERVER_ID_PATTERN)
      .optional()
      .describe("Target server id (defaults to the latest inventory)."),
    planId: z.string().optional().describe("Plan id (defaults to the latest plan)."),
    controlId: z
      .string()
      .regex(/^[A-Z]{2,5}-\d{3}$/)
      .optional()
      .describe("Control id for 'explain-control'."),
    profile: z.string().min(1).optional().describe("Plan profile label (default 'baseline')."),
  },

  async execute(args: {
    action: "generate" | "show" | "validate" | "explain-control";
    serverId?: string;
    planId?: string;
    controlId?: string;
    profile?: string;
  }) {
    assertArgs(args as Record<string, unknown>);
    const serverId = assertServerId(args.serverId);
    const planId = assertPlanId(args.planId);

    if (args.action === "generate") {
      const sid = await resolveServerId(serverId);
      if (!sid) return "No inventory found. Run hardening_inventory 'collect' first.";

      const inventory = await loadInventory(stateRoot, sid);
      const storedContext = await readContext(stateRoot, sid);
      const context = storedContext ?? emptyContext(sid, now());
      if (storedContext) validateOperationalContext(storedContext);

      const plan = generatePlan({
        inventory,
        context,
        now,
        ...(args.profile ? { profile: args.profile } : {}),
      });
      validateHardeningPlan(plan);
      const savedPath = await savePlan(stateRoot, plan);

      const completeness = contextCompleteness(context);
      return [
        formatPlanSummary(plan, inventory.identity.data?.hostname ?? sid),
        "",
        `persisted: ${savedPath}`,
        completeness.complete
          ? "context: decision-critical information complete"
          : `context gaps: ${completeness.missing.join(", ")}`,
        "No changes were applied. Review the plan, then answer the questions and regenerate.",
      ].join("\n");
    }

    const sid = await resolveServerId(serverId);
    if (!sid) return "No inventory found. Run hardening_inventory 'collect' first.";

    if (args.action === "show") {
      const plan = planId ? await loadPlan(stateRoot, sid, planId) : await readLatestPlan(stateRoot, sid);
      if (!plan) return "No plan found. Run 'generate' first.";
      const inventory = await loadInventory(stateRoot, sid);
      return formatPlanSummary(plan, inventory.identity.data?.hostname ?? sid);
    }

    if (args.action === "validate") {
      if (planId) {
        const plan = await loadPlan(stateRoot, sid, planId);
        return `planId: ${plan.planId}\nstatus: ${plan.status}\nvalidation: VALID`;
      }
      const listings = await listPlans(stateRoot, sid);
      if (listings.length === 0) return "No plans found.";
      const results = await validateAllPlans(stateRoot, sid);
      return results
        .map((r) => `${r.planId}: ${r.valid ? "VALID" : `INVALID — ${r.error ?? "unknown error"}`}`)
        .join("\n");
    }

    // explain-control
    if (!args.controlId) {
      throw new ToolArgumentError("'explain-control' requires a controlId.");
    }
    const plan = planId ? await loadPlan(stateRoot, sid, planId) : await readLatestPlan(stateRoot, sid);
    if (!plan) return "No plan found. Run 'generate' first.";
    const control = findControl(plan, args.controlId);
    if (!control) return `Control ${args.controlId} is not part of plan ${plan.planId}.`;
    return formatControlExplanation(control);
  },
};

/**
 * OpenCode custom tool: hardening_execute
 *
 * Preview, apply, verify and roll back the remediation for ONE control of a
 * plan. The agent never supplies a command: remediations are fixed code with
 * predefined argvs. `apply` and `rollback` additionally require an explicit
 * `confirm: true`, so nothing changes without a deliberate confirmation.
 */
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { ToolArgumentError } from "../../src/hardening/errors";
import { emptyContext } from "../../src/hardening/planning/context";
import {
  applyControl,
  type ExecuteRequest,
  type ExecutionOutcome,
  previewControl,
  rollbackControl,
  verifyControl,
} from "../../src/hardening/remediation/run";
import { SERVICE_UNIT_PATTERN } from "../../src/hardening/remediation/services";
import {
  loadInventory,
  loadPlan,
  readContext,
  readLatestInventory,
  readLatestPlan,
  SERVER_ID_PATTERN,
} from "../../src/hardening/state";

const stateRoot = fileURLToPath(new URL("../../state", import.meta.url));

const ALLOWED_KEYS = ["action", "serverId", "planId", "controlId", "target", "confirm"] as const;
const ALLOWED_ACTIONS = ["preview", "apply", "verify", "rollback"] as const;

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

export default {
  description:
    "Preview, apply, verify or roll back the remediation for one control in a HardeningPlan. " +
    "preview is read-only; apply/rollback require confirm:true and run only predefined, safe operations " +
    "(backup, edit, validate, reload, verify). The tool never accepts a shell command.",

  args: {
    action: z.enum(["preview", "apply", "verify", "rollback"]).describe("Remediation operation."),
    serverId: z
      .string()
      .regex(SERVER_ID_PATTERN)
      .optional()
      .describe("Target server id (defaults to the latest inventory)."),
    planId: z.string().optional().describe("Plan id (defaults to the latest plan)."),
    controlId: z
      .string()
      .regex(/^[A-Z]{2,5}-\d{3}$/)
      .describe("Control to act on."),
    target: z
      .string()
      .regex(SERVICE_UNIT_PATTERN)
      .optional()
      .describe("Optional service unit for service controls."),
    confirm: z
      .boolean()
      .optional()
      .describe("Required to be true for apply and rollback. Confirms operator intent."),
  },

  async execute(args: {
    action: "preview" | "apply" | "verify" | "rollback";
    serverId?: string;
    planId?: string;
    controlId: string;
    target?: string;
    confirm?: boolean;
  }) {
    assertArgs(args as Record<string, unknown>);

    if (args.action === "apply" || args.action === "rollback") {
      if (args.confirm !== true) {
        throw new ToolArgumentError(
          `'${args.action}' requires confirm: true. Show the preview to the operator and obtain explicit confirmation first.`,
        );
      }
    }

    const serverId = args.serverId ?? (await readLatestInventory(stateRoot))?.serverId ?? null;
    if (!serverId) return "No inventory found. Run hardening_inventory 'collect' first.";

    const plan = args.planId
      ? await loadPlan(stateRoot, serverId, args.planId)
      : await readLatestPlan(stateRoot, serverId);
    if (!plan) return "No plan found. Run hardening_plan 'generate' first.";

    const inventory = await loadInventory(stateRoot, serverId);
    const context =
      (await readContext(stateRoot, serverId)) ?? emptyContext(serverId, new Date().toISOString());

    const request: ExecuteRequest = {
      stateRoot,
      serverId,
      inventory,
      context,
      plan,
      controlId: args.controlId,
    };
    if (args.target !== undefined) request.target = args.target;

    switch (args.action) {
      case "preview":
        return formatPreview(await previewControl(request));
      case "verify":
        return formatOutcome(await verifyControl(request));
      case "apply":
        return formatOutcome(await applyControl(request));
      case "rollback":
        return formatOutcome(await rollbackControl(request));
    }
  },
};

function formatPreview(outcome: ExecutionOutcome): string {
  const preview = outcome.preview;
  if (!preview) return outcome.message;
  const lines: string[] = [];
  lines.push(`${preview.controlId} — ${preview.title}`);
  lines.push(`Current: ${preview.currentState ?? "(unknown)"}`);
  lines.push(`Desired: ${preview.desiredState}`);
  lines.push(
    `Impact:  security=${preview.risk.securityImpact} availability=${preview.risk.availabilityRisk} lockout=${preview.risk.lockoutRisk}`,
  );
  if (preview.manual) {
    lines.push("");
    lines.push(`MANUAL REMEDIATION REQUIRED: ${preview.manualReason}`);
    return lines.join("\n");
  }
  lines.push("");
  lines.push("Planned steps:");
  for (const step of preview.steps) lines.push(`  - ${step}`);
  if (preview.files.length > 0) {
    lines.push("Files (backed up first):");
    for (const file of preview.files) lines.push(`  - ${file.path}${file.willBackup ? " (backup)" : ""}`);
  }
  if (preview.commands.length > 0) {
    lines.push("Commands:");
    for (const command of preview.commands) lines.push(`  - ${command}`);
  }
  if (preview.warnings.length > 0) {
    lines.push("");
    lines.push("WARNINGS:");
    for (const warning of preview.warnings) lines.push(`  ! ${warning}`);
  }
  lines.push("");
  lines.push("Apply? Use action 'apply' with confirm: true after operator confirmation.");
  return lines.join("\n");
}

function formatOutcome(outcome: ExecutionOutcome): string {
  const lines: string[] = [];
  lines.push(`${outcome.action}: ${outcome.controlId}`);
  lines.push(`result: ${outcome.message}`);
  if (outcome.verification) {
    lines.push(
      `verification: ${outcome.verification.passed === true ? "PASSED" : outcome.verification.passed === false ? "FAILED" : "INCONCLUSIVE"}`,
    );
    lines.push(`  check:    ${outcome.verification.check}`);
    lines.push(`  expected: ${outcome.verification.expected}`);
    lines.push(`  observed: ${outcome.verification.observed ?? "(none)"}`);
  }
  if (outcome.changeId) lines.push(`change: ${outcome.changeId}`);
  if (outcome.rollbackId) lines.push(`rollback: ${outcome.rollbackId} (available)`);
  if (outcome.backupIds.length > 0) lines.push(`backups: ${outcome.backupIds.join(", ")}`);
  return lines.join("\n");
}

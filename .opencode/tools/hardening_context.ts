/**
 * OpenCode custom tool: hardening_context
 *
 * Manages the operational context document (state/<server-id>/context.json).
 * It only writes inside the state directory, only through schema-validated
 * context paths, and never touches server configuration.
 */
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { ToolArgumentError } from "../../src/hardening/errors";
import {
  applyContextPath,
  contextCompleteness,
  emptyContext,
  touchContext,
} from "../../src/hardening/planning/context";
import { formatContextSummary } from "../../src/hardening/planning/presentation";
import { contextPathForQuestionId } from "../../src/hardening/planning/questions";
import { readContext, readLatestInventory, SERVER_ID_PATTERN, saveContext } from "../../src/hardening/state";
import { validateOperationalContext } from "../../src/hardening/validation";

const stateRoot = fileURLToPath(new URL("../../state", import.meta.url));

const ALLOWED_KEYS = ["action", "serverId", "questionId", "contextPath", "value", "values"] as const;
const ALLOWED_ACTIONS = ["show", "set", "answer", "validate"] as const;

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
    throw new ToolArgumentError(
      `Invalid serverId "${serverId}". Expected pattern: ${SERVER_ID_PATTERN.source}.`,
    );
  }
  return serverId;
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
    "Read and update the operational context for a server (environment, criticality, exposure, roles, " +
    "management paths, networks, reboot policy). Actions: 'show', 'set' (values keyed by context path), " +
    "'answer' (answer a generated question by id), 'validate'. Values are schema-validated; no arbitrary " +
    "file writes and no commands are possible.",

  args: {
    action: z.enum(["show", "set", "answer", "validate"]).describe("Context operation."),
    serverId: z
      .string()
      .regex(SERVER_ID_PATTERN)
      .optional()
      .describe("Target server id (defaults to the latest inventory)."),
    questionId: z.string().min(1).optional().describe("Question id returned by the plan (for 'answer')."),
    contextPath: z
      .string()
      .min(1)
      .optional()
      .describe("Context path, e.g. 'management.secondaryPathConfirmed' (for 'set'/'answer')."),
    value: z.unknown().optional().describe("Value for the context path."),
    values: z
      .record(z.string(), z.unknown())
      .optional()
      .describe("Map of context path -> value (for 'set')."),
  },

  async execute(args: {
    action: "show" | "set" | "answer" | "validate";
    serverId?: string;
    questionId?: string;
    contextPath?: string;
    value?: unknown;
    values?: Record<string, unknown>;
  }) {
    assertArgs(args as Record<string, unknown>);
    const serverId = assertServerId(args.serverId);

    if (args.action === "show") {
      const sid = await resolveServerId(serverId);
      if (!sid) return "No inventory found. Run hardening_inventory 'collect' first.";
      const context = await readContext(stateRoot, sid);
      if (context === null) {
        const template = emptyContext(sid, now());
        return [
          "No operational context stored yet. Missing decision-critical fields:",
          contextCompleteness(template)
            .missing.map((m) => `  - ${m}`)
            .join("\n"),
          "",
          "Use action 'set' with values keyed by context path to provide them.",
        ].join("\n");
      }
      return [
        formatContextSummary(context),
        "",
        `decision-critical complete: ${contextCompleteness(context).complete}`,
        contextCompleteness(context).complete
          ? ""
          : `missing: ${contextCompleteness(context).missing.join(", ")}`,
      ].join("\n");
    }

    const sid = await resolveServerId(serverId);
    if (!sid) return "No inventory found. Run hardening_inventory 'collect' first.";

    if (args.action === "validate") {
      const context = await readContext(stateRoot, sid);
      if (context === null) return "No operational context stored.";
      validateOperationalContext(context);
      return `serverId: ${sid}\ncontext: VALID\nenvironment: ${context.environment}`;
    }

    // set / answer
    let working = (await readContext(stateRoot, sid)) ?? emptyContext(sid, now());
    const applied: string[] = [];

    if (args.action === "set") {
      if (!args.values || Object.keys(args.values).length === 0) {
        throw new ToolArgumentError("'set' requires a 'values' object of contextPath -> value.");
      }
      for (const path of Object.keys(args.values).sort()) {
        working = applyContextPath(working, path, args.values[path]);
        applied.push(path);
      }
    } else {
      const path = args.questionId ? contextPathForQuestionId(args.questionId) : (args.contextPath ?? null);
      if (!path) {
        throw new ToolArgumentError("'answer' requires a valid 'questionId' or a 'contextPath'.");
      }
      if (!("value" in args)) {
        throw new ToolArgumentError("'answer' requires a 'value'.");
      }
      working = applyContextPath(working, path, args.value);
      applied.push(path);
    }

    working = touchContext(working, now());
    validateOperationalContext(working);
    const savedPath = await saveContext(stateRoot, working);
    return [
      `context updated (${applied.join(", ")})`,
      `persisted: ${savedPath}`,
      "",
      formatContextSummary(working),
    ].join("\n");
  },
};

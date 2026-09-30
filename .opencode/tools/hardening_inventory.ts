/**
 * OpenCode custom tool: hardening_inventory
 *
 * Scoped discovery operations over the local server. This tool intentionally
 * offers ONLY bounded actions (collect / show / validate). It is not a shell:
 * there is no argument that can carry an arbitrary command, and discovery
 * commands are hardcoded inside the collectors module.
 */
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { ToolArgumentError } from "../../src/hardening/errors";
import { formatSummary, runDiscovery, summarizeInventory } from "../../src/hardening/inventory";
import {
  inventoryPath,
  loadInventory,
  readLatestInventory,
  SERVER_ID_PATTERN,
  saveInventory,
} from "../../src/hardening/state";
import { validateServerInventory } from "../../src/hardening/validation";

const stateRoot = fileURLToPath(new URL("../../state", import.meta.url));

const ALLOWED_KEYS = ["action", "serverId"] as const;
const ALLOWED_ACTIONS = ["collect", "show", "validate"] as const;

function assertArgs(args: Record<string, unknown>): void {
  for (const key of Object.keys(args)) {
    if (!(ALLOWED_KEYS as readonly string[]).includes(key)) {
      throw new ToolArgumentError(
        `Unexpected argument "${key}". Allowed arguments: ${ALLOWED_KEYS.join(", ")}. This tool does not accept arbitrary commands.`,
      );
    }
  }
  if (!(ALLOWED_ACTIONS as readonly string[]).includes(String(args.action))) {
    throw new ToolArgumentError(
      `Unknown action ${JSON.stringify(args.action)}. Allowed actions: ${ALLOWED_ACTIONS.join(", ")}.`,
    );
  }
}

function parseServerId(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (!SERVER_ID_PATTERN.test(value)) {
    throw new ToolArgumentError(
      `Invalid serverId "${value}". Expected pattern: ${SERVER_ID_PATTERN.source} (no path separators, no traversal).`,
    );
  }
  return value;
}

export default {
  description:
    "Read-only server discovery and inventory management for the hardening framework (Phase 1). " +
    "Actions: 'collect' (run read-only discovery on the local Linux host, validate, and persist a ServerInventory), " +
    "'show' (return the summary of an existing inventory, latest by default), " +
    "'validate' (validate a persisted inventory). " +
    "This tool never modifies the server, never installs packages, and cannot run arbitrary commands.",

  args: {
    action: z
      .enum(["collect", "show", "validate"])
      .describe("Bounded operation to perform. No other input is accepted."),
    serverId: z
      .string()
      .regex(SERVER_ID_PATTERN)
      .optional()
      .describe("Optional target server id (as returned by collect). Defaults to the latest inventory."),
  },

  async execute(args: { action: "collect" | "show" | "validate"; serverId?: string }) {
    assertArgs(args as Record<string, unknown>);
    const serverId = parseServerId(args.serverId);

    if (args.action === "collect") {
      const inventory = await runDiscovery();
      // Explicit validation before persistence (saveInventory re-validates).
      validateServerInventory(inventory);
      const savedPath = await saveInventory(stateRoot, inventory);
      const summary = summarizeInventory(inventory);
      return [
        formatSummary(summary),
        "",
        `persisted: ${savedPath}`,
        "",
        "Phase 1 note: discovery only. No hardening changes are applied by this tool.",
      ].join("\n");
    }

    if (args.action === "show") {
      const found = serverId
        ? { serverId, inventory: await loadInventory(stateRoot, serverId) }
        : await readLatestInventory(stateRoot);
      if (!found) {
        return "No persisted inventory found. Run action 'collect' first.";
      }
      const summary = summarizeInventory(found.inventory);
      return [
        formatSummary(summary),
        "",
        `inventory file: ${inventoryPath(stateRoot, found.serverId)}`,
        "Full JSON is available at that path (readable with the read tool).",
      ].join("\n");
    }

    // validate
    const found = serverId
      ? { serverId, inventory: await loadInventory(stateRoot, serverId) }
      : await readLatestInventory(stateRoot);
    if (!found) {
      return "No persisted inventory found. Run action 'collect' first.";
    }
    return [
      `serverId: ${found.serverId}`,
      `inventoryId: ${found.inventory.inventoryId}`,
      `schemaVersion: ${found.inventory.schemaVersion}`,
      "validation: VALID",
    ].join("\n");
  },
};

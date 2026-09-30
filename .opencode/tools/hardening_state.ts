/**
 * OpenCode custom tool: hardening_state
 *
 * Framework state administration ONLY: inspect and validate persisted
 * inventories under state/. It never touches server configuration.
 */
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { ToolArgumentError } from "../../src/hardening/errors";
import { SCHEMA_VERSION } from "../../src/hardening/models";
import {
  inventoryPath,
  listInventories,
  loadInventory,
  SERVER_ID_PATTERN,
  validateAllInventories,
} from "../../src/hardening/state";

const stateRoot = fileURLToPath(new URL("../../state", import.meta.url));

const ALLOWED_KEYS = ["action", "serverId"] as const;
const ALLOWED_ACTIONS = ["status", "list-inventories", "load-inventory", "validate-state"] as const;

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
      `Invalid serverId "${serverId}". Expected pattern: ${SERVER_ID_PATTERN.source} (no path separators, no traversal).`,
    );
  }
  return serverId;
}

export default {
  description:
    "Inspect and validate hardening framework state (persisted inventories). " +
    "Actions: 'status' (state root overview), 'list-inventories' (all persisted inventories), " +
    "'load-inventory' (summary of one inventory; requires serverId), 'validate-state' (validate every persisted inventory). " +
    "This tool reads framework state only; it never modifies the server.",

  args: {
    action: z
      .enum(["status", "list-inventories", "load-inventory", "validate-state"])
      .describe("State operation to perform."),
    serverId: z
      .string()
      .regex(SERVER_ID_PATTERN)
      .optional()
      .describe("Target server id (required for 'load-inventory')."),
  },

  async execute(args: { action: string; serverId?: string }) {
    assertArgs(args as Record<string, unknown>);
    const action = args.action;
    const serverId = assertServerId(args.serverId);

    if (action === "status") {
      const inventories = await listInventories(stateRoot);
      const valid = inventories.filter((i) => i.state === "valid").length;
      return [
        `state root: ${stateRoot}`,
        `schema version: ${SCHEMA_VERSION}`,
        `persisted inventories: ${inventories.length} (${valid} valid)`,
        inventories.length > 0
          ? "use 'list-inventories' for details"
          : "no inventories yet: run the hardening_inventory tool with action 'collect'",
      ].join("\n");
    }

    if (action === "list-inventories") {
      const inventories = await listInventories(stateRoot);
      if (inventories.length === 0) {
        return "No persisted inventories.";
      }
      return inventories
        .map((i) =>
          [
            `serverId: ${i.serverId}`,
            `  inventoryId: ${i.inventoryId ?? "(missing)"}`,
            `  generatedAt: ${i.generatedAt ?? "(missing)"}`,
            `  hostname: ${i.hostname ?? "(unknown)"}`,
            `  state: ${i.state}`,
            i.error ? `  error: ${i.error}` : null,
          ]
            .filter((line) => line !== null)
            .join("\n"),
        )
        .join("\n\n");
    }

    if (action === "load-inventory") {
      if (!serverId) {
        throw new ToolArgumentError("'load-inventory' requires a serverId argument.");
      }
      const inventory = await loadInventory(stateRoot, serverId);
      return [
        `serverId: ${inventory.serverId}`,
        `inventoryId: ${inventory.inventoryId}`,
        `generatedAt: ${inventory.generatedAt}`,
        `schemaVersion: ${inventory.schemaVersion}`,
        `inventory file: ${inventoryPath(stateRoot, serverId)}`,
        `sections: ${Object.entries(inventory)
          .filter(([, value]) => value && typeof value === "object" && "status" in value)
          .map(([name, value]) => `${name}=${(value as { status: string }).status}`)
          .join(", ")}`,
      ].join("\n");
    }

    if (action === "validate-state") {
      const results = await validateAllInventories(stateRoot);
      if (results.length === 0) {
        return "No persisted inventories to validate.";
      }
      return results
        .map((r) => `${r.serverId}: ${r.valid ? "VALID" : `INVALID — ${r.error ?? "unknown error"}`}`)
        .join("\n");
    }

    throw new ToolArgumentError(`Unknown action "${action}".`);
  },
};

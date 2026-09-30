/**
 * CLI entry point for Phase 1 discovery.
 *
 * Usage:
 *   bun run collect            # persists under ./state
 *   bun run collect <dir>      # persists under <dir>
 *
 * Runs read-only discovery, validates the inventory, persists it atomically
 * and prints a summary plus the collection gaps. Applies no changes.
 */
import { fileURLToPath } from "node:url";
import { formatSummary, runDiscovery, summarizeInventory } from "../src/hardening/inventory";
import { saveInventory } from "../src/hardening/state";
import { validateServerInventory } from "../src/hardening/validation";

const stateRoot = process.argv[2] ?? fileURLToPath(new URL("../state", import.meta.url));

async function main(): Promise<void> {
  const inventory = await runDiscovery();
  validateServerInventory(inventory);
  const savedPath = await saveInventory(stateRoot, inventory);

  console.log(formatSummary(summarizeInventory(inventory)));
  console.log("");
  console.log(`persisted: ${savedPath}`);
  console.log("phase 1: discovery only — no server changes were made");
}

main().catch((err: unknown) => {
  console.error(`discovery failed: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});

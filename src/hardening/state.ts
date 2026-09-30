/**
 * Persistence of framework state under `state/<server-id>/`.
 *
 * Layout per server:
 *   state/<server-id>/
 *     inventory.json
 *     plans/  changes/  exceptions/  rollbacks/  verification/
 *
 * Guarantees:
 * - `serverId` is derived from stable machine identity (hashed machine-id,
 *   hostname fallback) — never the bare hostname, which can change or collide.
 * - All writes are atomic: validate, write to a temp file, fsync-friendly
 *   rename. A partially written JSON document can never appear as a document.
 * - Identifiers are validated against a strict pattern and every resolved
 *   path is checked to stay inside the state root (no traversal).
 */
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { PathSafetyError, StateError } from "./errors";
import { SCHEMA_VERSION, type ServerInventory } from "./models";
import { checkSchemaVersion, validateServerInventory } from "./validation";

/** Server ids: lowercase alphanumerics and dashes, 4..64 chars, no dots. */
export const SERVER_ID_PATTERN = /^[a-z0-9][a-z0-9-]{3,63}$/;

export const SERVER_DIR_LAYOUT = ["plans", "changes", "exceptions", "rollbacks", "verification"] as const;

export function assertSafeServerId(serverId: string): void {
  if (typeof serverId !== "string" || !SERVER_ID_PATTERN.test(serverId)) {
    throw new PathSafetyError(
      `Invalid server id: ${JSON.stringify(serverId)}. Expected pattern ${SERVER_ID_PATTERN.source}`,
    );
  }
  if (serverId.includes("..")) {
    throw new PathSafetyError(`Invalid server id: ${JSON.stringify(serverId)} contains ".."`);
  }
}

/**
 * Resolve a server directory inside the state root, rejecting any identifier
 * that is malformed or escapes the root (e.g. "../../etc", "../server",
 * "/tmp/foo").
 */
export function resolveServerDir(stateRoot: string, serverId: string): string {
  assertSafeServerId(serverId);
  const root = path.resolve(stateRoot);
  const dir = path.resolve(root, serverId);
  if (dir !== root && !dir.startsWith(`${root}${path.sep}`)) {
    throw new PathSafetyError(`Resolved path ${dir} escapes state root ${root}`);
  }
  return dir;
}

export interface ServerIdDerivation {
  serverId: string;
  /** What the id was derived from. */
  basis: "machine-id" | "hostname-fallback";
  /** False when the fallback (unstable) basis had to be used. */
  stable: boolean;
}

/**
 * Derive a stable, non-sensitive server id. The machine-id itself is only
 * used as hashing input; the persisted id is a truncated SHA-256 prefix.
 */
export function deriveServerId(identity: {
  machineId: string | null;
  hostname: string | null;
}): ServerIdDerivation {
  if (identity.machineId) {
    const hash = createHash("sha256").update(`machine-id:${identity.machineId}`).digest("hex");
    return {
      serverId: `srv-${hash.slice(0, 16)}`,
      basis: "machine-id",
      stable: true,
    };
  }
  const fallbackKey = `hostname:${identity.hostname ?? "unknown-host"}`;
  const hash = createHash("sha256").update(fallbackKey).digest("hex");
  return {
    serverId: `srv-${hash.slice(0, 16)}`,
    basis: "hostname-fallback",
    stable: false,
  };
}

export function newInventoryId(): string {
  return `inv-${randomUUID()}`;
}

export function inventoryPath(stateRoot: string, serverId: string): string {
  return path.join(resolveServerDir(stateRoot, serverId), "inventory.json");
}

/** Create the per-server directory layout (idempotent). */
export async function ensureServerLayout(stateRoot: string, serverId: string): Promise<void> {
  const dir = resolveServerDir(stateRoot, serverId);
  await mkdir(dir, { recursive: true });
  for (const sub of SERVER_DIR_LAYOUT) {
    await mkdir(path.join(dir, sub), { recursive: true });
  }
}

/**
 * Atomically persist a validated inventory:
 * validate -> mkdir layout -> write temp file -> rename over the target.
 */
export async function saveInventory(stateRoot: string, inventory: ServerInventory): Promise<string> {
  validateServerInventory(inventory);
  const target = inventoryPath(stateRoot, inventory.serverId);
  await ensureServerLayout(stateRoot, inventory.serverId);
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  const payload = `${JSON.stringify(inventory, null, 2)}\n`;
  try {
    await writeFile(tmp, payload, { encoding: "utf8", mode: 0o600 });
    await rename(tmp, target);
  } catch (err) {
    await cleanupQuiet(tmp);
    throw new StateError(`Failed to persist inventory for ${inventory.serverId}`, {
      cause: err,
    });
  }
  return target;
}

async function cleanupQuiet(tmp: string): Promise<void> {
  try {
    await unlink(tmp);
  } catch {
    // Best effort only: the tmp file is clearly marked with a .tmp- prefix
    // and is never a valid document name; failing to clean up must not mask
    // the original error.
  }
}

/** Read and validate a persisted inventory. */
export async function loadInventory(stateRoot: string, serverId: string): Promise<ServerInventory> {
  const file = inventoryPath(stateRoot, serverId);
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (err) {
    throw new StateError(`No readable inventory for ${serverId} at ${file}`, { cause: err });
  }
  return parseInventoryDocument(text);
}

/** Parse + schema-gate + validate raw inventory JSON text. */
export function parseInventoryDocument(text: string): ServerInventory {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new StateError("inventory.json is corrupt (invalid JSON)", { cause: err });
  }
  checkSchemaVersion(parsed);
  return validateServerInventory(parsed);
}

export interface InventoryListing {
  serverId: string;
  inventoryId: string | null;
  generatedAt: string | null;
  schemaVersion: number | null;
  hostname: string | null;
  state: "valid" | "corrupt" | "incompatible-schema" | "invalid";
  error: string | null;
}

/** List all persisted inventories with their health state. */
export async function listInventories(stateRoot: string): Promise<InventoryListing[]> {
  const root = path.resolve(stateRoot);
  let entries: string[];
  try {
    entries = await readdir(root);
  } catch {
    return [];
  }
  const listings: InventoryListing[] = [];
  for (const entry of entries) {
    if (!SERVER_ID_PATTERN.test(entry)) continue;
    const file = path.join(root, entry, "inventory.json");
    let text: string;
    try {
      text = await readFile(file, "utf8");
    } catch {
      continue;
    }
    listings.push({
      serverId: entry,
      ...summarizePersisted(text),
    });
  }
  listings.sort((a, b) => (b.generatedAt ?? "").localeCompare(a.generatedAt ?? ""));
  return listings;
}

function summarizePersisted(text: string): Omit<InventoryListing, "serverId"> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {
      inventoryId: null,
      generatedAt: null,
      schemaVersion: null,
      hostname: null,
      state: "corrupt",
      error: "invalid JSON",
    };
  }
  const doc = parsed as {
    schemaVersion?: unknown;
    inventoryId?: unknown;
    generatedAt?: unknown;
    identity?: { data?: { hostname?: unknown } };
  };
  const version =
    typeof doc.schemaVersion === "number" && Number.isInteger(doc.schemaVersion) ? doc.schemaVersion : null;
  if (version !== null && version !== SCHEMA_VERSION) {
    return {
      inventoryId: typeof doc.inventoryId === "string" ? doc.inventoryId : null,
      generatedAt: typeof doc.generatedAt === "string" ? doc.generatedAt : null,
      schemaVersion: version,
      hostname: null,
      state: "incompatible-schema",
      error: `schemaVersion ${version} is not supported (expected ${SCHEMA_VERSION})`,
    };
  }
  try {
    const inventory = validateServerInventory(parsed);
    return {
      inventoryId: inventory.inventoryId,
      generatedAt: inventory.generatedAt,
      schemaVersion: inventory.schemaVersion,
      hostname: inventory.identity.data?.hostname ?? null,
      state: "valid",
      error: null,
    };
  } catch (err) {
    return {
      inventoryId: typeof doc.inventoryId === "string" ? doc.inventoryId : null,
      generatedAt: typeof doc.generatedAt === "string" ? doc.generatedAt : null,
      schemaVersion: version,
      hostname: null,
      state: "invalid",
      error: err instanceof Error ? err.message : "validation failed",
    };
  }
}

/** Load the most recently generated valid inventory, if any. */
export async function readLatestInventory(
  stateRoot: string,
): Promise<{ serverId: string; inventory: ServerInventory } | null> {
  const listings = await listInventories(stateRoot); // newest first
  for (const listing of listings) {
    if (listing.state !== "valid") continue;
    try {
      const inventory = await loadInventory(stateRoot, listing.serverId);
      return { serverId: listing.serverId, inventory };
    } catch {
      // Race with a concurrent write: fall through to the next candidate.
    }
  }
  return null;
}

/** Validate every persisted inventory. Returns per-server results. */
export async function validateAllInventories(
  stateRoot: string,
): Promise<{ serverId: string; valid: boolean; error: string | null }[]> {
  const listings = await listInventories(stateRoot);
  return listings.map((l) => ({
    serverId: l.serverId,
    valid: l.state === "valid",
    error: l.error,
  }));
}

/**
 * Persistence of framework state under `state/<server-id>/`.
 *
 * Layout per server:
 *   state/<server-id>/
 *     inventory.json
 *     context.json
 *     plans/<plan-id>.json
 *     changes/  exceptions/  rollbacks/  verification/
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
import {
  type HardeningPlan,
  type OperationalContext,
  type PlanStatus,
  SCHEMA_VERSION,
  type ServerInventory,
} from "./models";
import {
  checkSchemaVersion,
  validateHardeningPlan,
  validateOperationalContext,
  validateServerInventory,
} from "./validation";

/** Server ids: lowercase alphanumerics and dashes, 4..64 chars, no dots. */
export const SERVER_ID_PATTERN = /^[a-z0-9][a-z0-9-]{3,63}$/;

/** Plan ids: "plan-" followed by lowercase alphanumerics/dashes. */
export const PLAN_ID_PATTERN = /^plan-[a-z0-9][a-z0-9-]{7,63}$/;

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

export function assertSafePlanId(planId: string): void {
  if (typeof planId !== "string" || !PLAN_ID_PATTERN.test(planId)) {
    throw new PathSafetyError(
      `Invalid plan id: ${JSON.stringify(planId)}. Expected pattern ${PLAN_ID_PATTERN.source}`,
    );
  }
  if (planId.includes("..")) {
    throw new PathSafetyError(`Invalid plan id: ${JSON.stringify(planId)} contains ".."`);
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
 * Atomically persist a validated document: write a temp file, then rename over
 * the target. Validation happens before any write.
 */
async function atomicWriteJson(target: string, document: unknown): Promise<void> {
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  const payload = `${JSON.stringify(document, null, 2)}\n`;
  try {
    await writeFile(tmp, payload, { encoding: "utf8", mode: 0o600 });
    await rename(tmp, target);
  } catch (err) {
    await cleanupQuiet(tmp);
    throw new StateError(`Failed to persist ${path.basename(target)}`, { cause: err });
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
  await atomicWriteJson(target, inventory);
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

// ---------------------------------------------------------------------------
// Operational context (Phase 2)
// ---------------------------------------------------------------------------

export function contextPath(stateRoot: string, serverId: string): string {
  return path.join(resolveServerDir(stateRoot, serverId), "context.json");
}

/** Atomically persist a validated operational context. */
export async function saveContext(stateRoot: string, context: OperationalContext): Promise<string> {
  validateOperationalContext(context);
  const target = contextPath(stateRoot, context.serverId);
  await ensureServerLayout(stateRoot, context.serverId);
  await atomicWriteJson(target, context);
  return target;
}

/** Read and validate a persisted context (throws when missing/corrupt). */
export async function loadContext(stateRoot: string, serverId: string): Promise<OperationalContext> {
  const file = contextPath(stateRoot, serverId);
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (err) {
    throw new StateError(`No readable context for ${serverId} at ${file}`, { cause: err });
  }
  return parseContextDocument(text);
}

/** Read a context, returning null when it does not exist yet. */
export async function readContext(stateRoot: string, serverId: string): Promise<OperationalContext | null> {
  const file = contextPath(stateRoot, serverId);
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (err) {
    if ((err as { code?: string }).code === "ENOENT") return null;
    throw new StateError(`context for ${serverId} is not readable`, { cause: err });
  }
  return parseContextDocument(text);
}

export function parseContextDocument(text: string): OperationalContext {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new StateError("context.json is corrupt (invalid JSON)", { cause: err });
  }
  checkSchemaVersion(parsed);
  return validateOperationalContext(parsed);
}

// ---------------------------------------------------------------------------
// Plans (Phase 2)
// ---------------------------------------------------------------------------

export function plansDir(stateRoot: string, serverId: string): string {
  return path.join(resolveServerDir(stateRoot, serverId), "plans");
}

export function planPath(stateRoot: string, serverId: string, planId: string): string {
  assertSafePlanId(planId);
  const dir = plansDir(stateRoot, serverId);
  const target = path.resolve(dir, `${planId}.json`);
  if (!target.startsWith(`${path.resolve(dir)}${path.sep}`)) {
    throw new PathSafetyError(`Resolved plan path ${target} escapes plans directory`);
  }
  return target;
}

/** Atomically persist a validated plan. */
export async function savePlan(stateRoot: string, plan: HardeningPlan): Promise<string> {
  validateHardeningPlan(plan);
  const target = planPath(stateRoot, plan.serverId, plan.planId);
  await ensureServerLayout(stateRoot, plan.serverId);
  await atomicWriteJson(target, plan);
  return target;
}

export async function loadPlan(stateRoot: string, serverId: string, planId: string): Promise<HardeningPlan> {
  const file = planPath(stateRoot, serverId, planId);
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (err) {
    throw new StateError(`No readable plan ${planId} for ${serverId}`, { cause: err });
  }
  return parsePlanDocument(text);
}

export function parsePlanDocument(text: string): HardeningPlan {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new StateError("plan document is corrupt (invalid JSON)", { cause: err });
  }
  checkSchemaVersion(parsed);
  return validateHardeningPlan(parsed);
}

export interface PlanListing {
  planId: string;
  generatedAt: string | null;
  status: PlanStatus | null;
  state: "valid" | "corrupt" | "incompatible-schema" | "invalid";
  error: string | null;
}

export async function listPlans(stateRoot: string, serverId: string): Promise<PlanListing[]> {
  let entries: string[];
  try {
    entries = await readdir(plansDir(stateRoot, serverId));
  } catch {
    return [];
  }
  const listings: PlanListing[] = [];
  for (const entry of entries) {
    if (!entry.endsWith(".json")) continue;
    const planId = entry.slice(0, -".json".length);
    if (!PLAN_ID_PATTERN.test(planId)) continue;
    let text: string;
    try {
      text = await readFile(path.join(plansDir(stateRoot, serverId), entry), "utf8");
    } catch {
      continue;
    }
    listings.push({ planId, ...summarizePlanText(text) });
  }
  listings.sort((a, b) => (b.generatedAt ?? "").localeCompare(a.generatedAt ?? ""));
  return listings;
}

function summarizePlanText(text: string): Omit<PlanListing, "planId"> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { generatedAt: null, status: null, state: "corrupt", error: "invalid JSON" };
  }
  const doc = parsed as { schemaVersion?: unknown; generatedAt?: unknown; status?: unknown };
  const version =
    typeof doc.schemaVersion === "number" && Number.isInteger(doc.schemaVersion) ? doc.schemaVersion : null;
  if (version !== null && version !== SCHEMA_VERSION) {
    return {
      generatedAt: typeof doc.generatedAt === "string" ? doc.generatedAt : null,
      status: null,
      state: "incompatible-schema",
      error: `schemaVersion ${version} is not supported (expected ${SCHEMA_VERSION})`,
    };
  }
  try {
    const plan = validateHardeningPlan(parsed);
    return { generatedAt: plan.generatedAt, status: plan.status, state: "valid", error: null };
  } catch (err) {
    return {
      generatedAt: typeof doc.generatedAt === "string" ? doc.generatedAt : null,
      status: null,
      state: "invalid",
      error: err instanceof Error ? err.message : "validation failed",
    };
  }
}

export async function readLatestPlan(stateRoot: string, serverId: string): Promise<HardeningPlan | null> {
  const listings = await listPlans(stateRoot, serverId); // newest first
  for (const listing of listings) {
    if (listing.state !== "valid") continue;
    try {
      return await loadPlan(stateRoot, serverId, listing.planId);
    } catch {
      // Race with a concurrent write: fall through.
    }
  }
  return null;
}

export async function validateAllPlans(
  stateRoot: string,
  serverId: string,
): Promise<{ planId: string; valid: boolean; error: string | null }[]> {
  const listings = await listPlans(stateRoot, serverId);
  return listings.map((l) => ({ planId: l.planId, valid: l.state === "valid", error: l.error }));
}

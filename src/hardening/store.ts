/**
 * Local agent state.
 *
 * Everything lives under `.server-hardener/` next to where OpenCode runs:
 *
 *   .server-hardener/
 *   ├── backups/            one JSON per backed-up file (content + hash + mode)
 *   ├── last-run.json       what was evaluated/applied/verified/rolled back
 *   └── optional-context.json   operator-supplied operational context
 *
 * There is no per-server tree, no server identity and no plan database.
 * Writes are atomic; identifiers are validated and never escape the root.
 */
import { randomUUID } from "node:crypto";
import { mkdir, readdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { PathSafetyError, StateError } from "./errors";
import type { BackupRecord, LastRun, LastRunEntry, OperationalContext } from "./models";
import { validateBackupRecord, validateLastRun, validateOperationalContext } from "./validation";

export const STORE_DIR = ".server-hardener";
export const LAST_RUN_FILE = "last-run.json";
export const CONTEXT_FILE = "optional-context.json";

const BACKUP_ID_PATTERN = /^bkp-[a-z0-9][a-z0-9-]{7,63}$/;
const VERIFICATION_ID_PATTERN = /^ver-[a-z0-9][a-z0-9-]{7,63}$/;

/** Default store root: `.server-hardener` in the current working directory. */
export function defaultStoreRoot(cwd: string = process.cwd()): string {
  return path.join(cwd, STORE_DIR);
}

export function assertSafeId(id: string, pattern: RegExp, label: string): void {
  if (typeof id !== "string" || !pattern.test(id) || id.includes("..") || id.includes("/")) {
    throw new PathSafetyError(`Invalid ${label}: ${JSON.stringify(id)}`);
  }
}

export function newBackupId(): string {
  return `bkp-${randomUUID()}`;
}

export function newVerificationId(): string {
  return `ver-${randomUUID()}`;
}

async function atomicWrite(target: string, document: unknown): Promise<void> {
  await mkdir(path.dirname(target), { recursive: true });
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  const payload = `${JSON.stringify(document, null, 2)}\n`;
  try {
    await writeFile(tmp, payload, { encoding: "utf8", mode: 0o600 });
    await rename(tmp, target);
  } catch (err) {
    try {
      await unlink(tmp);
    } catch {
      // best effort
    }
    throw new StateError(`cannot write ${target}`, { cause: err });
  }
}

export async function ensureStore(storeRoot: string): Promise<void> {
  await mkdir(path.join(storeRoot, "backups"), { recursive: true });
}

// --- Backups ---------------------------------------------------------------

function backupPath(storeRoot: string, backupId: string): string {
  assertSafeId(backupId, BACKUP_ID_PATTERN, "backup id");
  return path.join(storeRoot, "backups", `${backupId}.json`);
}

export async function saveBackup(storeRoot: string, backup: BackupRecord): Promise<string> {
  validateBackupRecord(backup);
  const target = backupPath(storeRoot, backup.backupId);
  await ensureStore(storeRoot);
  await atomicWrite(target, backup);
  return target;
}

export async function loadBackup(storeRoot: string, backupId: string): Promise<BackupRecord> {
  const file = backupPath(storeRoot, backupId);
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (err) {
    throw new StateError(`no readable backup ${backupId}`, { cause: err });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new StateError(`backup ${backupId} is corrupt`, { cause: err });
  }
  return validateBackupRecord(parsed);
}

export async function listBackups(storeRoot: string): Promise<BackupRecord[]> {
  let entries: string[];
  try {
    entries = await readdir(path.join(storeRoot, "backups"));
  } catch {
    return [];
  }
  const backups: BackupRecord[] = [];
  for (const entry of entries) {
    if (!entry.endsWith(".json")) continue;
    try {
      backups.push(await loadBackup(storeRoot, entry.slice(0, -".json".length)));
    } catch {
      // skip unreadable
    }
  }
  return backups;
}

// --- last-run --------------------------------------------------------------

export async function readLastRun(storeRoot: string): Promise<LastRun | null> {
  let text: string;
  try {
    text = await readFile(path.join(storeRoot, LAST_RUN_FILE), "utf8");
  } catch {
    return null;
  }
  try {
    return validateLastRun(JSON.parse(text));
  } catch (err) {
    throw new StateError("last-run.json is corrupt", { cause: err });
  }
}

/**
 * Append one entry to last-run.json (creating it if needed) and return the
 * updated summary.
 */
export async function appendLastRun(
  storeRoot: string,
  entry: LastRunEntry,
  context: { hostname: string | null; evaluated: number },
): Promise<LastRun> {
  const existing = await readLastRun(storeRoot);
  const run: LastRun = {
    updatedAt: entry.at,
    hostname: context.hostname,
    evaluated: context.evaluated,
    entries: [...(existing?.entries ?? []), entry],
  };
  validateLastRun(run);
  await ensureStore(storeRoot);
  await atomicWrite(path.join(storeRoot, LAST_RUN_FILE), run);
  return run;
}

export async function clearLastRun(storeRoot: string): Promise<void> {
  try {
    await unlink(path.join(storeRoot, LAST_RUN_FILE));
  } catch {
    // nothing to clear
  }
}

// --- optional operational context -----------------------------------------

export async function readContext(storeRoot: string): Promise<OperationalContext | null> {
  let text: string;
  try {
    text = await readFile(path.join(storeRoot, CONTEXT_FILE), "utf8");
  } catch (err) {
    if ((err as { code?: string }).code === "ENOENT") return null;
    throw new StateError("optional-context.json is not readable", { cause: err });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new StateError("optional-context.json is corrupt", { cause: err });
  }
  return validateOperationalContext(parsed);
}

export async function saveContext(storeRoot: string, context: OperationalContext): Promise<string> {
  validateOperationalContext(context);
  await ensureStore(storeRoot);
  const target = path.join(storeRoot, CONTEXT_FILE);
  await atomicWrite(target, context);
  return target;
}

export { VERIFICATION_ID_PATTERN };

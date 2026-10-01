/**
 * Minimal local state on the workstation: `.server-hardener/`.
 *
 *   .server-hardener/
 *   ├── session.json          the target selected for this session
 *   ├── last-run.json         applied / skipped / failed / rolled-back entries
 *   └── optional-context.json operator-supplied operational context
 *
 * Configuration backups live on the TARGET, not here. There is no per-server
 * tree, no fleet state and no plan database.
 */
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { PathSafetyError, StateError } from "./errors";
import type { LastRun, LastRunEntry, OperationalContext } from "./models";
import { validateLastRun, validateOperationalContext } from "./validation";

export const STORE_DIR = ".server-hardener";
export const LAST_RUN_FILE = "last-run.json";
export const CONTEXT_FILE = "optional-context.json";
export const SESSION_FILE = "session.json";

const ID_PATTERN = /^(bkp|ver)-[a-z0-9][a-z0-9-]{7,63}$/;

/** The target selected for the current session. */
export interface SessionInfo {
  target: string;
  connectedAt: string;
  hostname: string | null;
  root: boolean;
  sudo: boolean;
  isLocalhost: boolean;
}

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

export function newRunId(): string {
  return `run-${randomUUID()}`;
}

export { ID_PATTERN };

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
  await mkdir(storeRoot, { recursive: true });
}

// --- session ---------------------------------------------------------------

export async function readSession(storeRoot: string): Promise<SessionInfo | null> {
  let text: string;
  try {
    text = await readFile(path.join(storeRoot, SESSION_FILE), "utf8");
  } catch (err) {
    if ((err as { code?: string }).code === "ENOENT") return null;
    throw new StateError("session.json is not readable", { cause: err });
  }
  try {
    return JSON.parse(text) as SessionInfo;
  } catch (err) {
    throw new StateError("session.json is corrupt", { cause: err });
  }
}

export async function writeSession(storeRoot: string, session: SessionInfo): Promise<string> {
  const target = path.join(storeRoot, SESSION_FILE);
  await atomicWrite(target, session);
  return target;
}

export async function clearSession(storeRoot: string): Promise<void> {
  try {
    await unlink(path.join(storeRoot, SESSION_FILE));
  } catch {
    // nothing to clear
  }
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

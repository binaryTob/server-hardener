/**
 * Filesystem operations for remediation: read, atomic write, backup/restore.
 *
 * Backups are stored (content inline) under state/<server-id>/backups/ with a
 * hash, so rollback never depends on external artifacts. Writes are atomic and
 * never follow a computed path outside the intended file.
 */
import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { StateError } from "../errors";
import type { BackupRecord } from "../models";
import { loadBackup, newBackupId, saveBackup } from "../state";
import type { RemediationContext } from "./types";

export function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

export async function readTextOrNull(file: string): Promise<string | null> {
  try {
    return await readFile(file, "utf8");
  } catch (err) {
    if ((err as { code?: string }).code === "ENOENT") return null;
    throw new StateError(`cannot read ${file}`, { cause: err });
  }
}

export async function fileExists(file: string): Promise<boolean> {
  try {
    await readFile(file);
    return true;
  } catch {
    return false;
  }
}

export async function writeTextAtomic(file: string, content: string): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-hardener-${process.pid}-${Date.now()}`;
  try {
    await writeFile(tmp, content, { encoding: "utf8", mode: 0o644 });
    await rename(tmp, file);
  } catch (err) {
    try {
      await unlink(tmp);
    } catch {
      // best effort
    }
    throw new StateError(`cannot write ${file}`, { cause: err });
  }
}

export async function deleteFile(file: string): Promise<void> {
  try {
    await unlink(file);
  } catch (err) {
    if ((err as { code?: string }).code !== "ENOENT") throw err;
  }
}

export async function listDir(dir: string): Promise<string[]> {
  try {
    return await readdir(dir);
  } catch {
    return [];
  }
}

/** Read a file and persist a BackupRecord. The file must exist. */
export async function createBackup(
  ctx: Pick<RemediationContext, "stateRoot" | "serverId" | "control" | "now">,
  file: string,
): Promise<BackupRecord> {
  const content = await readFile(file, "utf8");
  const record: BackupRecord = {
    schemaVersion: 1,
    backupId: newBackupId(),
    serverId: ctx.serverId,
    controlId: ctx.control.controlId,
    originalPath: file,
    createdAt: ctx.now(),
    sha256: sha256Hex(content),
    bytes: Buffer.byteLength(content, "utf8"),
    content,
  };
  await saveBackup(ctx.stateRoot, record);
  return record;
}

/** Restore a previously created backup to its original path. */
export async function restoreBackup(stateRoot: string, serverId: string, backupId: string): Promise<string> {
  const backup = await loadBackup(stateRoot, serverId, backupId);
  await writeTextAtomic(backup.originalPath, backup.content);
  return backup.originalPath;
}

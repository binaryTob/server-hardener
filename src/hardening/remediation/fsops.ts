/**
 * Filesystem operations for remediation: read, atomic write, backup/restore.
 *
 * Backups are stored (content + hash + mode/uid/gid inline) under
 * `.server-hardener/backups/`, so rollback never depends on external artifacts.
 * Writes are atomic.
 */
import { createHash } from "node:crypto";
import { chmod, chown, mkdir, readdir, readFile, rename, stat, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { StateError } from "../errors";
import type { BackupRecord } from "../models";
import { loadBackup, newBackupId, saveBackup } from "../store";
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
    await stat(file);
    return true;
  } catch {
    return false;
  }
}

export async function writeTextAtomic(file: string, content: string, mode = 0o644): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-hardener-${process.pid}-${Date.now()}`;
  try {
    await writeFile(tmp, content, { encoding: "utf8", mode });
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

/** Read a file and persist a BackupRecord (content + hash + mode/uid/gid). */
export async function createBackup(
  ctx: Pick<RemediationContext, "storeRoot" | "control" | "now">,
  file: string,
): Promise<BackupRecord> {
  const [content, info] = await Promise.all([readFile(file, "utf8"), stat(file)]);
  const record: BackupRecord = {
    backupId: newBackupId(),
    controlId: ctx.control.controlId,
    originalPath: file,
    createdAt: ctx.now(),
    sha256: sha256Hex(content),
    bytes: Buffer.byteLength(content, "utf8"),
    mode: info.mode & 0o777,
    uid: info.uid,
    gid: info.gid,
    content,
  };
  await saveBackup(ctx.storeRoot, record);
  return record;
}

/** Restore a backup to its original path, preserving owner and mode. */
export async function restoreBackup(storeRoot: string, backupId: string): Promise<string> {
  const backup = await loadBackup(storeRoot, backupId);
  await writeTextAtomic(backup.originalPath, backup.content, backup.mode ?? 0o644);
  try {
    if (backup.mode !== null) await chmod(backup.originalPath, backup.mode);
    if (backup.uid !== null && backup.gid !== null) await chown(backup.originalPath, backup.uid, backup.gid);
  } catch {
    // chown usually needs root; best effort.
  }
  return backup.originalPath;
}

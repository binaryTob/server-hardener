/**
 * Controlled filesystem access for read-only discovery.
 *
 * Discovery reads well-known system files only. It never writes, never walks
 * arbitrary trees, and never reads user file contents. Access failures are
 * normalized (missing / permission-denied) instead of thrown, so a single
 * unreadable file degrades only the section that needs it.
 */
import { constants } from "node:fs";
import { access, readdir, readFile, readlink } from "node:fs/promises";

export type ReadFailureStatus = "unavailable" | "insufficient-permissions";

export type FileRead = { ok: true; content: string } | { ok: false; status: ReadFailureStatus };

export type DirRead = { ok: true; names: string[] } | { ok: false; status: ReadFailureStatus };

export interface FileReader {
  readText(path: string): Promise<FileRead>;
  /** Resolve a symlink target (used for /proc/<pid>/exe). */
  readlink(path: string): Promise<FileRead>;
  exists(path: string): Promise<boolean>;
  readDir(path: string): Promise<DirRead>;
}

export class NodeFileReader implements FileReader {
  async readText(path: string): Promise<FileRead> {
    try {
      const content = await readFile(path, "utf8");
      return { ok: true, content };
    } catch (err) {
      return { ok: false, status: classifyReadError(err) };
    }
  }

  async readlink(path: string): Promise<FileRead> {
    try {
      const content = await readlink(path, "utf8");
      return { ok: true, content };
    } catch (err) {
      return { ok: false, status: classifyReadError(err) };
    }
  }

  async exists(path: string): Promise<boolean> {
    try {
      await accessFile(path);
      return true;
    } catch {
      return false;
    }
  }

  async readDir(path: string): Promise<DirRead> {
    try {
      const names = await readdir(path);
      return { ok: true, names };
    } catch (err) {
      return { ok: false, status: classifyReadError(err) };
    }
  }
}

async function accessFile(path: string): Promise<void> {
  await access(path, constants.F_OK);
}

function classifyReadError(err: unknown): ReadFailureStatus {
  const code = (err as { code?: string }).code;
  if (code === "EACCES" || code === "EPERM") return "insufficient-permissions";
  return "unavailable";
}

const COMMON_BIN_DIRS = [
  "/usr/bin",
  "/usr/sbin",
  "/usr/local/bin",
  "/usr/local/sbin",
  "/bin",
  "/sbin",
  "/snap/bin",
];

/**
 * Detect whether a binary exists by checking PATH and common tool directories.
 * Pure existence check: no execution, no shell, no package queries.
 */
export async function detectBinary(files: FileReader, name: string): Promise<string | null> {
  const dirs = new Set<string>(COMMON_BIN_DIRS);
  const pathEnv = process.env.PATH ?? "";
  for (const dir of pathEnv.split(":")) {
    if (dir) dirs.add(dir);
  }
  for (const dir of dirs) {
    const candidate = `${dir}/${name}`;
    if (await files.exists(candidate)) return candidate;
  }
  return null;
}

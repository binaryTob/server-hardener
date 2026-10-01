/**
 * LocalHost: runs operations on the operator's own machine.
 *
 * Used for tests and for explicitly hardening localhost. It is NEVER selected
 * implicitly: a target must name `localhost` for this to be used.
 */
import {
  access,
  chmod,
  chown,
  mkdir,
  readdir,
  readFile,
  readlink,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { type CommandOutcome, ExecCommandRunner } from "../exec";
import type { DirRead, FileRead } from "../fsio";
import type { Host, HostExecOptions, HostFileStat } from "./host";
import type { TargetSpec } from "./target";

export class LocalHost implements Host {
  readonly kind = "local" as const;
  readonly platformHint = process.platform;
  readonly isLocalhost = true;
  readonly label: string;
  private readonly runner: ExecCommandRunner;

  constructor(spec: TargetSpec, options: { timeoutMs?: number } = {}) {
    this.label = spec.user ? `${spec.user}@localhost` : "localhost";
    this.runner = new ExecCommandRunner(options);
  }

  run(command: string, args: string[]): Promise<CommandOutcome> {
    return this.runner.run(command, args);
  }

  exec(command: string, args: string[], _options: HostExecOptions = {}): Promise<CommandOutcome> {
    return this.runner.run(command, args);
  }

  runPrivileged(command: string, args: string[]): Promise<CommandOutcome> {
    return this.runner.run(command, args);
  }

  async isRoot(): Promise<boolean> {
    return typeof process.getuid === "function" && process.getuid() === 0;
  }

  async sudoAvailable(): Promise<boolean> {
    return this.isRoot();
  }

  async verifyConnection(): Promise<CommandOutcome> {
    return this.runner.run("true", []);
  }

  async homeDir(): Promise<string | null> {
    return homedir() || null;
  }

  // --- FileReader ----------------------------------------------------------

  async readText(file: string): Promise<FileRead> {
    try {
      return { ok: true, content: await readFile(file, "utf8") };
    } catch (err) {
      return { ok: false, status: classify(err) };
    }
  }

  readTextPrivileged(file: string): Promise<FileRead> {
    return this.readText(file);
  }

  async readlink(file: string): Promise<FileRead> {
    try {
      return { ok: true, content: await readlink(file, "utf8") };
    } catch (err) {
      return { ok: false, status: classify(err) };
    }
  }

  async exists(file: string): Promise<boolean> {
    try {
      await access(file);
      return true;
    } catch {
      return false;
    }
  }

  async readDir(dir: string): Promise<DirRead> {
    try {
      return { ok: true, names: await readdir(dir) };
    } catch (err) {
      return { ok: false, status: classify(err) };
    }
  }

  // --- Write / metadata ----------------------------------------------------

  async writeText(file: string, content: string, mode = 0o644): Promise<void> {
    await mkdir(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp-hardener-${process.pid}-${Date.now()}`;
    await writeFile(tmp, content, { encoding: "utf8", mode });
    await rename(tmp, file);
  }

  writeTextPrivileged(file: string, content: string, mode?: number): Promise<void> {
    return this.writeText(file, content, mode);
  }

  async stat(file: string): Promise<HostFileStat | null> {
    try {
      const info = await stat(file);
      return { mode: info.mode & 0o777, uid: info.uid, gid: info.gid };
    } catch {
      return null;
    }
  }

  async chmod(file: string, mode: number): Promise<void> {
    await chmod(file, mode);
  }

  async chown(file: string, uid: number, gid: number): Promise<void> {
    await chown(file, uid, gid);
  }

  async mkdirpPrivileged(dir: string): Promise<void> {
    await mkdir(dir, { recursive: true });
  }

  async removePrivileged(file: string): Promise<void> {
    try {
      await unlink(file);
    } catch {
      // best effort
    }
  }
}

function classify(err: unknown): "unavailable" | "insufficient-permissions" {
  const code = (err as { code?: string }).code;
  return code === "EACCES" || code === "EPERM" ? "insufficient-permissions" : "unavailable";
}

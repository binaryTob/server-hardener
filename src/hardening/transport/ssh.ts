/**
 * SshHost: runs operations on a remote target over SSH.
 *
 * Security model:
 * - `ssh` is spawned with an argv array, never through a shell. The remote
 *   argument list is quoted (`buildRemoteCommand`) because OpenSSH hands the
 *   command to the target's login shell.
 * - BatchMode is enabled so we never prompt for a password, and no credential
 *   is ever read or stored. `~/.ssh/config`, ssh-agent, IdentityFile,
 *   ProxyJump and known_hosts are honoured by using the user's own ssh.
 * - Privileged operations use `sudo -n` (non-interactive); if sudo would prompt,
 *   the operation fails and the operator is told.
 */
import { type ChildProcessWithoutNullStreams, spawn as nodeSpawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { TransportError } from "../errors";
import { assertSafeCommand, type CommandOutcome, type CommandStatus } from "../exec";
import type { DirRead, FileRead } from "../fsio";
import type { Host, HostExecOptions, HostFileStat } from "./host";
import { buildRemoteCommand } from "./quote";
import { sshDestination, type TargetSpec } from "./target";

export type SshFailureKind = "host-key" | "auth" | "connection" | "timeout" | "error";

export interface SshHostOptions {
  sshBinary?: string;
  timeoutMs?: number;
  spawn?: typeof nodeSpawn;
  /** Reuse one connection (ControlMaster). Default true; avoids rate limiting. */
  multiplex?: boolean;
  /** Override the ssh ControlPath; "disabled" forces a fresh connection. */
  controlPath?: string;
}

const DEFAULT_TIMEOUT_MS = 30_000;

export function classifySshFailure(stderr: string, killed: boolean): SshFailureKind {
  if (killed) return "timeout";
  const text = stderr.toLowerCase();
  if (
    text.includes("host key verification failed") ||
    text.includes("remote host identification has changed")
  ) {
    return "host-key";
  }
  if (
    text.includes("permission denied (publickey") ||
    text.includes("permission denied (password") ||
    text.includes("authentication failed") ||
    text.includes("no supported authentication") ||
    text.includes("too many authentication failures")
  ) {
    return "auth";
  }
  if (
    text.includes("could not resolve hostname") ||
    text.includes("connection refused") ||
    text.includes("connection timed out") ||
    text.includes("connection reset") ||
    text.includes("no route to host") ||
    text.includes("network is unreachable") ||
    text.includes("operation timed out") ||
    text.includes("kex_exchange_identification")
  ) {
    return "connection";
  }
  return "error";
}

/**
 * Classify the result of a remote COMMAND (not the ssh transport). A missing
 * binary or a denied file must degrade to `unavailable` /
 * `insufficient-permissions`, exactly like the local runner, so parsers behave
 * the same over SSH.
 */
export function classifyRemoteResult(
  exitCode: number | null,
  stderr: string,
): { status: CommandStatus; failureKind?: SshFailureKind } {
  const kind = classifySshFailure(stderr, false);
  if (kind !== "error") return { status: "error", failureKind: kind };
  if (exitCode === 127 || /command not found/i.test(stderr)) return { status: "unavailable" };
  if (exitCode === 126 || /permission denied/i.test(stderr)) return { status: "insufficient-permissions" };
  return { status: "error" };
}

export function sshBaseArgs(): string[] {
  return ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "NumberOfPasswordPrompts=0"];
}

/**
 * Build the local `ssh` argv for a fixed remote command. `ssh` is spawned with
 * this array; no local shell is involved, and the remote command is quoted.
 *
 * `controlPath`:
 *  - a path  -> reuse one multiplexed connection (ControlMaster);
 *  - "disabled" -> force a brand-new connection (used for reconnect checks);
 *  - null     -> no multiplexing options added.
 */
export function buildSshArgv(
  destination: string,
  remoteArgv: string[],
  sudo: boolean,
  port: number | null = null,
  controlPath: string | "disabled" | null = null,
): string[] {
  const base = buildRemoteCommand(remoteArgv);
  const remote = sudo ? `sudo -n ${base}` : base;
  const portArgs = port === null ? [] : ["-p", String(port)];
  const controlArgs =
    controlPath === null
      ? []
      : controlPath === "disabled"
        ? ["-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no"]
        : ["-o", "ControlMaster=auto", "-o", `ControlPath=${controlPath}`, "-o", "ControlPersist=60"];
  return [...sshBaseArgs(), ...controlArgs, ...portArgs, destination, "--", remote];
}

export class SshHost implements Host {
  readonly kind = "ssh" as const;
  readonly platformHint = "linux";
  readonly isLocalhost = false;
  readonly label: string;
  private readonly destination: string;
  private readonly port: number | null;
  private readonly controlPath: string | null;
  private controlDirReady = false;
  private rootKnown: boolean | null = null;
  private readonly sshBinary: string;
  private readonly timeoutMs: number;
  private readonly spawn: typeof nodeSpawn;

  constructor(spec: TargetSpec, options: SshHostOptions = {}) {
    this.destination = sshDestination(spec);
    this.port = spec.port;
    this.label = this.destination;
    this.controlPath =
      options.controlPath !== undefined
        ? options.controlPath === "disabled"
          ? null
          : options.controlPath
        : options.multiplex === false
          ? null
          : path.join(homedir(), ".ssh", "server-hardener-%r@%h:%p");
    this.sshBinary = options.sshBinary ?? "ssh";
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.spawn = options.spawn ?? nodeSpawn;
  }

  private async ensureControlDir(): Promise<void> {
    if (this.controlDirReady || this.controlPath === null) return;
    try {
      await mkdir(path.join(homedir(), ".ssh"), { recursive: true });
    } catch {
      // If we cannot prepare the control dir, fall back to fresh connections.
    }
    this.controlDirReady = true;
  }

  async exec(command: string, args: string[], options: HostExecOptions = {}): Promise<CommandOutcome> {
    assertSafeCommand(command, args);
    const controlPath: string | "disabled" | null = options.fresh === true ? "disabled" : this.controlPath;
    if (controlPath !== null && controlPath !== "disabled") await this.ensureControlDir();
    const sshArgs = buildSshArgv(
      this.destination,
      [command, ...args],
      options.sudo === true,
      this.port,
      controlPath,
    );
    return this.spawnSsh(sshArgs, options.stdin, options.timeoutMs ?? this.timeoutMs);
  }

  run(command: string, args: string[]): Promise<CommandOutcome> {
    return this.exec(command, args);
  }

  /** True when the remote login user is already root (no sudo needed). */
  private async isRootUser(): Promise<boolean> {
    if (this.rootKnown === null) {
      const outcome = await this.exec("id", ["-u"]);
      this.rootKnown = outcome.status === "ok" && outcome.stdout.trim() === "0";
    }
    return this.rootKnown;
  }

  /** Whether privileged operations should be prefixed with `sudo -n`. */
  private async useSudo(): Promise<boolean> {
    return !(await this.isRootUser());
  }

  async runPrivileged(command: string, args: string[]): Promise<CommandOutcome> {
    return this.exec(command, args, { sudo: await this.useSudo() });
  }

  private spawnSsh(sshArgs: string[], stdin: string | undefined, timeoutMs: number): Promise<CommandOutcome> {
    return new Promise((resolve) => {
      let child: ChildProcessWithoutNullStreams;
      try {
        child = this.spawn(this.sshBinary, sshArgs, { stdio: ["pipe", "pipe", "pipe"] });
      } catch (err) {
        resolve({ status: "unavailable", stdout: "", stderr: describe(err), exitCode: null, notRun: true });
        return;
      }
      let stdout = "";
      let stderr = "";
      let killed = false;
      const timer = setTimeout(() => {
        killed = true;
        child.kill("SIGKILL");
      }, timeoutMs);
      child.stdout.on("data", (chunk: Buffer) => {
        stdout += chunk.toString("utf8");
      });
      child.stderr.on("data", (chunk: Buffer) => {
        stderr += chunk.toString("utf8");
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        resolve({
          status: "unavailable",
          stdout,
          stderr: `${stderr}${describe(err)}`,
          exitCode: null,
          notRun: true,
          failureKind: "connection",
        });
      });
      child.on("close", (code, signal) => {
        clearTimeout(timer);
        const exitCode = typeof code === "number" ? code : null;
        if (killed || signal === "SIGKILL") {
          resolve({ status: "timeout", stdout, stderr, exitCode, notRun: false, failureKind: "timeout" });
          return;
        }
        if (exitCode === 0) {
          resolve({ status: "ok", stdout, stderr, exitCode, notRun: false });
          return;
        }
        const classified = classifyRemoteResult(exitCode, stderr);
        const outcome: CommandOutcome = {
          status: classified.status,
          stdout,
          stderr,
          exitCode,
          notRun: false,
        };
        if (classified.failureKind !== undefined) outcome.failureKind = classified.failureKind;
        resolve(outcome);
      });
      if (stdin !== undefined) child.stdin.write(stdin);
      child.stdin.end();
    });
  }

  // --- FileReader ----------------------------------------------------------

  async readText(file: string): Promise<FileRead> {
    const outcome = await this.exec("cat", ["--", file]);
    if (outcome.status === "ok") return { ok: true, content: outcome.stdout };
    return { ok: false, status: readFailure(outcome) };
  }

  async readTextPrivileged(file: string): Promise<FileRead> {
    return this.readTextWith(file, await this.useSudo());
  }

  private async readTextWith(file: string, sudo: boolean): Promise<FileRead> {
    const outcome = await this.exec("cat", ["--", file], { sudo });
    if (outcome.status === "ok") return { ok: true, content: outcome.stdout };
    return { ok: false, status: readFailure(outcome) };
  }

  async readlink(file: string): Promise<FileRead> {
    const outcome = await this.exec("readlink", ["--", file]);
    if (outcome.status === "ok") return { ok: true, content: outcome.stdout.trim() };
    return { ok: false, status: readFailure(outcome) };
  }

  async exists(file: string): Promise<boolean> {
    const outcome = await this.exec("test", ["-e", file]);
    return outcome.status === "ok" || outcome.exitCode === 0;
  }

  async readDir(dir: string): Promise<DirRead> {
    const outcome = await this.exec("ls", ["-1", "--", dir]);
    if (outcome.status !== "ok") return { ok: false, status: readFailure(outcome) };
    return {
      ok: true,
      names: outcome.stdout
        .split("\n")
        .map((name) => name.trim())
        .filter((name) => name.length > 0),
    };
  }

  // --- Write / metadata ----------------------------------------------------

  async writeText(file: string, content: string, mode = 0o644): Promise<void> {
    await this.writeTextWith(file, content, mode, false);
  }

  async writeTextPrivileged(file: string, content: string, mode?: number): Promise<void> {
    return this.writeTextWith(file, content, mode ?? 0o644, await this.useSudo());
  }

  private async writeTextWith(file: string, content: string, mode: number, sudo: boolean): Promise<void> {
    const outcome = await this.exec("tee", ["--", file], { stdin: content, sudo });
    if (outcome.status !== "ok") {
      throw new TransportError(
        `failed to write ${file} on ${this.label}: ${outcome.stderr.trim() || outcome.status}`,
      );
    }
    await this.exec("chmod", [mode.toString(8), "--", file], { sudo });
  }

  async stat(file: string): Promise<HostFileStat | null> {
    const outcome = await this.exec("stat", ["-c", "%a %u %g", "--", file]);
    if (outcome.status !== "ok") return null;
    const [modeText, uidText, gidText] = outcome.stdout.trim().split(/\s+/);
    const mode = modeText ? Number.parseInt(modeText, 8) : Number.NaN;
    const uid = uidText ? Number.parseInt(uidText, 10) : Number.NaN;
    const gid = gidText ? Number.parseInt(gidText, 10) : Number.NaN;
    if (Number.isNaN(mode) || Number.isNaN(uid) || Number.isNaN(gid)) return null;
    return { mode, uid, gid };
  }

  async chmod(file: string, mode: number): Promise<void> {
    await this.exec("chmod", [mode.toString(8), "--", file], { sudo: await this.useSudo() });
  }

  async chown(file: string, uid: number, gid: number): Promise<void> {
    await this.exec("chown", [`${uid}:${gid}`, "--", file], { sudo: await this.useSudo() });
  }

  async mkdirpPrivileged(dir: string): Promise<void> {
    await this.exec("mkdir", ["-p", "--", dir], { sudo: await this.useSudo() });
  }

  async removePrivileged(file: string): Promise<void> {
    await this.exec("rm", ["-f", "--", file], { sudo: await this.useSudo() });
  }

  // --- Probe ---------------------------------------------------------------

  async isRoot(): Promise<boolean> {
    return this.isRootUser();
  }

  async sudoAvailable(): Promise<boolean> {
    const outcome = await this.exec("sudo", ["-n", "true"]);
    return outcome.status === "ok";
  }

  async verifyConnection(): Promise<CommandOutcome> {
    // A NEW connection: ignore any multiplexed master.
    return this.exec("true", [], { fresh: true });
  }

  async homeDir(): Promise<string | null> {
    const outcome = await this.exec("printenv", ["HOME"]);
    const home = outcome.status === "ok" ? outcome.stdout.trim() : "";
    return home.length > 0 ? home : null;
  }
}

function readFailure(outcome: CommandOutcome): "unavailable" | "insufficient-permissions" {
  const text = outcome.stderr.toLowerCase();
  if (outcome.status === "insufficient-permissions" || text.includes("permission denied")) {
    return "insufficient-permissions";
  }
  return "unavailable";
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

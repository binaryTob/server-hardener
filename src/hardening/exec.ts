/**
 * Controlled command execution for read-only discovery.
 *
 * Security model:
 * - Commands are NEVER free-form strings provided by an agent or user. Each
 *   collector hardcodes its own argv in code; `CommandRunner` only receives
 *   already-known (command, args) pairs.
 * - Command names must be bare executables resolved through PATH: no paths,
 *   no whitespace, no shell metacharacters. Args are passed as an argv array
 *   to `execFile` with `shell: false`, so no shell is ever involved.
 * - Every run has a timeout and an output size limit, and its outcome is
 *   normalized so parsers never see exceptions.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { CommandSafetyError } from "./errors";

const execFileAsync = promisify(execFile);

export type CommandStatus = "ok" | "unavailable" | "insufficient-permissions" | "timeout" | "error";

export interface CommandOutcome {
  status: CommandStatus;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  /** True when the command never ran (missing binary / denied). */
  notRun: boolean;
}

export interface CommandRunner {
  /**
   * Run a fixed command with fixed args. Implementations must never use a
   * shell and must never accept a user-provided command string.
   */
  run(command: string, args: string[]): Promise<CommandOutcome>;
}

/** Bare executable name only: letters, digits, dot, dash, underscore. */
export const COMMAND_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;

const MAX_STDERR_DETAIL = 500;

export function assertSafeCommand(command: string, args: string[]): void {
  if (typeof command !== "string" || !COMMAND_NAME_PATTERN.test(command)) {
    throw new CommandSafetyError(
      `Rejected unsafe command name: ${JSON.stringify(command)}. Only bare executable names are allowed.`,
    );
  }
  if (!Array.isArray(args)) {
    throw new CommandSafetyError("Command args must be an argv array, not a string.");
  }
  for (const arg of args) {
    if (typeof arg !== "string") {
      throw new CommandSafetyError("Command args must all be strings.");
    }
    if (arg.includes("\0")) {
      throw new CommandSafetyError("Rejected command arg containing a NUL byte.");
    }
  }
}

export interface ExecCommandRunnerOptions {
  timeoutMs?: number;
  maxOutputBytes?: number;
}

export class ExecCommandRunner implements CommandRunner {
  private readonly timeoutMs: number;
  private readonly maxOutputBytes: number;

  constructor(options: ExecCommandRunnerOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.maxOutputBytes = options.maxOutputBytes ?? 8 * 1024 * 1024;
  }

  async run(command: string, args: string[]): Promise<CommandOutcome> {
    assertSafeCommand(command, args);
    try {
      const { stdout, stderr } = await execFileAsync(command, args, {
        timeout: this.timeoutMs,
        maxBuffer: this.maxOutputBytes,
        encoding: "utf8",
        shell: false,
        windowsHide: true,
      });
      return { status: "ok", stdout: stdout ?? "", stderr: stderr ?? "", exitCode: 0, notRun: false };
    } catch (err) {
      return normalizeError(err);
    }
  }
}

function normalizeError(err: unknown): CommandOutcome {
  const e = err as {
    code?: number | string;
    killed?: boolean;
    signal?: string;
    stdout?: string | { toString(): string };
    stderr?: string | { toString(): string };
  };
  const stdout = toText(e.stdout);
  const stderr = toText(e.stderr);
  const exitCode = typeof e.code === "number" ? e.code : null;

  if (e.code === "ENOENT") {
    return { status: "unavailable", stdout, stderr, exitCode: null, notRun: true };
  }
  if (e.code === "EACCES" || e.code === "EPERM") {
    return {
      status: "insufficient-permissions",
      stdout,
      stderr,
      exitCode,
      notRun: true,
    };
  }
  if (exitCode === 126) {
    return { status: "insufficient-permissions", stdout, stderr, exitCode, notRun: true };
  }
  if (exitCode === 127) {
    return { status: "unavailable", stdout, stderr, exitCode, notRun: true };
  }
  if (e.killed || e.signal) {
    return { status: "timeout", stdout, stderr, exitCode, notRun: false };
  }
  return { status: "error", stdout, stderr, exitCode, notRun: false };
}

function toText(value: string | { toString(): string } | undefined | null): string {
  if (value === undefined || value === null) return "";
  const text = typeof value === "string" ? value : value.toString();
  return text.length > MAX_STDERR_DETAIL ? text.slice(0, MAX_STDERR_DETAIL) : text;
}

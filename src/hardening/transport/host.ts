/**
 * Host abstraction: where operations run.
 *
 * `Host` implements both `CommandRunner` (discovery) and `FileReader`
 * (discovery file access), plus the privileged/file-write operations the
 * remediation engine needs. Implementations: `SshHost` (default, remote target)
 * and `LocalHost` (tests / explicit opt-in).
 *
 * Nothing here accepts a command string from the model: operations are fixed
 * argvs from the collectors and remediations.
 */
import type { CommandOutcome, CommandRunner } from "../exec";
import type { FileRead, FileReader } from "../fsio";
import { LocalHost } from "./local";
import { SshHost } from "./ssh";
import type { TargetSpec } from "./target";

export interface HostFileStat {
  mode: number;
  uid: number;
  gid: number;
}

export interface HostExecOptions {
  sudo?: boolean;
  stdin?: string;
  timeoutMs?: number;
  /** Force a brand-new connection (no multiplexing). Used for reconnect checks. */
  fresh?: boolean;
}

export interface Host extends CommandRunner, FileReader {
  /** Human label used in output, e.g. "admin@server.example". */
  readonly label: string;
  readonly kind: "ssh" | "local";
  /** Platform hint for discovery (ssh targets are assumed Linux). */
  readonly platformHint: string;
  readonly isLocalhost: boolean;

  exec(command: string, args: string[], options?: HostExecOptions): Promise<CommandOutcome>;
  /** Run with privilege escalation when available (sudo -n on ssh targets). */
  runPrivileged(command: string, args: string[]): Promise<CommandOutcome>;

  readTextPrivileged(path: string): Promise<FileRead>;
  writeText(path: string, content: string, mode?: number): Promise<void>;
  writeTextPrivileged(path: string, content: string, mode?: number): Promise<void>;
  stat(path: string): Promise<HostFileStat | null>;
  chmod(path: string, mode: number): Promise<void>;
  chown(path: string, uid: number, gid: number): Promise<void>;
  mkdirpPrivileged(path: string): Promise<void>;
  removePrivileged(path: string): Promise<void>;

  isRoot(): Promise<boolean>;
  sudoAvailable(): Promise<boolean>;
  /** Open a NEW connection to the target and report whether it works. */
  verifyConnection(): Promise<CommandOutcome>;
  homeDir(): Promise<string | null>;
}

/** Result of probing a target after connecting. */
export interface HostProbe {
  label: string;
  root: boolean;
  sudo: boolean;
  home: string | null;
}

export interface HostFactoryOptions {
  sshBinary?: string;
  timeoutMs?: number;
}

/**
 * Build a Host for a target. Remote (SSH) is the normal path; `localhost` is
 * only used when the target is explicitly a local alias/address.
 */
export function createHost(spec: TargetSpec, options: HostFactoryOptions = {}): Host {
  if (spec.isLocalhost) return new LocalHost(spec);
  const sshOptions: HostFactoryOptions = {};
  if (options.sshBinary !== undefined) sshOptions.sshBinary = options.sshBinary;
  if (options.timeoutMs !== undefined) sshOptions.timeoutMs = options.timeoutMs;
  return new SshHost(spec, sshOptions);
}

export async function probeHost(host: Host): Promise<HostProbe> {
  const [rootOutcome, sudoOutcome, homeOutcome] = await Promise.all([
    host.isRoot(),
    host.sudoAvailable(),
    host.homeDir(),
  ]);
  return { label: host.label, root: rootOutcome, sudo: sudoOutcome, home: homeOutcome };
}

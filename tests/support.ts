/**
 * Shared test support: sample inventory/context, catalog lookup and an
 * in-memory FakeHost that implements the Host contract (no real host, no SSH).
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { getControl } from "../src/hardening/controls/catalog";
import type { ControlDefinition } from "../src/hardening/controls/types";
import type { CommandOutcome } from "../src/hardening/exec";
import type { DirRead, FileRead } from "../src/hardening/fsio";
import { runDiscovery } from "../src/hardening/inventory";
import type {
  EvaluatedControl,
  OperationalContext,
  ServerInventory,
  ServerRole,
} from "../src/hardening/models";
import { emptyContext } from "../src/hardening/planning/context";
import { evaluateControl } from "../src/hardening/planning/evaluate";
import type { Host, HostExecOptions, HostFileStat } from "../src/hardening/transport/host";
import { successfulScenario } from "./helpers";

export const NOW = "2025-03-04T05:06:07.000Z";

export function clone<T>(value: T): T {
  return structuredClone(value);
}

export async function sampleInventory(): Promise<ServerInventory> {
  const { runner, files } = successfulScenario();
  return runDiscovery({ runner, files, now: () => NOW, platform: "linux" });
}

export function mustControl(controlId: string): ControlDefinition {
  const control = getControl(controlId);
  if (!control) throw new Error(`control ${controlId} not found in catalog`);
  return control;
}

export function evaluate(
  controlId: string,
  inventory: ServerInventory,
  context: OperationalContext,
): EvaluatedControl {
  return evaluateControl(mustControl(controlId), inventory, context);
}

export interface SampleContextOptions {
  environment?: OperationalContext["environment"];
  internetExposure?: OperationalContext["internetExposure"];
  secondaryPathConfirmed?: boolean | null;
  consoleAccess?: boolean | null;
  confirmedRoles?: ServerRole[];
}

export function sampleContext(options: SampleContextOptions = {}): OperationalContext {
  const base = emptyContext(NOW);
  return {
    ...base,
    environment: options.environment ?? "production",
    criticality: "high",
    internetExposure: options.internetExposure ?? "none",
    roles: (options.confirmedRoles ?? ["generic-server"]).map((role) => ({
      role,
      confidence: "confirmed" as const,
      source: "test",
    })),
    management: {
      methods: ["ssh"],
      secondaryPathConfirmed:
        options.secondaryPathConfirmed === undefined ? true : options.secondaryPathConfirmed,
      consoleAccess: options.consoleAccess === undefined ? true : options.consoleAccess,
    },
    networks: { administrative: ["10.0.0.0/8"], service: ["10.0.0.0/8"] },
    reboot: { allowed: true, maintenanceWindowAvailable: true },
    highAvailability: false,
    operatorNotes: null,
  };
}

export function withoutAdministrativeUsers(inventory: ServerInventory): ServerInventory {
  const copy = clone(inventory);
  if (copy.users.data) {
    copy.users.data.users = copy.users.data.users.map((user) =>
      user.uid === 0 ? user : { ...user, supplementaryGroups: [], primaryGroup: "users" },
    );
    copy.users.data.groups = copy.users.data.groups.map((group) => ({ ...group, members: [] }));
  }
  if (copy.privilegedAccess.data) copy.privilegedAccess.data.administrativeGroups = [];
  return copy;
}

export function withUnknownLockState(inventory: ServerInventory): ServerInventory {
  const copy = clone(inventory);
  if (copy.users.data) {
    copy.users.data.users = copy.users.data.users.map((user) => ({
      ...user,
      locked: { value: null, confidence: "unknown" as const, source: "/etc/shadow", collectedAt: NOW },
    }));
  }
  return copy;
}

// --- In-memory target host -------------------------------------------------

const SSHD_DEFAULTS: Record<string, string> = {
  permitrootlogin: "yes",
  passwordauthentication: "yes",
  permitemptypasswords: "no",
  x11forwarding: "yes",
  maxauthtries: "6",
};

function ok(stdout: string): CommandOutcome {
  return { status: "ok", stdout, stderr: "", exitCode: 0, notRun: false };
}
function unavailable(): CommandOutcome {
  return { status: "unavailable", stdout: "", stderr: "not found", exitCode: null, notRun: true };
}

interface ServiceState {
  enabled: boolean;
  active: boolean;
}

interface FileMeta {
  mode: number;
  uid: number;
  gid: number;
}

/** A fake remote target: in-memory files, sysctl values and systemd units. */
export class FakeHost implements Host {
  readonly kind = "ssh" as const;
  readonly platformHint = "linux";
  readonly isLocalhost = false;
  readonly label = "admin@fake-target";

  readonly files = new Map<string, string>();
  readonly metas = new Map<string, FileMeta>();
  readonly sysctl = new Map<string, string>();
  readonly services = new Map<string, ServiceState>();
  sshdSyntaxOk = true;
  ufwStatusText = "Status: inactive";
  firewalldState = "not running";
  connectionOk = true;
  verboseConnectionFailure = false;

  constructor(seed: Record<string, string> = {}) {
    for (const [file, content] of Object.entries(seed)) {
      this.files.set(file, content);
      this.metas.set(file, { mode: 0o644, uid: 0, gid: 0 });
    }
  }

  private effectiveSshd(): string {
    const values = { ...SSHD_DEFAULTS };
    const text = this.files.get("/etc/ssh/sshd_config") ?? "";
    for (const line of text.split("\n")) {
      const match = /^\s*([A-Za-z]+)\s+(\S+)/.exec(line);
      if (match?.[1] && match[2]) values[match[1].toLowerCase()] = match[2];
    }
    return Object.entries(values)
      .map(([key, value]) => `${key} ${value}`)
      .join("\n");
  }

  exec(command: string, args: string[], _options: HostExecOptions = {}): Promise<CommandOutcome> {
    if (command === "sysctl") {
      if (args[0] === "-n") return Promise.resolve(ok(this.sysctl.get(args[1] ?? "") ?? ""));
      if (args[0] === "-w") {
        const [key, value] = (args[1] ?? "").split("=");
        if (key !== undefined && value !== undefined) this.sysctl.set(key, value);
        return Promise.resolve(ok(""));
      }
    }
    if (command === "sshd") {
      if (args[0] === "-t")
        return Promise.resolve(
          this.sshdSyntaxOk
            ? ok("")
            : { status: "error", stdout: "", stderr: "syntax error", exitCode: 1, notRun: false },
        );
      if (args[0] === "-T") return Promise.resolve(ok(this.effectiveSshd()));
    }
    if (command === "systemctl") {
      const sub = args[0] ?? "";
      const withNow = args.includes("--now");
      const unit = args[args.length - 1] ?? "";
      const state = this.services.get(unit);
      if (sub === "is-active")
        return Promise.resolve(state ? ok(state.active ? "active" : "inactive") : unavailable());
      if (sub === "is-enabled")
        return Promise.resolve(state ? ok(state.enabled ? "enabled" : "disabled") : unavailable());
      if (sub === "disable" || sub === "stop") {
        if (state) {
          if (sub === "disable" || withNow) state.enabled = false;
          if (sub === "stop" || withNow) state.active = false;
        }
        return Promise.resolve(ok(""));
      }
      if (sub === "enable" || sub === "start") {
        if (state) {
          if (sub === "enable" || withNow) state.enabled = true;
          if (sub === "start" || withNow) state.active = true;
        }
        return Promise.resolve(ok(""));
      }
      if (sub === "reload") return Promise.resolve(ok(""));
    }
    if (command === "ufw") {
      if (args[0] === "status") return Promise.resolve(ok(this.ufwStatusText));
      if (args[0] === "--force" || args[0] === "enable") {
        this.ufwStatusText = "Status: active";
        return Promise.resolve(ok(""));
      }
      if (args[0] === "disable") {
        this.ufwStatusText = "Status: inactive";
        return Promise.resolve(ok(""));
      }
      return Promise.resolve(ok(""));
    }
    if (command === "firewall-cmd") {
      if (args[0] === "--state") return Promise.resolve(ok(this.firewalldState));
      return Promise.resolve(ok(""));
    }
    if (command === "rm") {
      const target = args[args.length - 1] ?? "";
      this.files.delete(target);
      return Promise.resolve(ok(""));
    }
    if (command === "true") {
      return Promise.resolve(
        this.connectionOk
          ? ok("")
          : {
              status: "error",
              stdout: "",
              stderr: "Host key verification failed.",
              exitCode: 255,
              notRun: false,
              failureKind: "host-key",
            },
      );
    }
    if (command === "mkdir" || command === "chmod" || command === "chown") return Promise.resolve(ok(""));
    if (command === "id") return Promise.resolve(ok("0"));
    if (command === "sudo") return Promise.resolve(ok(""));
    if (command === "printenv") return Promise.resolve(ok("/root"));
    return Promise.resolve(unavailable());
  }

  run(command: string, args: string[]): Promise<CommandOutcome> {
    return this.exec(command, args);
  }
  runPrivileged(command: string, args: string[]): Promise<CommandOutcome> {
    return this.exec(command, args, { sudo: true });
  }
  readTextPrivileged(file: string): Promise<FileRead> {
    return this.readText(file);
  }
  async readText(file: string): Promise<FileRead> {
    const content = this.files.get(file);
    return content === undefined ? { ok: false, status: "unavailable" } : { ok: true, content };
  }
  async readlink(): Promise<FileRead> {
    return { ok: false, status: "unavailable" };
  }
  async exists(file: string): Promise<boolean> {
    return this.files.has(file);
  }
  async readDir(dir: string): Promise<DirRead> {
    const names = [...this.files.keys()]
      .filter((f) => path.posix.dirname(f) === dir)
      .map((f) => path.posix.basename(f));
    return { ok: true, names };
  }
  async writeText(file: string, content: string, mode = 0o644): Promise<void> {
    this.files.set(file, content);
    this.metas.set(file, { mode, uid: 0, gid: 0 });
  }
  writeTextPrivileged(file: string, content: string, mode?: number): Promise<void> {
    return this.writeText(file, content, mode);
  }
  async stat(file: string): Promise<HostFileStat | null> {
    if (!this.files.has(file)) return null;
    return this.metas.get(file) ?? { mode: 0o644, uid: 0, gid: 0 };
  }
  async chmod(file: string, mode: number): Promise<void> {
    const meta = this.metas.get(file) ?? { mode, uid: 0, gid: 0 };
    this.metas.set(file, { ...meta, mode });
  }
  async chown(file: string, uid: number, gid: number): Promise<void> {
    const meta = this.metas.get(file) ?? { mode: 0o644, uid, gid };
    this.metas.set(file, { ...meta, uid, gid });
  }
  async mkdirpPrivileged(): Promise<void> {
    // in-memory: nothing to create
  }
  async removePrivileged(file: string): Promise<void> {
    this.files.delete(file);
  }
  async isRoot(): Promise<boolean> {
    return true;
  }
  async sudoAvailable(): Promise<boolean> {
    return true;
  }
  async verifyConnection(): Promise<CommandOutcome> {
    if (this.connectionOk) return ok("");
    return {
      status: "error",
      stdout: "",
      stderr: this.verboseConnectionFailure ? "" : "Host key verification failed.",
      exitCode: 255,
      notRun: false,
      failureKind: "host-key",
    };
  }
  async homeDir(): Promise<string | null> {
    return "/root";
  }
}

export interface ExecEnv {
  host: FakeHost;
  inventory: ServerInventory;
  context: OperationalContext;
  storeRoot: string;
}

export async function makeExecEnv(): Promise<ExecEnv> {
  const host = new FakeHost({
    "/etc/ssh/sshd_config":
      "# test sshd_config\nPermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\nMaxAuthTries 6\n",
    "/etc/fstab": "/dev/sda2 / ext4 defaults 0 1\n/dev/sda3 /tmp ext4 defaults 0 2\n",
  });
  host.services.set("ssh.service", { enabled: true, active: true });
  host.sysctl.set("kernel.randomize_va_space", "0");
  const storeRoot = await mkdtemp(path.join(tmpdir(), "hardener-store-"));
  return { host, inventory: await sampleInventory(), context: sampleContext(), storeRoot };
}

export async function cleanupExecEnv(env: ExecEnv): Promise<void> {
  await rm(env.storeRoot, { recursive: true, force: true });
}

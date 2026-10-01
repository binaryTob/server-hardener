/**
 * Shared test support: sample inventory/context, catalog lookup and a stateful
 * fake command runner with a temporary system tree. Nothing touches the real host.
 */
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { getControl } from "../src/hardening/controls/catalog";
import type { ControlDefinition } from "../src/hardening/controls/types";
import type { CommandOutcome, CommandRunner } from "../src/hardening/exec";
import { runDiscovery } from "../src/hardening/inventory";
import type {
  EvaluatedControl,
  OperationalContext,
  ServerInventory,
  ServerRole,
} from "../src/hardening/models";
import { emptyContext } from "../src/hardening/planning/context";
import { evaluateControl } from "../src/hardening/planning/evaluate";
import type { SystemPaths } from "../src/hardening/remediation/types";
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

// --- Stateful fake runner + temp system tree -------------------------------

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
function error(stderr: string): CommandOutcome {
  return { status: "error", stdout: "", stderr, exitCode: 1, notRun: false };
}
function unavailable(): CommandOutcome {
  return { status: "unavailable", stdout: "", stderr: "not found", exitCode: null, notRun: true };
}

interface ServiceState {
  enabled: boolean;
  active: boolean;
}

export class MutableRunner implements CommandRunner {
  readonly sysctl = new Map<string, string>();
  readonly services = new Map<string, ServiceState>();
  sshdSyntaxOk = true;
  ufwStatusText = "Status: inactive";
  firewalldState = "not running";
  private readonly sshdConfigPath: string;

  constructor(sshdConfigPath: string) {
    this.sshdConfigPath = sshdConfigPath;
  }

  private effectiveSshd(): string {
    let text = "";
    try {
      text = readFileSync(this.sshdConfigPath, "utf8");
    } catch {
      text = "";
    }
    const values = { ...SSHD_DEFAULTS };
    for (const line of text.split("\n")) {
      const match = /^\s*([A-Za-z]+)\s+(\S+)/.exec(line);
      if (match?.[1] && match[2]) values[match[1].toLowerCase()] = match[2];
    }
    return Object.entries(values)
      .map(([key, value]) => `${key} ${value}`)
      .join("\n");
  }

  run(command: string, args: string[]): Promise<CommandOutcome> {
    if (command === "sysctl") {
      if (args[0] === "-n") return Promise.resolve(ok(this.sysctl.get(args[1] ?? "") ?? ""));
      if (args[0] === "-w") {
        const [key, value] = (args[1] ?? "").split("=");
        if (key !== undefined && value !== undefined) this.sysctl.set(key, value);
        return Promise.resolve(ok(""));
      }
    }
    if (command === "sshd") {
      if (args[0] === "-t") return Promise.resolve(this.sshdSyntaxOk ? ok("") : error("syntax error"));
      if (args[0] === "-T") return Promise.resolve(ok(this.effectiveSshd()));
    }
    if (command === "systemctl") {
      const sub = args[0] ?? "";
      const now = args.includes("--now");
      const unit = args[args.length - 1] ?? "";
      const state = this.services.get(unit);
      if (sub === "is-active")
        return Promise.resolve(state ? ok(state.active ? "active" : "inactive") : unavailable());
      if (sub === "is-enabled")
        return Promise.resolve(state ? ok(state.enabled ? "enabled" : "disabled") : unavailable());
      if (sub === "disable" || sub === "stop") {
        if (state) {
          if (sub === "disable" || now) state.enabled = false;
          if (sub === "stop" || now) state.active = false;
        }
        return Promise.resolve(ok(""));
      }
      if (sub === "enable" || sub === "start") {
        if (state) {
          if (sub === "enable" || now) state.enabled = true;
          if (sub === "start" || now) state.active = true;
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
      return Promise.resolve(ok("success"));
    }
    return Promise.resolve(unavailable());
  }
}

export interface ExecEnv {
  dir: string;
  storeRoot: string;
  paths: SystemPaths;
  runner: MutableRunner;
  inventory: ServerInventory;
  context: OperationalContext;
}

export async function makeExecEnv(): Promise<ExecEnv> {
  const dir = await mkdtemp(path.join(tmpdir(), "hardener-exec-"));
  const paths: SystemPaths = {
    sshdConfig: path.join(dir, "sshd_config"),
    sysctlConfDir: path.join(dir, "sysctl.d"),
    sysctlManagedFile: path.join(dir, "sysctl.d", "99-server-hardener.conf"),
    fstab: path.join(dir, "fstab"),
  };
  await mkdir(paths.sysctlConfDir, { recursive: true });
  await writeFile(
    paths.sshdConfig,
    "# test sshd_config\nPermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\nMaxAuthTries 6\n",
    "utf8",
  );
  await writeFile(paths.fstab, "/dev/sda2 / ext4 defaults 0 1\n/dev/sda3 /tmp ext4 defaults 0 2\n", "utf8");

  const runner = new MutableRunner(paths.sshdConfig);
  runner.services.set("ssh.service", { enabled: true, active: true });
  runner.sysctl.set("kernel.randomize_va_space", "0");

  return {
    dir,
    storeRoot: path.join(dir, ".server-hardener"),
    paths,
    runner,
    inventory: await sampleInventory(),
    context: sampleContext(),
  };
}

export async function cleanupExecEnv(env: ExecEnv): Promise<void> {
  await rm(env.dir, { recursive: true, force: true });
}

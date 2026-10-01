/**
 * Deterministic test doubles for discovery: a FakeCommandRunner backed by
 * fixture files and a FakeFileReader backed by in-memory maps. No real
 * command is ever executed in tests.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { OBSERVED_UNITS } from "../src/hardening/collectors/linux";
import type { CommandOutcome, CommandRunner } from "../src/hardening/exec";
import type { DirRead, FileRead, FileReader } from "../src/hardening/fsio";

const FIXTURES = path.resolve(import.meta.dir, "./fixtures");

export function loadFixture(name: string): string {
  return readFileSync(path.join(FIXTURES, name), "utf8");
}

export function ok(stdout: string): CommandOutcome {
  return { status: "ok", stdout, stderr: "", exitCode: 0, notRun: false };
}

export function unavailable(): CommandOutcome {
  return {
    status: "unavailable",
    stdout: "",
    stderr: "command not found",
    exitCode: null,
    notRun: true,
  };
}

export function denied(): CommandOutcome {
  return {
    status: "insufficient-permissions",
    stdout: "",
    stderr: "Permission denied",
    exitCode: null,
    notRun: true,
  };
}

const MACHINE_ID = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";

/** Fake command runner: fixed (commandKey -> outcome) map. */
export class FakeRunner implements CommandRunner {
  private readonly map = new Map<string, CommandOutcome>();
  private readonly defaultOutcome: CommandOutcome;

  constructor(
    entries: Record<string, CommandOutcome | string>,
    defaultOutcome: CommandOutcome = unavailable(),
  ) {
    this.defaultOutcome = defaultOutcome;
    for (const [key, value] of Object.entries(entries)) {
      this.map.set(key, typeof value === "string" ? ok(value) : value);
    }
  }

  run(command: string, args: string[]): Promise<CommandOutcome> {
    const fullKey = [command, ...args].join(" ");
    // Exact key, then the longest registered prefix (real call sites pass
    // extra flags, e.g. "systemctl is-active <units...>").
    let best: { key: string; outcome: CommandOutcome } | null = null;
    for (const [key, outcome] of this.map) {
      if (fullKey === key || fullKey.startsWith(`${key} `)) {
        if (best === null || key.length > best.key.length) {
          best = { key, outcome };
        }
      }
    }
    if (best) return Promise.resolve(best.outcome);
    const byCommand = this.map.get(command);
    if (byCommand) return Promise.resolve(byCommand);
    return Promise.resolve(this.defaultOutcome);
  }
}

/** Fake file reader: explicit content map + permission-denied sets. */
export class FakeFiles implements FileReader {
  private readonly contents: Record<string, string>;
  private readonly deniedPaths: string[];
  private readonly existing: string[];
  private readonly dirs: Record<string, string[]>;
  private readonly links: Record<string, string>;

  constructor(
    contents: Record<string, string>,
    deniedPaths: string[] = [],
    existing: string[] = [],
    dirs: Record<string, string[]> = {},
    links: Record<string, string> = {},
  ) {
    this.contents = contents;
    this.deniedPaths = deniedPaths;
    this.existing = existing;
    this.dirs = dirs;
    this.links = links;
  }

  readText(file: string): Promise<FileRead> {
    if (this.deniedPaths.includes(file)) {
      return Promise.resolve({ ok: false, status: "insufficient-permissions" });
    }
    if (file in this.contents) {
      return Promise.resolve({ ok: true, content: this.contents[file] });
    }
    return Promise.resolve({ ok: false, status: "unavailable" });
  }

  readlink(file: string): Promise<FileRead> {
    const target = this.links[file];
    if (target !== undefined) return Promise.resolve({ ok: true, content: target });
    return Promise.resolve({ ok: false, status: "unavailable" });
  }

  exists(file: string): Promise<boolean> {
    return Promise.resolve(file in this.contents || this.existing.includes(file));
  }

  readDir(dir: string): Promise<DirRead> {
    const names = this.dirs[dir];
    if (names === undefined) {
      return Promise.resolve({
        ok: false,
        status: this.deniedPaths.includes(dir) ? "insufficient-permissions" : "unavailable",
      });
    }
    return Promise.resolve({ ok: true, names });
  }
}

export function runnerEntries(): Record<string, CommandOutcome | string> {
  return {
    hostnamectl: ok(loadFixture("hostnamectl.txt")),
    hostname: ok("srv-01\n"),
    "hostname -f": ok("srv-01.example.com\n"),
    "uname -srm": ok("Linux 6.8.0-45-generic x86_64\n"),
    "systemd-detect-virt": ok("kvm\n"),
    "ip addr": ok(loadFixture("ip-addr.txt")),
    "ip route": ok(loadFixture("ip-route.txt")),
    "ss -tulpn": ok(loadFixture("ss.txt")),
    "sudo --version": ok("Sudo version 1.9.15p5\nSudoers policy plugin version 1.9.15p5\n"),
    "systemctl list-units": ok(loadFixture("systemctl-list-units.txt")),
    "systemctl list-unit-files": ok(loadFixture("systemctl-unit-files.txt")),
    "systemctl is-active": ok(loadFixture("systemctl-is-active.txt")),
    // is-enabled is queried per unit (see collectEnabledStates).
    ...Object.fromEntries(
      OBSERVED_UNITS.map((unit, index) => [
        `systemctl is-enabled ${unit}`,
        ok(
          loadFixture("systemctl-is-enabled.txt")
            .split("\n")
            .map((l) => l.trim())
            .filter((l) => l.length > 0)[index] ?? "not-found",
        ),
      ]),
    ),
    "dpkg-query -W": ok(loadFixture("dpkg-query.txt")),
    "rpm -qa": ok(""),
    findmnt: ok(loadFixture("findmnt.txt")),
    df: ok(loadFixture("df.txt")),
    lsblk: ok(loadFixture("lsblk.json")),
    getenforce: unavailable(),
    "timedatectl show": ok(loadFixture("timedatectl-show.txt")),
    "docker --version": ok("Docker version 27.5.1, build abc123\n"),
    "containerd --version": ok("containerd github.com/containerd/containerd v1.7.24\n"),
  };
}

export const FILE_CONTENTS: Record<string, string> = {
  "/etc/machine-id": `${MACHINE_ID}\n`,
  "/etc/os-release": loadFixture("os-release.txt"),
  "/etc/resolv.conf": loadFixture("resolv.conf"),
  "/etc/passwd": loadFixture("passwd.txt"),
  "/etc/group": loadFixture("group.txt"),
  "/etc/shadow": loadFixture("shadow.txt"),
  "/sys/module/apparmor/parameters/enabled": "Y",
  "/proc/mounts": loadFixture("proc-mounts.txt"),
};

export const FILE_EXISTING = [
  "/etc/sudoers",
  "/run/systemd/system",
  "/usr/bin/sudo",
  "/usr/bin/ufw",
  "/usr/sbin/nft",
  "/usr/sbin/iptables",
  "/usr/bin/docker",
];

export const FILE_DIRS: Record<string, string[]> = { "/etc/sudoers.d": ["90-cloud-init-users"] };

export const FILE_LINKS: Record<string, string> = {
  "/proc/812/exe": "/usr/sbin/sshd",
  "/proc/941/exe": "/usr/sbin/cupsd (deleted)",
};

/** Full-success scenario built from sanitized realistic fixtures. */
export function successfulScenario(): { runner: FakeRunner; files: FakeFiles } {
  return {
    runner: new FakeRunner(runnerEntries()),
    files: new FakeFiles(FILE_CONTENTS, [], FILE_EXISTING, FILE_DIRS, FILE_LINKS),
  };
}

/**
 * Scenario where everything succeeds except /etc/shadow (permission denied),
 * which is the common case when discovery runs without root.
 */
export function shadowDeniedScenario(): { runner: FakeRunner; files: FakeFiles } {
  const contents = { ...FILE_CONTENTS };
  delete contents["/etc/shadow"];
  return {
    runner: new FakeRunner(runnerEntries()),
    files: new FakeFiles(contents, ["/etc/shadow"], FILE_EXISTING, FILE_DIRS, FILE_LINKS),
  };
}

export { MACHINE_ID };

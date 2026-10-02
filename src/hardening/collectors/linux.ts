/**
 * Linux read-only collector.
 *
 * Runs every command needed for discovery. All argvs are hardcoded here —
 * no caller can inject commands. Every tool used is a standard,
 * non-destructive inspection command; failures are captured as outcomes,
 * never thrown, so one broken tool degrades only its own section.
 *
 * Commands intentionally avoided: anything that writes, updates, contacts
 * remote repositories, or escalates privileges (no sudo).
 */
import type { CommandOutcome, CommandRunner } from "../exec";
import type { DirRead, FileRead, FileReader } from "../fsio";
import { detectBinary } from "../fsio";

/** A command execution plus its display form for provenance. */
export interface RawCommand {
  /** Display form, e.g. "ss -tulpn". Used as evidence source in the inventory. */
  display: string;
  outcome: CommandOutcome;
}

/** Service units observed via `systemctl is-active` / `is-enabled`. */
export const OBSERVED_UNITS = [
  "apparmor.service",
  "auditd.service",
  "chrony.service",
  "chronyd.service",
  "clamav-daemon.service",
  "containerd.service",
  "docker.service",
  "falcon-sensor.service",
  "firewalld.service",
  "k3s.service",
  "kubelet.service",
  "mdatp.service",
  "nftables.service",
  "ntp.service",
  "ossec.service",
  "rsyslog.service",
  "sentinelone.service",
  "ssh.service",
  "sshd.service",
  "systemd-journald.service",
  "systemd-timesyncd.service",
  "ufw.service",
  "wazuh-agent.service",
] as const;

/** Binaries whose existence is checked (no execution beyond --version forms). */
const DETECTED_BINARIES = [
  "sudo",
  "ufw",
  "nft",
  "iptables",
  "firewall-cmd",
  "clamscan",
  "wazuh-control",
  "sentinelctl",
  "mdatp",
  "falconctl",
  "docker",
  "podman",
  "containerd",
  "k3s",
  "kubelet",
  "kubectl",
  "chronyd",
  "ntpd",
] as const;

export interface LinuxRaw {
  collectedAt: string;
  identity: {
    hostnamectl: RawCommand;
    hostname: RawCommand;
    hostnameFqdn: RawCommand;
    unameSrm: RawCommand;
    detectVirt: RawCommand;
    machineId: FileRead;
    machineIdSource: string;
  };
  operatingSystem: {
    osRelease: FileRead;
    unameSrm: RawCommand;
    hostnamectl: RawCommand;
  };
  network: {
    ipAddr: RawCommand;
    ipRoute: RawCommand;
    resolvConf: FileRead;
  };
  sockets: {
    ss: RawCommand;
  };
  users: {
    passwd: FileRead;
    group: FileRead;
    shadow: FileRead;
  };
  privilegedAccess: {
    sudoVersion: RawCommand;
    sudoBinary: string | null;
    sudoersMainExists: boolean;
    sudoersDir: DirRead;
  };
  services: {
    systemdRunning: boolean;
    systemctlUnits: RawCommand;
    systemctlUnitFiles: RawCommand;
    isActive: RawCommand;
    isEnabled: RawCommand;
  };
  packages: {
    dpkgQuery: RawCommand;
    rpmQuery: RawCommand;
  };
  security: {
    getenforce: RawCommand;
    appArmorEnabled: FileRead;
    ufwStatus: RawCommand;
    firewalldState: RawCommand;
    detectedBinaries: Readonly<Record<string, string | null>>;
  };
  filesystems: {
    findmnt: RawCommand;
    df: RawCommand;
    lsblk: RawCommand;
    procMounts: FileRead;
  };
  time: {
    timedatectlShow: RawCommand;
  };
  containers: {
    dockerVersion: RawCommand;
    podmanVersion: RawCommand;
    containerdVersion: RawCommand;
    k3sVersion: RawCommand;
    kubeletVersion: RawCommand;
  };
}

export interface CollectorDependencies {
  runner: CommandRunner;
  files: FileReader;
  now: () => string;
}

async function run(runner: CommandRunner, command: string, args: string[]): Promise<RawCommand> {
  const outcome = await runner.run(command, args);
  // Display form is used as evidence source: collapse control characters.
  const display = [command, ...args].map((part) => part.replace(/\s+/g, " ")).join(" ");
  return { display, outcome };
}

/**
 * Collect `systemctl is-enabled` per unit and aggregate in OBSERVED_UNITS order.
 * A single multi-unit call truncates on some systemd versions and would
 * misalign results.
 */
async function collectEnabledStates(runner: CommandRunner): Promise<RawCommand> {
  const outcomes = await Promise.all(
    OBSERVED_UNITS.map((unit) => runner.run("systemctl", ["is-enabled", unit])),
  );
  const display = "systemctl is-enabled <units...>";
  if (outcomes.every((outcome) => outcome.notRun)) {
    return {
      display,
      outcome: { status: "unavailable", stdout: "", stderr: "", exitCode: null, notRun: true },
    };
  }
  const lines = outcomes.map((outcome) => {
    const line = outcome.stdout.trim().split("\n")[0]?.trim();
    return line && line.length > 0 ? line : "unknown";
  });
  return {
    display,
    outcome: { status: "ok", stdout: lines.join("\n"), stderr: "", exitCode: 0, notRun: false },
  };
}

/**
 * Collect all raw Linux discovery data. Never throws for per-command failures;
 * only a total runner failure can reject (handled by the orchestrator).
 */
export async function collectLinuxRaw(deps: CollectorDependencies): Promise<LinuxRaw> {
  const { runner, files, now } = deps;
  const collectedAt = now();

  const [hostnamectl, hostname, hostnameFqdn, unameSrm, detectVirt] = await Promise.all([
    run(runner, "hostnamectl", []),
    run(runner, "hostname", []),
    run(runner, "hostname", ["-f"]),
    run(runner, "uname", ["-srm"]),
    run(runner, "systemd-detect-virt", []),
  ]);

  const machineIdRead = await firstReadable(files, ["/etc/machine-id", "/var/lib/dbus/machine-id"]);
  const osRelease = await files.readText("/etc/os-release");

  const [ipAddr, ipRoute] = await Promise.all([run(runner, "ip", ["addr"]), run(runner, "ip", ["route"])]);
  const resolvConf = await files.readText("/etc/resolv.conf");

  const ss = await run(runner, "ss", ["-tulpn"]);

  const [passwd, group, shadow] = await Promise.all([
    files.readText("/etc/passwd"),
    files.readText("/etc/group"),
    files.readText("/etc/shadow"),
  ]);

  const sudoBinary = await detectBinary(files, "sudo");
  const sudoVersion = await run(runner, "sudo", ["--version"]);
  const sudoersMainExists = await files.exists("/etc/sudoers");
  const sudoersDir = await files.readDir("/etc/sudoers.d");

  const systemdRunning = await files.exists("/run/systemd/system");
  const [systemctlUnits, systemctlUnitFiles, isActive] = await Promise.all([
    run(runner, "systemctl", [
      "list-units",
      "--type=service",
      "--all",
      "--no-legend",
      "--no-pager",
      "--plain",
    ]),
    run(runner, "systemctl", ["list-unit-files", "--type=service", "--no-legend", "--no-pager", "--plain"]),
    run(runner, "systemctl", ["is-active", ...OBSERVED_UNITS]),
  ]);
  // `systemctl is-enabled a b c...` truncates early on some systemd versions,
  // which would misalign results against the requested units. Query each unit
  // individually and aggregate the answers in the same order.
  const isEnabled = await collectEnabledStates(runner);

  const [dpkgQuery, rpmQuery] = await Promise.all([
    // biome-ignore lint/suspicious/noTemplateCurlyInString: dpkg-query placeholders are literal and must reach dpkg untouched
    run(runner, "dpkg-query", ["-W", "--showformat=${binary:Package}\t${Version}\t${Architecture}\n"]),
    run(runner, "rpm", ["-qa", "--queryformat=%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"]),
  ]);

  const detectedBinaries: Record<string, string | null> = {};
  for (const name of DETECTED_BINARIES) {
    detectedBinaries[name] = await detectBinary(files, name);
  }

  const [getenforce, ufwStatus, firewalldState] = await Promise.all([
    run(runner, "getenforce", []),
    run(runner, "ufw", ["status"]),
    run(runner, "firewall-cmd", ["--state"]),
  ]);
  const appArmorEnabled = await files.readText("/sys/module/apparmor/parameters/enabled");

  const [findmnt, df, lsblk] = await Promise.all([
    run(runner, "findmnt", ["-l", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"]),
    run(runner, "df", ["-l", "--output=target,source,fstype,size,used,avail,pcent", "-B1"]),
    run(runner, "lsblk", ["-o", "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT", "--json"]),
  ]);
  const procMounts = await files.readText("/proc/mounts");

  const timedatectlShow = await run(runner, "timedatectl", [
    "show",
    "--property=Timezone",
    "--property=NTP",
    "--property=NTPSynchronized",
  ]);

  const [dockerVersion, podmanVersion, containerdVersion, k3sVersion, kubeletVersion] = await Promise.all([
    run(runner, "docker", ["--version"]),
    run(runner, "podman", ["--version"]),
    run(runner, "containerd", ["--version"]),
    run(runner, "k3s", ["--version"]),
    run(runner, "kubelet", ["--version"]),
  ]);

  return {
    collectedAt,
    identity: {
      hostnamectl,
      hostname,
      hostnameFqdn,
      unameSrm,
      detectVirt,
      machineId: machineIdRead.read,
      machineIdSource: machineIdRead.source,
    },
    operatingSystem: { osRelease, unameSrm, hostnamectl },
    network: { ipAddr, ipRoute, resolvConf },
    sockets: { ss },
    users: { passwd, group, shadow },
    privilegedAccess: {
      sudoVersion,
      sudoBinary,
      sudoersMainExists,
      sudoersDir,
    },
    services: { systemdRunning, systemctlUnits, systemctlUnitFiles, isActive, isEnabled },
    packages: { dpkgQuery, rpmQuery },
    security: { getenforce, appArmorEnabled, ufwStatus, firewalldState, detectedBinaries },
    filesystems: { findmnt, df, lsblk, procMounts },
    time: { timedatectlShow },
    containers: { dockerVersion, podmanVersion, containerdVersion, k3sVersion, kubeletVersion },
  };
}

async function firstReadable(
  files: FileReader,
  paths: string[],
): Promise<{ read: FileRead; source: string }> {
  const source = paths[0] ?? "";
  const read = await files.readText(source);
  if (read.ok || paths.length <= 1) return { read, source };
  return firstReadable(files, paths.slice(1));
}

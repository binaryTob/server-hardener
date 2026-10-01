/**
 * Inventory (orchestration) tests: complete, partial, missing-command,
 * insufficient-permission and unknown-data scenarios, all with deterministic
 * fakes. No real command or file is touched.
 */
import { describe, expect, test } from "bun:test";
import { runDiscovery, summarizeInventory } from "../src/hardening/inventory";
import { validateServerInventory } from "../src/hardening/validation";
import {
  denied,
  FakeFiles,
  FakeRunner,
  FILE_CONTENTS,
  FILE_DIRS,
  FILE_EXISTING,
  FILE_LINKS,
  loadFixture,
  MACHINE_ID,
  ok,
  runnerEntries,
  shadowDeniedScenario,
  successfulScenario,
  unavailable,
} from "./helpers";

const NOW = "2025-01-02T03:04:05.000Z";

function discovery(runner: FakeRunner, files: FakeFiles) {
  return runDiscovery({ runner, files, now: () => NOW, platform: "linux" });
}

describe("complete inventory", () => {
  test("produces a valid, fully-populated inventory", async () => {
    const { runner, files } = successfulScenario();
    const inventory = await discovery(runner, files);

    expect(() => validateServerInventory(inventory)).not.toThrow();
    expect(inventory.generatedAt).toBe(NOW);

    // Identity & OS
    expect(inventory.identity.status).toBe("success");
    expect(inventory.identity.data?.hostname).toBe("srv-01");
    expect(inventory.identity.data?.fqdn).toBe("srv-01.example.com");
    expect(inventory.identity.data?.machineId).toBe(MACHINE_ID);
    expect(inventory.identity.data?.architecture).toBe("x86_64");
    expect(inventory.identity.data?.virtualization).toMatchObject({
      value: "kvm",
      confidence: "observed",
    });
    expect(inventory.operatingSystem.data?.distribution).toBe("Ubuntu 24.04.2 LTS");
    expect(inventory.operatingSystem.data?.kernelRelease).toBe("6.8.0-45-generic");

    // Network
    expect(inventory.network.status).toBe("success");
    expect(inventory.network.data?.interfaces).toHaveLength(3);
    expect(inventory.network.data?.defaultGateways).toHaveLength(1);
    expect(inventory.network.data?.dnsServers).toEqual(["127.0.0.53"]);

    // Sockets: evidence + scope, loopback vs wildcard vs specific
    expect(inventory.sockets.status).toBe("success");
    expect(inventory.sockets.data?.sockets).toHaveLength(9);
    const ssh = inventory.sockets.data?.sockets.find((s) => s.port === 22 && s.ipVersion === "ipv4");
    expect(ssh?.scope).toBe("wildcard");
    expect(ssh?.executable).toBe("/usr/sbin/sshd");
    const cups = inventory.sockets.data?.sockets.find((s) => s.port === 631 && s.address === "127.0.0.1");
    expect(cups?.executable).toBe("/usr/sbin/cupsd");

    // Users: heuristic account types are marked "derived"
    expect(inventory.users.status).toBe("success");
    const user = inventory.users.data?.users.find((u) => u.name === "user");
    expect(user?.accountType).toMatchObject({ value: "human-like", confidence: "derived" });
    expect(user?.locked).toMatchObject({ value: false, confidence: "observed" });
    const svc = inventory.users.data?.users.find((u) => u.name === "_xyzsvc");
    expect(svc?.accountType.value).toBe("service");
    const root = inventory.users.data?.users.find((u) => u.name === "root");
    expect(root?.locked.value).toBe(true);

    // Privileged access
    expect(inventory.privilegedAccess.data?.rootAccountExists).toBe(true);
    expect(inventory.privilegedAccess.data?.sudo).toEqual({
      available: true,
      version: "1.9.15p5",
    });
    const adminNames = inventory.privilegedAccess.data?.administrativeGroups.map((g) => g.name);
    expect(adminNames).toContain("sudo");
    expect(adminNames).toContain("adm");
    const dropIn = inventory.privilegedAccess.data?.sudoersFiles.find((f) => f.kind === "drop-in");
    expect(dropIn?.path).toBe("/etc/sudoers.d/90-cloud-init-users");
    // sudoers contents are never read
    expect(JSON.stringify(inventory.privilegedAccess.data)).not.toContain("NOPASSWD");

    // Services
    expect(inventory.services.status).toBe("success");
    expect(inventory.services.data?.serviceManager).toBe("systemd");
    const sshService = inventory.services.data?.services.find((s) => s.name === "ssh.service");
    expect(sshService).toMatchObject({ enabled: true, active: true, startup: "enabled" });

    // Packages
    expect(inventory.packages.status).toBe("success");
    expect(inventory.packages.data?.managersDetected).toEqual(["dpkg", "rpm"]);
    expect(inventory.packages.data?.packages).toHaveLength(5);

    // Security controls
    expect(inventory.securityControls.status).toBe("partial"); // getenforce unavailable
    expect(inventory.securityControls.data?.appArmor).toMatchObject({
      available: true,
      status: "Y",
    });
    expect(inventory.securityControls.data?.selinux.available).toBe(false);
    expect(inventory.securityControls.data?.firewall.implementation).toMatchObject({
      value: "ufw",
      confidence: "derived",
    });
    expect(inventory.securityControls.data?.firewall.detectedImplementations).toContain("nftables");
    expect(inventory.securityControls.data?.sshServer).toMatchObject({
      available: true,
      active: true,
      enabled: true,
      unit: "ssh.service",
    });
    expect(inventory.securityControls.data?.endpointProtection).toEqual([]);

    // Filesystems (mounts + capacity + block devices)
    expect(inventory.filesystems.status).toBe("success");
    expect(inventory.filesystems.data?.mounts).toHaveLength(6);
    const rootMount = inventory.filesystems.data?.mounts.find((m) => m.mountpoint === "/");
    expect(rootMount?.capacityBytes).toBe(501809635328);
    expect(rootMount?.usedPercent).toBe(33);
    expect(inventory.filesystems.data?.blockDevices).toHaveLength(3);

    // Time (NTP implementation is derived)
    expect(inventory.time.data?.timezone).toBe("America/Argentina/Buenos_Aires");
    expect(inventory.time.data?.ntpSynchronized).toBe(true);
    expect(inventory.time.data?.ntpImplementation).toMatchObject({
      value: "systemd-timesyncd",
      confidence: "derived",
    });

    // Containers (presence + version only)
    expect(inventory.containers.status).toBe("success");
    expect(inventory.containers.data?.runtimes.map((r) => r.name).sort()).toEqual(["containerd", "docker"]);
    expect(inventory.containers.data?.runtimes.find((r) => r.name === "docker")?.version).toBe("27.5.1");
  });

  test("summary reflects statuses, counts and gaps", async () => {
    const { runner, files } = successfulScenario();
    const inventory = await discovery(runner, files);
    const summary = summarizeInventory(inventory);
    expect(summary.hostname).toBe("srv-01");
    expect(summary.counts.interfaces).toBe(3);
    expect(summary.counts.users).toBe(4);
    expect(summary.counts.packages).toBe(5);
    expect(summary.sectionStatuses.sockets).toBe("success");
    // getenforce missing is surfaced as a gap note, not hidden
    expect(summary.gaps.some((g) => g.includes("getenforce"))).toBe(true);
  });
});

describe("partial and degraded scenarios", () => {
  test("unreadable /etc/shadow -> users partial, lock state unknown (not guessed)", async () => {
    const { runner, files } = shadowDeniedScenario();
    const inventory = await discovery(runner, files);

    expect(inventory.users.status).toBe("partial");
    expect(inventory.users.notes?.some((n) => n.includes("insufficient permissions"))).toBe(true);
    for (const user of inventory.users.data?.users ?? []) {
      expect(user.locked.value).toBeNull();
      expect(user.locked.confidence).toBe("unknown");
    }
    // Account type is still derived from passwd only.
    const user = inventory.users.data?.users.find((u) => u.name === "user");
    expect(user?.accountType).toMatchObject({ value: "human-like", confidence: "derived" });
  });

  test("missing ss -> sockets unavailable, everything else still collected", async () => {
    const runner = new FakeRunner({ ...runnerEntries(), "ss -tulpn": unavailable() });
    const files = new FakeFiles(FILE_CONTENTS, [], FILE_EXISTING, FILE_DIRS, FILE_LINKS);
    const inventory = await discovery(runner, files);

    expect(inventory.sockets.status).toBe("unavailable");
    expect(inventory.sockets.data?.sockets).toEqual([]);
    expect(inventory.sockets.notes?.some((n) => n.includes("not available"))).toBe(true);
    // The rest of the inventory is unaffected.
    expect(inventory.identity.status).toBe("success");
    expect(inventory.network.status).toBe("success");
    expect(inventory.packages.status).toBe("success");
    expect(() => validateServerInventory(inventory)).not.toThrow();
  });

  test("insufficient permissions running ss -> status insufficient-permissions", async () => {
    const runner = new FakeRunner({ ...runnerEntries(), "ss -tulpn": denied() });
    const files = new FakeFiles(FILE_CONTENTS, [], FILE_EXISTING, FILE_DIRS, FILE_LINKS);
    const inventory = await discovery(runner, files);
    expect(inventory.sockets.status).toBe("insufficient-permissions");
  });

  test("no package manager available -> packages unavailable", async () => {
    const runner = new FakeRunner({
      ...runnerEntries(),
      "dpkg-query -W": unavailable(),
      "rpm -qa": unavailable(),
    });
    const files = new FakeFiles(FILE_CONTENTS, [], FILE_EXISTING, FILE_DIRS, FILE_LINKS);
    const inventory = await discovery(runner, files);
    expect(inventory.packages.status).toBe("unavailable");
    expect(inventory.packages.data?.managersDetected).toEqual([]);
    expect(inventory.packages.data?.packages).toEqual([]);
  });

  test("unknown data is reported as unknown, never invented", async () => {
    const runner = new FakeRunner({
      ...runnerEntries(),
      hostnamectl: ok(" Static hostname: srv-01\nOperating System: Ubuntu 24.04.2 LTS\n"),
      "systemd-detect-virt": ok(""),
    });
    const files = new FakeFiles(FILE_CONTENTS, [], FILE_EXISTING, FILE_DIRS, FILE_LINKS);
    const inventory = await discovery(runner, files);
    expect(inventory.identity.data?.virtualization).toMatchObject({
      value: null,
      confidence: "unknown",
    });
  });

  test("total collector failure degrades every section to error, no throw", async () => {
    const throwingRunner = {
      run: () => Promise.reject(new Error("boom")),
    };
    const files = new FakeFiles({}, [], [], {}, {});
    const inventory = await runDiscovery({
      runner: throwingRunner,
      files,
      now: () => NOW,
      platform: "linux",
    });
    expect(inventory.identity.status).toBe("error");
    expect(inventory.sockets.status).toBe("error");
    expect(inventory.identity.error).toContain("boom");
  });

  test("non-linux platform -> all sections unsupported, no commands run", async () => {
    const runner = new FakeRunner({});
    const files = new FakeFiles({}, [], [], {}, {});
    const inventory = await runDiscovery({
      runner,
      files,
      now: () => NOW,
      platform: "win32",
    });
    expect(inventory.identity.status).toBe("unsupported");
    expect(inventory.operatingSystem.status).toBe("unsupported");
    expect(inventory.operatingSystem.data?.family).toBe("unknown");
    expect(inventory.sockets.status).toBe("unsupported");
    expect(() => validateServerInventory(inventory)).not.toThrow();
  });
});

describe("no secrets are persisted", () => {
  test("inventory never contains shadow hashes or keys", async () => {
    const { runner, files } = successfulScenario();
    const inventory = await discovery(runner, files);
    const serialized = JSON.stringify(inventory);
    expect(serialized).not.toContain("fakehashvaluehere");
    expect(serialized).not.toContain("$6$");
    expect(serialized).not.toContain("rounds=4096");
    // The shadow file was read for lock state, but its content is not stored.
    expect(loadFixture("shadow.txt")).toContain("$6$");
  });
});

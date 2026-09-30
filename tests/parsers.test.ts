/**
 * Parser tests: pure functions, fixture-driven, no real command execution.
 */
import { describe, expect, test } from "bun:test";
import { parseOsRelease, parseUnameSrm } from "../src/hardening/parsers/linux/identity";
import { parseDf, parseFindmnt, parseLsblk, parseProcMounts } from "../src/hardening/parsers/linux/mounts";
import { parseIpAddr, parseIpRoute, parseResolvConf } from "../src/hardening/parsers/linux/network";
import { parseDpkgQuery, parseRpmQuery } from "../src/hardening/parsers/linux/packages";
import { parseUnitStates } from "../src/hardening/parsers/linux/security";
import { parseSystemctlUnitFiles, parseSystemctlUnits } from "../src/hardening/parsers/linux/services";
import { classifyScope, parseSs, splitEndpoint } from "../src/hardening/parsers/linux/sockets";
import { parseTimedatectl } from "../src/hardening/parsers/linux/time";
import { parseGroup, parsePasswd, parseShadowLocks } from "../src/hardening/parsers/linux/users";
import { loadFixture } from "./helpers";

describe("os-release / uname", () => {
  test("parses Ubuntu os-release", () => {
    const parsed = parseOsRelease(loadFixture("os-release.txt"));
    expect(parsed.prettyName).toBe("Ubuntu 24.04.2 LTS");
    expect(parsed.name).toBe("Ubuntu");
    expect(parsed.version).toBe("24.04.2 LTS (Noble Numbat)");
    expect(parsed.versionId).toBe("24.04");
  });

  test("parses uname -srm", () => {
    const parsed = parseUnameSrm("Linux 6.8.0-45-generic x86_64\n");
    expect(parsed.kernel).toBe("Linux");
    expect(parsed.release).toBe("6.8.0-45-generic");
    expect(parsed.arch).toBe("x86_64");
  });

  test("returns nulls on malformed uname", () => {
    const parsed = parseUnameSrm("garbage");
    expect(parsed.kernel).toBeNull();
    expect(parsed.release).toBeNull();
    expect(parsed.arch).toBeNull();
  });
});

describe("ip addr / ip route / resolv.conf", () => {
  test("parses interfaces and distinguishes loopback", () => {
    const interfaces = parseIpAddr(loadFixture("ip-addr.txt"));
    expect(interfaces).toHaveLength(3);

    const lo = interfaces[0];
    expect(lo?.name).toBe("lo");
    expect(lo?.isLoopback).toBe(true);
    expect(lo?.mtu).toBe(65536);
    expect(lo?.ipv4Addresses).toEqual(["127.0.0.1/8"]);
    expect(lo?.ipv6Addresses).toEqual(["::1/128"]);

    const eth0 = interfaces[1];
    expect(eth0?.name).toBe("eth0");
    expect(eth0?.isLoopback).toBe(false);
    expect(eth0?.state).toBe("UP");
    expect(eth0?.macAddress).toBe("52:54:00:12:34:56");
    expect(eth0?.ipv4Addresses).toEqual(["192.0.2.10/24"]);
    expect(eth0?.ipv6Addresses).toEqual(["2001:db8::10/64"]);

    const docker0 = interfaces[2];
    expect(docker0?.name).toBe("docker0");
    expect(docker0?.state).toBe("DOWN");
  });

  test("parses routes and default gateway", () => {
    const routes = parseIpRoute(loadFixture("ip-route.txt"));
    expect(routes).toHaveLength(3);
    const def = routes.find((r) => r.destination === "default");
    expect(def?.via).toBe("192.0.2.1");
    expect(def?.device).toBe("eth0");
  });

  test("parses nameservers from resolv.conf", () => {
    expect(parseResolvConf(loadFixture("resolv.conf"))).toEqual(["127.0.0.53"]);
  });
});

describe("ss parsing", () => {
  test("parses sockets, processes and addresses", () => {
    const sockets = parseSs(loadFixture("ss.txt"));
    expect(sockets).toHaveLength(9);

    const ssh4 = sockets.find((s) => s.port === 22 && s.ipVersion === "ipv4");
    expect(ssh4?.protocol).toBe("tcp");
    expect(ssh4?.address).toBe("0.0.0.0");
    expect(ssh4?.scope).toBe("wildcard");
    expect(ssh4?.processName).toBe("sshd");
    expect(ssh4?.processPid).toBe(812);

    const ssh6 = sockets.find((s) => s.port === 22 && s.ipVersion === "ipv6");
    expect(ssh6?.address).toBe("::");
    expect(ssh6?.scope).toBe("wildcard");

    const resolved = sockets.find((s) => s.port === 53 && s.ipVersion === "ipv4");
    expect(resolved?.address).toBe("127.0.0.53");
    expect(resolved?.scope).toBe("loopback");

    const v6loop = sockets.find((s) => s.address === "::1");
    expect(v6loop?.scope).toBe("loopback");

    const linkLocal = sockets.find((s) => s.address?.startsWith("fe80"));
    expect(linkLocal?.scope).toBe("specific-address");

    const specific = sockets.find((s) => s.address === "192.0.2.10");
    expect(specific?.scope).toBe("specific-address");
  });

  test("classifyScope covers loopback range, wildcard and specific", () => {
    expect(classifyScope("127.0.0.1")).toBe("loopback");
    expect(classifyScope("127.0.0.54")).toBe("loopback");
    expect(classifyScope("::1")).toBe("loopback");
    expect(classifyScope("0.0.0.0")).toBe("wildcard");
    expect(classifyScope("::")).toBe("wildcard");
    expect(classifyScope("*")).toBe("wildcard");
    expect(classifyScope("192.0.2.10")).toBe("specific-address");
    expect(classifyScope(null)).toBe("unknown");
  });

  test("splitEndpoint handles IPv4, bracketed IPv6 and scoped addresses", () => {
    expect(splitEndpoint("0.0.0.0:22")).toEqual({ address: "0.0.0.0", port: 22 });
    expect(splitEndpoint("[::]:22")).toEqual({ address: "::", port: 22 });
    expect(splitEndpoint("127.0.0.53%lo:53")).toEqual({ address: "127.0.0.53%lo", port: 53 });
    expect(splitEndpoint("*:*")).toEqual({ address: null, port: null });
  });
});

describe("users / groups / shadow", () => {
  test("parses passwd", () => {
    const parsed = parsePasswd(loadFixture("passwd.txt"));
    expect(parsed.malformed).toBe(0);
    expect(parsed.users).toHaveLength(4);
    expect(parsed.users[2]).toMatchObject({
      name: "user",
      uid: 1000,
      gid: 1000,
      shell: "/bin/bash",
      home: "/home/user",
    });
  });

  test("parses groups", () => {
    const parsed = parseGroup(loadFixture("group.txt"));
    expect(parsed.malformed).toBe(0);
    expect(parsed.groups.find((g) => g.name === "sudo")?.members).toEqual(["user"]);
    expect(parsed.groups.find((g) => g.name === "adm")?.members).toEqual(["syslog", "user"]);
  });

  test("parses shadow lock states", () => {
    const parsed = parseShadowLocks(loadFixture("shadow.txt"));
    expect(parsed.locked.get("root")).toBe(true);
    expect(parsed.locked.get("daemon")).toBe(true);
    expect(parsed.locked.get("user")).toBe(false);
    expect(parsed.locked.get("_xyzsvc")).toBe(true);
  });
});

describe("systemctl parsing", () => {
  test("parses list-units", () => {
    const units = parseSystemctlUnits(loadFixture("systemctl-list-units.txt"));
    expect(units.get("ssh.service")).toEqual({ active: "active", sub: "running" });
    expect(units.get("ufw.service")).toEqual({ active: "inactive", sub: "exited" });
  });

  test("parses list-unit-files", () => {
    const files = parseSystemctlUnitFiles(loadFixture("systemctl-unit-files.txt"));
    expect(files.get("ssh.service")).toBe("enabled");
    expect(files.get("wazuh-agent.service")).toBe("not-found");
    expect(files.get("nftables.service")).toBe("disabled");
  });

  test("parses aligned multi-unit is-active/is-enabled output", () => {
    const states = parseUnitStates(
      { outcome: { status: "ok", stdout: loadFixture("systemctl-is-active.txt") } },
      { outcome: { status: "ok", stdout: loadFixture("systemctl-is-enabled.txt") } },
    );
    expect(states.complete).toBe(true);
    expect(states.active.get("ssh.service")).toBe("active");
    expect(states.enabled.get("ssh.service")).toBe("enabled");
    expect(states.enabled.get("wazuh-agent.service")).toBe("not-found");
    expect(states.active.get("systemd-timesyncd.service")).toBe("active");
  });
});

describe("packages", () => {
  test("parses dpkg-query output", () => {
    const packages = parseDpkgQuery(loadFixture("dpkg-query.txt"));
    expect(packages).toHaveLength(5);
    expect(packages[0]).toEqual({
      manager: "dpkg",
      name: "accountsservice",
      version: "23.13.9-2ubuntu6.1",
      architecture: "amd64",
    });
  });

  test("parses rpm output", () => {
    const packages = parseRpmQuery("bash\t5.2.26-4.el9\tx86_64\n");
    expect(packages[0]).toEqual({
      manager: "rpm",
      name: "bash",
      version: "5.2.26-4.el9",
      architecture: "x86_64",
    });
  });
});

describe("filesystems", () => {
  test("parses findmnt output", () => {
    const parsed = parseFindmnt(loadFixture("findmnt.txt"));
    expect(parsed.skipped).toBe(0);
    expect(parsed.mounts).toHaveLength(6);
    const root = parsed.mounts.find((m) => m.mountpoint === "/");
    expect(root?.source).toBe("/dev/sda2");
    expect(root?.filesystemType).toBe("ext4");
    expect(root?.mountOptions).toContain("relatime");
  });

  test("parses /proc/mounts fallback and decodes escaped paths", () => {
    const mounts = parseProcMounts(loadFixture("proc-mounts.txt"));
    expect(mounts).toHaveLength(5);
    const decoded = parseProcMounts("/dev/sdb1 /media/My\\040Disk ext4 rw,relatime 0 0\n");
    expect(decoded[0]?.mountpoint).toBe("/media/My Disk");
  });

  test("parses df capacity", () => {
    const capacities = parseDf(loadFixture("df.txt"));
    const root = capacities.get("/");
    expect(root?.capacityBytes).toBe(501809635328);
    expect(root?.usedPercent).toBe(33);
  });

  test("parses lsblk JSON including children", () => {
    const parsed = parseLsblk(loadFixture("lsblk.json"));
    expect(parsed.error).toBeNull();
    expect(parsed.devices.map((d) => d.name)).toEqual(["sda", "sda1", "sda2"]);
    expect(parsed.devices[2]?.mountpoint).toBe("/");
  });

  test("lsblk invalid JSON is reported as an error, not thrown", () => {
    const parsed = parseLsblk("not json");
    expect(parsed.error).not.toBeNull();
    expect(parsed.devices).toHaveLength(0);
  });
});

describe("time", () => {
  test("parses timedatectl show output", () => {
    const parsed = parseTimedatectl(loadFixture("timedatectl-show.txt"));
    expect(parsed.timezone).toBe("America/Argentina/Buenos_Aires");
    expect(parsed.ntp).toBe(true);
    expect(parsed.ntpSynchronized).toBe(true);
  });
});

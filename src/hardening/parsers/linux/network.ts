/**
 * Parsers for network discovery: `ip addr`, `ip route`, /etc/resolv.conf.
 *
 * Parses the classic text output of iproute2 (available everywhere) instead of
 * JSON output (only in newer iproute2). Read-only: this module never modifies
 * networking configuration.
 */

import type { LinuxRaw } from "../../collectors/linux";
import type { NetworkData, NetworkInterface, RouteEntry, Section } from "../../models";
import {
  combinedStatus,
  failureNote,
  fileFailureNote,
  fileReadStatus,
  makeSection,
  primaryStatus,
} from "./shared";

const IFACE_HEADER = /^(\d+):\s+([^:@\s]+)(@[\w.-]+)?:\s+<([^>]*)>(.*)$/;

/** Parse classic `ip addr` output into interfaces. */
export function parseIpAddr(text: string): NetworkInterface[] {
  const interfaces: NetworkInterface[] = [];
  let current: NetworkInterface | null = null;

  for (const line of text.split("\n")) {
    const header = IFACE_HEADER.exec(line);
    if (header) {
      const flags = (header[4] ?? "").split(",");
      const rest = header[5] ?? "";
      const mtu = /\bmtu (\d+)\b/.exec(rest);
      const state = /\bstate (\S+)\b/.exec(rest);
      const name = header[2] ?? "";
      current = {
        name,
        isLoopback: flags.includes("LOOPBACK") || name === "lo",
        state: state ? (state[1] ?? null) : flags.includes("UP") ? "UP" : null,
        macAddress: null,
        mtu: mtu ? Number(mtu[1]) : null,
        ipv4Addresses: [],
        ipv6Addresses: [],
      };
      interfaces.push(current);
      continue;
    }
    if (!current) continue;

    const ether = /^\s+link\/(?:ether|loopback)\s+([0-9a-fA-F:]{17})/.exec(line);
    if (ether) {
      current.macAddress = ether[1] ?? null;
      continue;
    }
    const inet = /^\s+inet\s+(\S+)/.exec(line);
    if (inet) {
      current.ipv4Addresses.push(inet[1] ?? "");
      continue;
    }
    const inet6 = /^\s+inet6\s+(\S+)/.exec(line);
    if (inet6) {
      current.ipv6Addresses.push(inet6[1] ?? "");
    }
  }
  return interfaces.filter((iface) => iface !== null);
}

/** Parse classic `ip route` output into route entries. */
export function parseIpRoute(text: string): RouteEntry[] {
  const routes: RouteEntry[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const via = findTokenValue(tokens, "via");
    const device = findTokenValue(tokens, "dev");
    routes.push({
      destination: tokens[0] ?? trimmed,
      via: via ?? null,
      device: device ?? null,
    });
  }
  return routes;
}

function findTokenValue(tokens: string[], key: string): string | null {
  const idx = tokens.indexOf(key);
  if (idx < 0) return null;
  return tokens[idx + 1] ?? null;
}

/** Parse nameserver entries from resolv.conf. */
export function parseResolvConf(text: string): string[] {
  const servers: string[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) continue;
    const fields = trimmed.split(/\s+/);
    if (fields[0] === "nameserver" && fields[1]) {
      servers.push(fields[1]);
    }
  }
  return servers;
}

export function parseNetwork(raw: LinuxRaw["network"]): Section<NetworkData> {
  const interfaces = raw.ipAddr.outcome.status === "ok" ? parseIpAddr(raw.ipAddr.outcome.stdout) : null;
  const routes = raw.ipRoute.outcome.status === "ok" ? parseIpRoute(raw.ipRoute.outcome.stdout) : null;
  const dnsServers = raw.resolvConf.ok ? parseResolvConf(raw.resolvConf.content) : null;

  const notes: string[] = [];
  for (const raw_ of [raw.ipAddr, raw.ipRoute]) {
    const note = failureNote(raw_.display, raw_.outcome);
    if (note) notes.push(note);
  }
  if (!raw.resolvConf.ok) {
    const note = fileFailureNote("/etc/resolv.conf", raw.resolvConf.status);
    if (note) notes.push(note);
  }

  const status = combinedStatus([
    primaryStatus(raw.ipAddr.outcome),
    primaryStatus(raw.ipRoute.outcome),
    fileReadStatus(raw.resolvConf),
  ]);

  const defaultGateways = (routes ?? []).filter((r) => r.destination === "default");

  return makeSection(
    status,
    {
      interfaces: interfaces ?? [],
      defaultGateways,
      routes: routes ?? [],
      dnsServers: dnsServers ?? [],
    },
    notes,
  );
}

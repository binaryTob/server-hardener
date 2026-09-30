/**
 * Parser for listening sockets (`ss -tulpn`).
 *
 * Records evidence only: a socket listening on a wildcard address is NOT
 * treated as a vulnerability by itself — risk evaluation belongs to future
 * phases and to a human reviewing the inventory.
 */

import type { LinuxRaw } from "../../collectors/linux";
import type {
  IpVersion,
  ListeningScope,
  ListeningSocket,
  Section,
  SocketData,
  SocketProtocol,
} from "../../models";
import { failureNote, makeSection, primaryStatus } from "./shared";

const PROCESS_RE = /users:\(\("([^"]+)",pid=(\d+)/;

/** Split a "address:port" local endpoint as printed by ss. */
export function splitEndpoint(endpoint: string): { address: string | null; port: number | null } {
  if (!endpoint || endpoint === "*:*" || endpoint === "*") {
    return { address: null, port: null };
  }
  if (endpoint.startsWith("[")) {
    const close = endpoint.indexOf("]");
    if (close > 0) {
      const address = endpoint.slice(1, close) || null;
      const port = parsePort(endpoint.slice(close + 2));
      return { address, port };
    }
  }
  const lastColon = endpoint.lastIndexOf(":");
  if (lastColon < 0) return { address: null, port: null };
  const address = endpoint.slice(0, lastColon) || null;
  const port = parsePort(endpoint.slice(lastColon + 1));
  return { address, port };
}

function parsePort(value: string | undefined): number | null {
  if (!value || value === "*") return null;
  const port = Number.parseInt(value, 10);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
}

/**
 * Classify the listening scope. Loopback covers the whole 127.0.0.0/8 range
 * (systemd-resolved binds e.g. 127.0.0.54) and ::1.
 */
export function classifyScope(address: string | null): ListeningScope {
  if (address === null || address === "") return "unknown";
  if (address === "*" || address === "::" || address === "0.0.0.0") return "wildcard";
  const bare = address.split("%")[0] ?? address;
  if (bare === "::1") return "loopback";
  if (bare.startsWith("127.")) return "loopback";
  return "specific-address";
}

function ipVersion(netid: string): IpVersion {
  if (netid.endsWith("6")) return "ipv6";
  if (netid === "tcp" || netid === "udp") return "ipv4";
  return "unknown";
}

function protocol(netid: string): SocketProtocol {
  if (netid.startsWith("tcp")) return "tcp";
  if (netid.startsWith("udp")) return "udp";
  return "unknown";
}

/** Parse `ss -tulpn` output into listening sockets. */
export function parseSs(text: string): ListeningSocket[] {
  const sockets: ListeningSocket[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("Netid")) continue;
    const tokens = trimmed.split(/\s+/);
    if (tokens.length < 6) continue;
    const netid = tokens[0] ?? "";
    const state = tokens[1] ?? "";
    if (state !== "LISTEN" && state !== "UNCONN") continue;

    const local = splitEndpoint(tokens[4] ?? "");
    const process = tokens.length > 6 ? PROCESS_RE.exec(tokens.slice(6).join(" ")) : null;

    sockets.push({
      protocol: protocol(netid),
      ipVersion: ipVersion(netid),
      address: local.address ? local.address.split("%")[0] : null,
      port: local.port,
      processPid: process ? Number.parseInt(process[2] ?? "", 10) : null,
      processName: process ? (process[1] ?? null) : null,
      executable: null,
      scope: classifyScope(local.address),
    });
  }
  return sockets;
}

export function parseSockets(raw: LinuxRaw["sockets"]): Section<SocketData> {
  const ok = raw.ss.outcome.status === "ok";
  const sockets = ok ? parseSs(raw.ss.outcome.stdout) : [];
  const notes: string[] = [];
  const note = failureNote(raw.ss.display, raw.ss.outcome);
  if (note) notes.push(note);
  if (ok && sockets.length > 0 && sockets.every((s) => s.processPid === null)) {
    notes.push(
      "no process attribution available for sockets: attribute the owning processes requires elevated privileges or same-user processes",
    );
  }

  return makeSection(ok ? "success" : primaryStatus(raw.ss.outcome), { sockets }, notes);
}

/**
 * Target parsing and validation.
 *
 * Accepted forms:
 *   - ssh config alias:  db.example
 *   - user@hostname:     admin@server.example
 *   - user@ip:           admin@server.example
 *   - bare host/ip:      server / 192.0.2.10
 *
 * Validation is strict to avoid option injection (a target starting with "-")
 * and shell metacharacters. The target is always passed as a single argv
 * element to `ssh`, never interpolated into a shell string.
 */
import { TargetValidationError } from "../errors";

export interface TargetSpec {
  /** Original string as provided. */
  raw: string;
  user: string | null;
  /** Alias, hostname or IP (without the user or port part). */
  host: string;
  /** Non-standard SSH port, or null for the ssh default/config. */
  port: number | null;
  /** True when the host is an explicitly-named local machine. */
  isLocalhost: boolean;
}

const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
const HOST_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,253}[A-Za-z0-9])?$/;
const LOCALHOSTS = new Set(["localhost", "127.0.0.1", "::1", "ip6-localhost"]);

function parsePort(value: string): number {
  if (!/^\d{1,5}$/.test(value)) {
    throw new TargetValidationError(`invalid port: ${JSON.stringify(value)}`);
  }
  const port = Number.parseInt(value, 10);
  if (port < 1 || port > 65535) {
    throw new TargetValidationError(`port out of range: ${port}`);
  }
  return port;
}

/** Split "host", "host:port", "[ipv6]" or "[ipv6]:port". */
function splitHostPort(hostPart: string): { host: string; port: number | null } {
  if (hostPart.startsWith("[")) {
    const end = hostPart.indexOf("]");
    if (end > 0) {
      const host = hostPart.slice(1, end);
      const rest = hostPart.slice(end + 1);
      if (rest === "") return { host, port: null };
      if (rest.startsWith(":")) return { host, port: parsePort(rest.slice(1)) };
    }
  } else if (hostPart.split(":").length === 2) {
    const [host, maybePort] = hostPart.split(":");
    if (!host || !maybePort || !/^\d+$/.test(maybePort)) {
      throw new TargetValidationError(`invalid host:port in target: ${JSON.stringify(hostPart)}`);
    }
    return { host, port: parsePort(maybePort) };
  }
  return { host: hostPart, port: null };
}

export function parseTarget(input: string): TargetSpec {
  if (typeof input !== "string") {
    throw new TargetValidationError("target must be a string");
  }
  const raw = input.trim();
  if (raw.length === 0) {
    throw new TargetValidationError("target is empty");
  }
  if (raw.length > 320) {
    throw new TargetValidationError("target is too long");
  }
  if (raw.startsWith("-")) {
    throw new TargetValidationError("target must not start with '-'");
  }
  if (/[\s;|&$()`<>"'\\\n\r\t]/.test(raw)) {
    throw new TargetValidationError(`target contains forbidden characters: ${JSON.stringify(raw)}`);
  }

  const atIndex = raw.indexOf("@");
  let user: string | null = null;
  let hostPart = raw;
  if (atIndex >= 0) {
    if (raw.indexOf("@", atIndex + 1) >= 0) {
      throw new TargetValidationError("target has more than one '@'");
    }
    user = raw.slice(0, atIndex);
    hostPart = raw.slice(atIndex + 1);
    if (!USER_RE.test(user)) {
      throw new TargetValidationError(`invalid user in target: ${JSON.stringify(user)}`);
    }
  }

  const { host, port } = splitHostPort(hostPart);
  if (!HOST_RE.test(host)) {
    throw new TargetValidationError(`invalid host in target: ${JSON.stringify(host)}`);
  }

  return { raw, user, host, port, isLocalhost: LOCALHOSTS.has(host.toLowerCase()) };
}

/** The string handed to ssh (alias or user@host); the port is passed separately. */
export function sshDestination(spec: TargetSpec): string {
  return spec.user ? `${spec.user}@${spec.host}` : spec.host;
}

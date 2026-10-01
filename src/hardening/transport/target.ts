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
  /** Alias, hostname or IP (without the user part). */
  host: string;
  /** True when the host is an explicitly-named local machine. */
  isLocalhost: boolean;
}

const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
const HOST_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,253}[A-Za-z0-9])?$/;
const LOCALHOSTS = new Set(["localhost", "127.0.0.1", "::1", "ip6-localhost"]);

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
  let host = raw;
  if (atIndex >= 0) {
    if (raw.indexOf("@", atIndex + 1) >= 0) {
      throw new TargetValidationError("target has more than one '@'");
    }
    user = raw.slice(0, atIndex);
    host = raw.slice(atIndex + 1);
    if (!USER_RE.test(user)) {
      throw new TargetValidationError(`invalid user in target: ${JSON.stringify(user)}`);
    }
  }
  if (!HOST_RE.test(host)) {
    throw new TargetValidationError(`invalid host in target: ${JSON.stringify(host)}`);
  }

  return { raw, user, host, isLocalhost: LOCALHOSTS.has(host.toLowerCase()) };
}

/** The string handed to ssh (alias or user@host). */
export function sshDestination(spec: TargetSpec): string {
  return spec.user ? `${spec.user}@${spec.host}` : spec.host;
}

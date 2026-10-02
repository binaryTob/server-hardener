/**
 * Operational context: construction, role detection and answer application.
 *
 * The context is operator-supplied truth. Role detection only PROPOSES roles
 * (confidence "derived"); it never promotes them to operational fact on its
 * own. Pure functions: no host access.
 */

import { services, sockets } from "../controls/helpers";
import { AssessmentError } from "../errors";
import type {
  Criticality,
  Environment,
  InternetExposure,
  ManagementMethod,
  OperationalContext,
  RoleAssignment,
  ServerInventory,
  ServerRole,
} from "../models";

export function emptyContext(updatedAt: string): OperationalContext {
  return {
    updatedAt,
    environment: "unknown",
    criticality: "unknown",
    internetExposure: "unknown",
    roles: [],
    management: { methods: [], sshPort: null, secondaryPathConfirmed: null, consoleAccess: null },
    networks: { administrative: [], service: [] },
    reboot: { allowed: null, maintenanceWindowAvailable: null },
    highAvailability: null,
    operatorNotes: null,
  };
}

/** Context fields whose absence changes a decision. */
export const DECISION_CRITICAL_PATHS = [
  "environment",
  "internetExposure",
  "management.secondaryPathConfirmed",
  "management.consoleAccess",
  "roles",
] as const;

export function contextCompleteness(context: OperationalContext): {
  complete: boolean;
  missing: string[];
} {
  const missing: string[] = [];
  if (context.environment === "unknown") missing.push("environment");
  if (context.internetExposure === "unknown") missing.push("internetExposure");
  if (context.management.secondaryPathConfirmed === null) {
    missing.push("management.secondaryPathConfirmed");
  }
  if (context.management.consoleAccess === null) missing.push("management.consoleAccess");
  if (context.roles.filter((r) => r.confidence === "confirmed").length === 0) missing.push("roles");
  return { complete: missing.length === 0, missing };
}

// --- Role detection --------------------------------------------------------

const DATABASE_SERVICE_FRAGMENTS = ["postgres", "mysql", "mariadb", "mongo", "redis", "mssql", "oracle"];
const WEB_SERVICE_FRAGMENTS = ["nginx", "apache", "httpd", "caddy", "lighttpd", "tomcat"];
const DIRECTORY_SERVICE_FRAGMENTS = ["sssd", "winbind", "slapd", "realmd"];
const FILE_SERVICE_FRAGMENTS = ["nfs-server", "nfsd", "smbd", "nmbd"];
const DATABASE_PORTS = [5432, 3306, 27017, 6379, 1433, 1521];
const DIRECTORY_PORTS = [389, 636, 88];
const FILE_PORTS = [2049, 445, 139];
const LOGGING_PORTS = [514];

function pushRole(found: Map<ServerRole, string>, role: ServerRole, reason: string): void {
  if (!found.has(role)) found.set(role, reason);
}

/**
 * Propose roles from inventory evidence. Always `derived`: the operator must
 * confirm or correct them before they are treated as operational truth.
 */
export function detectRoles(inventory: ServerInventory): RoleAssignment[] {
  const found = new Map<ServerRole, string>();
  const serviceNames = services(inventory).map((s) => s.name.toLowerCase());
  const listeningPorts = new Set(
    sockets(inventory)
      .map((s) => s.port)
      .filter((p): p is number => p !== null),
  );

  const hasService = (fragments: string[]) =>
    serviceNames.some((name) => fragments.some((fragment) => name.includes(fragment)));
  const hasPort = (ports: number[]) => ports.some((port) => listeningPorts.has(port));

  const runtimes = inventory.containers.data?.runtimes ?? [];
  const runtimeNames = new Set(runtimes.map((r) => r.name));
  if (runtimeNames.has("kubelet") || runtimeNames.has("k3s")) {
    pushRole(found, "kubernetes-node", "kubelet/k3s runtime detected");
  }
  if (runtimeNames.has("docker") || runtimeNames.has("podman") || runtimeNames.has("containerd")) {
    pushRole(found, "container-host", "container runtime detected");
  }
  if (hasService(DATABASE_SERVICE_FRAGMENTS) || hasPort(DATABASE_PORTS)) {
    pushRole(found, "database", "database service or port detected");
  }
  if (hasService(WEB_SERVICE_FRAGMENTS) || hasPort([80, 443])) {
    pushRole(found, "web-server", "web server service or port detected");
  }
  if (hasService(DIRECTORY_SERVICE_FRAGMENTS) || hasPort(DIRECTORY_PORTS)) {
    pushRole(found, "directory-service", "directory service or port detected");
  }
  if (hasService(FILE_SERVICE_FRAGMENTS) || hasPort(FILE_PORTS)) {
    pushRole(found, "file-server", "file sharing service or port detected");
  }
  if (hasPort(LOGGING_PORTS)) {
    pushRole(found, "logging", "log reception port detected");
  }
  if (found.size === 0) {
    pushRole(found, "generic-server", "no specialised role evidence found");
  }

  return [...found.entries()].map(([role, reason]) => ({
    role,
    confidence: "derived" as const,
    source: reason,
  }));
}

/**
 * Return a context with detected roles added as `derived` proposals, never
 * overwriting an existing (confirmed or derived) role.
 */
export function withDetectedRoles(
  context: OperationalContext,
  inventory: ServerInventory,
): OperationalContext {
  const existing = new Set(context.roles.map((r) => r.role));
  const additions = detectRoles(inventory).filter((r) => !existing.has(r.role));
  if (additions.length === 0) return context;
  return { ...context, roles: [...context.roles, ...additions] };
}

// --- Applying answers ------------------------------------------------------

const ENVIRONMENT_VALUES: Environment[] = ["production", "staging", "development", "testing", "unknown"];
const CRITICALITY_VALUES: Criticality[] = ["low", "medium", "high", "critical", "unknown"];
const EXPOSURE_VALUES: InternetExposure[] = ["direct", "indirect", "none", "unknown"];
export const MANAGEMENT_METHOD_VALUES: ManagementMethod[] = [
  "ssh",
  "ssh-via-bastion",
  "vpn",
  "console",
  "serial-console",
  "out-of-band",
  "rdp",
  "web-console",
  "automation",
  "other",
];

export const SERVER_ROLE_VALUES: ServerRole[] = [
  "generic-server",
  "web-server",
  "application-server",
  "database",
  "container-host",
  "kubernetes-node",
  "bastion",
  "monitoring",
  "logging",
  "file-server",
  "directory-service",
  "automation",
  "unknown",
];

function asBoolean(path: string, value: unknown): boolean | null {
  if (value === null) return null;
  if (typeof value !== "boolean") {
    throw new AssessmentError(`context "${path}" expects a boolean or null`);
  }
  return value;
}

function asEnum<T extends string>(path: string, value: unknown, allowed: T[]): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new AssessmentError(`context "${path}" expects one of: ${allowed.join(", ")}`);
  }
  return value as T;
}

function asStringArray(path: string, value: unknown): string[] {
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
    throw new AssessmentError(`context "${path}" expects an array of strings`);
  }
  return value as string[];
}

/**
 * Apply a single answer (by context path) to a context, returning a new
 * context. Pure. Throws `AssessmentError` on unknown paths or invalid values so
 * no schema violation can be persisted.
 */
export function applyContextPath(
  context: OperationalContext,
  path: string,
  value: unknown,
): OperationalContext {
  switch (path) {
    case "environment":
      return { ...context, environment: asEnum(path, value, ENVIRONMENT_VALUES) };
    case "criticality":
      return { ...context, criticality: asEnum(path, value, CRITICALITY_VALUES) };
    case "internetExposure":
      return { ...context, internetExposure: asEnum(path, value, EXPOSURE_VALUES) };
    case "highAvailability":
      return { ...context, highAvailability: asBoolean(path, value) };
    case "operatorNotes":
      if (value !== null && typeof value !== "string") {
        throw new AssessmentError('context "operatorNotes" expects a string or null');
      }
      return { ...context, operatorNotes: value as string | null };
    case "management.methods":
      return {
        ...context,
        management: {
          ...context.management,
          methods: asStringArray(path, value).map((m) => asEnum(path, m, MANAGEMENT_METHOD_VALUES)),
        },
      };
    case "management.secondaryPathConfirmed":
      return {
        ...context,
        management: { ...context.management, secondaryPathConfirmed: asBoolean(path, value) },
      };
    case "management.consoleAccess":
      return {
        ...context,
        management: { ...context.management, consoleAccess: asBoolean(path, value) },
      };
    case "management.sshPort": {
      if (value === null) {
        return { ...context, management: { ...context.management, sshPort: null } };
      }
      if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > 65535) {
        throw new AssessmentError('context "management.sshPort" expects a port number or null');
      }
      return { ...context, management: { ...context.management, sshPort: value } };
    }
    case "networks.administrative":
      return { ...context, networks: { ...context.networks, administrative: asStringArray(path, value) } };
    case "networks.service":
      return { ...context, networks: { ...context.networks, service: asStringArray(path, value) } };
    case "reboot.allowed":
      return { ...context, reboot: { ...context.reboot, allowed: asBoolean(path, value) } };
    case "reboot.maintenanceWindowAvailable":
      return {
        ...context,
        reboot: { ...context.reboot, maintenanceWindowAvailable: asBoolean(path, value) },
      };
    case "roles": {
      const roles = asStringArray(path, value).map((r) => asEnum(path, r, SERVER_ROLE_VALUES));
      const assignments: RoleAssignment[] = roles.map((role) => ({
        role,
        confidence: "confirmed",
        source: "operator",
      }));
      return { ...context, roles: assignments };
    }
    default:
      throw new AssessmentError(`unknown context path "${path}"`);
  }
}

export function touchContext(context: OperationalContext, updatedAt: string): OperationalContext {
  return { ...context, updatedAt };
}

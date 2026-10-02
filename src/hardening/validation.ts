/**
 * Validation layer: zod schemas mirroring the domain models in models.ts.
 *
 * Used to validate data before it is written to `.server-hardener/` and when
 * it is read back. Corrupt data produces an explicit ValidationFailureError
 * listing every offending path — no silent coercion.
 */
import { z } from "zod";
import { ValidationFailureError } from "./errors";
import type { BackupRecord, LastRun, OperationalContext, ServerInventory } from "./models";

const confidenceSchema = z.enum(["observed", "derived", "unknown"]);

const collectionStatusSchema = z.enum([
  "success",
  "partial",
  "unsupported",
  "insufficient-permissions",
  "unavailable",
  "error",
]);

const evidence = <T extends z.ZodType>(value: T) =>
  z.object({
    value: value.nullable(),
    source: z.string().min(1),
    confidence: confidenceSchema,
    collectedAt: z.string().min(1),
  });

const section = <T extends z.ZodType>(data: T) =>
  z.object({
    status: collectionStatusSchema,
    data: data.nullable(),
    error: z.string().optional(),
    notes: z.array(z.string()).optional(),
  });

// --- Identity / OS -------------------------------------------------------

const identityDataSchema = z.object({
  hostname: z.string().nullable(),
  fqdn: z.string().nullable(),
  machineId: z.string().nullable(),
  virtualization: evidence(z.string()),
  architecture: z.string().nullable(),
});

const osFamilySchema = z.enum(["linux", "windows", "bsd", "unknown"]);

const operatingSystemDataSchema = z.object({
  family: osFamilySchema,
  distribution: z.string().nullable(),
  version: z.string().nullable(),
  versionId: z.string().nullable(),
  kernel: z.string().nullable(),
  kernelRelease: z.string().nullable(),
});

// --- Network --------------------------------------------------------------

const networkInterfaceSchema = z.object({
  name: z.string().min(1),
  isLoopback: z.boolean(),
  state: z.string().nullable(),
  macAddress: z.string().nullable(),
  mtu: z.number().int().positive().nullable(),
  ipv4Addresses: z.array(z.string()),
  ipv6Addresses: z.array(z.string()),
});

const routeEntrySchema = z.object({
  destination: z.string().min(1),
  via: z.string().nullable(),
  device: z.string().nullable(),
});

const networkDataSchema = z.object({
  interfaces: z.array(networkInterfaceSchema),
  defaultGateways: z.array(routeEntrySchema),
  routes: z.array(routeEntrySchema),
  dnsServers: z.array(z.string()),
});

// --- Sockets ---------------------------------------------------------------

const listeningSocketSchema = z.object({
  protocol: z.enum(["tcp", "udp", "unknown"]),
  ipVersion: z.enum(["ipv4", "ipv6", "unknown"]),
  address: z.string().nullable(),
  port: z.number().int().positive().max(65535).nullable(),
  processPid: z.number().int().positive().nullable(),
  processName: z.string().nullable(),
  executable: z.string().nullable(),
  scope: z.enum(["loopback", "specific-address", "wildcard", "unknown"]),
});

const socketDataSchema = z.object({
  sockets: z.array(listeningSocketSchema),
});

// --- Users -----------------------------------------------------------------

const accountTypeSchema = z.enum(["system", "human-like", "service", "unknown"]);

const inventoryUserSchema = z.object({
  name: z.string().min(1),
  uid: z.number().int(),
  gid: z.number().int(),
  primaryGroup: z.string().nullable(),
  supplementaryGroups: z.array(z.string()),
  shell: z.string().nullable(),
  home: z.string().nullable(),
  locked: evidence(z.boolean()),
  accountType: evidence(accountTypeSchema),
});

const inventoryGroupSchema = z.object({
  name: z.string().min(1),
  gid: z.number().int(),
  members: z.array(z.string()),
});

const usersDataSchema = z.object({
  users: z.array(inventoryUserSchema),
  groups: z.array(inventoryGroupSchema),
});

// --- Privileged access -----------------------------------------------------

const adminGroupSchema = z.object({
  name: z.string().min(1),
  gid: z.number().int(),
  members: z.array(z.string()),
});

const sudoersFileRefSchema = z.object({
  path: z.string().min(1),
  exists: z.boolean(),
  kind: z.enum(["main", "drop-in"]),
});

const privilegedAccessDataSchema = z.object({
  rootAccountExists: z.boolean().nullable(),
  administrativeGroups: z.array(adminGroupSchema),
  sudo: z.object({
    available: z.boolean(),
    version: z.string().nullable(),
  }),
  sudoersFiles: z.array(sudoersFileRefSchema),
});

// --- Services --------------------------------------------------------------

const inventoryServiceSchema = z.object({
  name: z.string().min(1),
  enabled: z.boolean().nullable(),
  active: z.boolean().nullable(),
  subState: z.string().nullable(),
  startup: z.string().nullable(),
});

const servicesDataSchema = z.object({
  serviceManager: z.enum(["systemd", "unknown"]),
  services: z.array(inventoryServiceSchema),
});

// --- Packages --------------------------------------------------------------

const packageManagerSchema = z.enum(["dpkg", "rpm", "unknown"]);

const inventoryPackageSchema = z.object({
  manager: packageManagerSchema,
  name: z.string().min(1),
  version: z.string().nullable(),
  architecture: z.string().nullable(),
});

const packagesDataSchema = z.object({
  managersDetected: z.array(packageManagerSchema),
  packages: z.array(inventoryPackageSchema),
});

// --- Security controls -----------------------------------------------------

const securityControlStateSchema = z.object({
  available: z.boolean(),
  status: z.string().nullable(),
});

const serviceControlStateSchema = z.object({
  available: z.boolean(),
  active: z.boolean().nullable(),
  enabled: z.boolean().nullable(),
});

const endpointKindSchema = z.enum(["antivirus", "edr", "hids", "monitoring", "other"]);

const detectedCapabilitySchema = z.object({
  name: z.string().min(1),
  kind: endpointKindSchema,
  status: z.string().nullable(),
  source: z.string().min(1),
  confidence: confidenceSchema,
});

const securityControlsDataSchema = z.object({
  selinux: securityControlStateSchema,
  appArmor: securityControlStateSchema,
  firewall: z.object({
    implementation: evidence(z.string()),
    active: z.boolean().nullable(),
    enabled: z.boolean().nullable(),
    detectedImplementations: z.array(z.string()),
  }),
  auditd: serviceControlStateSchema,
  journald: serviceControlStateSchema,
  rsyslog: serviceControlStateSchema,
  sshServer: serviceControlStateSchema.extend({
    unit: z.string().nullable(),
  }),
  endpointProtection: z.array(detectedCapabilitySchema),
});

// --- Filesystems -----------------------------------------------------------

const mountInfoSchema = z.object({
  mountpoint: z.string().min(1),
  source: z.string().nullable(),
  filesystemType: z.string().nullable(),
  mountOptions: z.array(z.string()),
  capacityBytes: z.number().int().positive().nullable(),
  usedBytes: z.number().int().positive().nullable(),
  availableBytes: z.number().int().positive().nullable(),
  usedPercent: z.number().int().min(0).max(100).nullable(),
});

const blockDeviceSchema = z.object({
  name: z.string().min(1),
  type: z.string().nullable(),
  size: z.string().nullable(),
  filesystemType: z.string().nullable(),
  mountpoint: z.string().nullable(),
});

const filesystemsDataSchema = z.object({
  mounts: z.array(mountInfoSchema),
  blockDevices: z.array(blockDeviceSchema),
});

// --- Time / Containers -----------------------------------------------------

const timeDataSchema = z.object({
  timezone: z.string().nullable(),
  ntpImplementation: evidence(z.string()),
  ntpSynchronized: z.boolean().nullable(),
});

const containerRuntimeNameSchema = z.enum(["docker", "podman", "containerd", "kubelet", "k3s", "kubectl"]);

const containerRuntimeSchema = z.object({
  name: containerRuntimeNameSchema,
  version: z.string().nullable(),
  active: z.boolean().nullable(),
  detectedVia: z.string().min(1),
});

const containersDataSchema = z.object({
  runtimes: z.array(containerRuntimeSchema),
});

// --- ServerInventory --------------------------------------------------------

export const serverInventorySchema = z.object({
  generatedAt: z.string().min(1),
  identity: section(identityDataSchema),
  operatingSystem: section(operatingSystemDataSchema),
  network: section(networkDataSchema),
  sockets: section(socketDataSchema),
  users: section(usersDataSchema),
  privilegedAccess: section(privilegedAccessDataSchema),
  services: section(servicesDataSchema),
  packages: section(packagesDataSchema),
  securityControls: section(securityControlsDataSchema),
  filesystems: section(filesystemsDataSchema),
  time: section(timeDataSchema),
  containers: section(containersDataSchema),
});

export function validateServerInventory(input: unknown): ServerInventory {
  const result = serverInventorySchema.safeParse(input);
  if (!result.success) {
    const issues = result.error.issues.map((issue) => {
      const path = issue.path.length > 0 ? issue.path.map(String).join(".") : "(root)";
      return `${path}: ${issue.message}`;
    });
    throw new ValidationFailureError("ServerInventory failed schema validation", issues);
  }
  return result.data as ServerInventory;
}

// --- Operational context --------------------------------------------------

const environmentSchema = z.enum(["production", "staging", "development", "testing", "unknown"]);
const criticalitySchema = z.enum(["low", "medium", "high", "critical", "unknown"]);
const internetExposureSchema = z.enum(["direct", "indirect", "none", "unknown"]);
const serverRoleSchema = z.enum([
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
]);
const roleConfidenceSchema = z.enum(["confirmed", "derived"]);
const roleAssignmentSchema = z.object({
  role: serverRoleSchema,
  confidence: roleConfidenceSchema,
  source: z.string().min(1),
});
const managementMethodSchema = z.enum([
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
]);
const cidrSchema = z
  .string()
  .regex(/^[0-9a-fA-F:.]+\/[0-9]{1,3}$/, "expected CIDR notation, e.g. 10.0.0.0/8");

export const operationalContextSchema = z
  .object({
    updatedAt: z.string().min(1),
    environment: environmentSchema,
    criticality: criticalitySchema,
    internetExposure: internetExposureSchema,
    roles: z.array(roleAssignmentSchema),
    management: z.object({
      methods: z.array(managementMethodSchema),
      sshPort: z.number().int().min(1).max(65535).nullable().optional(),
      secondaryPathConfirmed: z.boolean().nullable(),
      consoleAccess: z.boolean().nullable(),
    }),
    networks: z.object({
      administrative: z.array(cidrSchema),
      service: z.array(cidrSchema),
    }),
    reboot: z.object({
      allowed: z.boolean().nullable(),
      maintenanceWindowAvailable: z.boolean().nullable(),
    }),
    highAvailability: z.boolean().nullable(),
    operatorNotes: z.string().nullable(),
  })
  .strict();

export function validateOperationalContext(input: unknown): OperationalContext {
  const result = operationalContextSchema.safeParse(input);
  if (!result.success) {
    throw new ValidationFailureError(
      "OperationalContext failed schema validation",
      result.error.issues.map((issue) => {
        const path = issue.path.length > 0 ? issue.path.map(String).join(".") : "(root)";
        return `${path}: ${issue.message}`;
      }),
    );
  }
  return result.data as OperationalContext;
}

// --- Local state: backups and last-run ------------------------------------

export const backupRecordSchema = z.object({
  backupId: z.string().min(1),
  controlId: z.string().min(1),
  originalPath: z.string().min(1),
  createdAt: z.string().min(1),
  sha256: z.string().min(1),
  bytes: z.number().int().nonnegative(),
  mode: z.number().int().nonnegative().nullable(),
  uid: z.number().int().nullable(),
  gid: z.number().int().nullable(),
  content: z.string(),
});

const verificationSummarySchema = z.object({
  check: z.string(),
  expected: z.string(),
  observed: z.string().nullable(),
  passed: z.boolean().nullable(),
});

export const lastRunEntrySchema = z.object({
  at: z.string().min(1),
  host: z.string().min(1),
  controlId: z.string().min(1),
  action: z.enum(["apply", "rollback"]),
  target: z.string(),
  result: z.enum(["applied", "skipped", "failed", "rolled-back", "manual"]),
  changed: z.boolean(),
  message: z.string(),
  before: z.string().nullable(),
  after: z.string().nullable(),
  backupDir: z.string().nullable(),
  verification: verificationSummarySchema.nullable(),
  backupIds: z.array(z.string()),
});

export const lastRunSchema = z.object({
  updatedAt: z.string().min(1),
  hostname: z.string().nullable(),
  evaluated: z.number().int().nonnegative(),
  entries: z.array(lastRunEntrySchema),
});

function validationIssues(error: z.ZodError): string[] {
  return error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.map(String).join(".") : "(root)";
    return `${path}: ${issue.message}`;
  });
}

export function validateBackupRecord(input: unknown): BackupRecord {
  const result = backupRecordSchema.safeParse(input);
  if (!result.success) {
    throw new ValidationFailureError("BackupRecord failed schema validation", validationIssues(result.error));
  }
  return result.data as BackupRecord;
}

export function validateLastRun(input: unknown): LastRun {
  const result = lastRunSchema.safeParse(input);
  if (!result.success) {
    throw new ValidationFailureError("LastRun failed schema validation", validationIssues(result.error));
  }
  return result.data as LastRun;
}

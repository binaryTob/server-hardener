/**
 * Validation layer: zod schemas mirroring the domain models in models.ts.
 *
 * Every document is validated before being persisted and again when loaded.
 * Corrupt or incompatible data produces an explicit ValidationFailureError
 * listing every offending path — no silent coercion.
 *
 * The schemas intentionally mirror models.ts one-to-one; persistence round-trip
 * tests keep both sides aligned.
 */
import { z } from "zod";
import { UnsupportedSchemaVersionError, ValidationFailureError } from "./errors";
import { SCHEMA_VERSION, type ServerInventory } from "./models";

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
  schemaVersion: z.literal(SCHEMA_VERSION),
  inventoryId: z.string().min(1),
  serverId: z.string().min(1),
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

/**
 * Check the schemaVersion field of a raw (possibly foreign) document before
 * full validation. Explicit error on incompatible versions; anything that is
 * not a versioned document is rejected.
 */
export function checkSchemaVersion(input: unknown, expected: number = SCHEMA_VERSION): number {
  if (typeof input !== "object" || input === null) {
    throw new ValidationFailureError("Document is not an object", ["(root): not an object"]);
  }
  const version = (input as { schemaVersion?: unknown }).schemaVersion;
  if (typeof version !== "number" || !Number.isInteger(version)) {
    throw new ValidationFailureError("Document has no integer schemaVersion", [
      "schemaVersion: missing or not an integer",
    ]);
  }
  if (version !== expected) {
    throw new UnsupportedSchemaVersionError(version, expected);
  }
  return version;
}

// --- Future-phase document envelopes (contracts, not produced yet) ---------

const controlSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  description: z.string(),
  category: z.enum([
    "os",
    "network",
    "services",
    "users",
    "authentication",
    "logging",
    "filesystem",
    "packages",
    "kernel",
  ]),
  rationale: z.string(),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  applicability: z.object({
    osFamilies: z.array(osFamilySchema),
    requires: z.array(z.string()).optional(),
  }),
  currentState: z.string().nullable(),
  desiredState: z.string(),
  securityImpact: z.string(),
  availabilityRisk: z.string(),
  lockoutRisk: z.string(),
  requiresApproval: z.boolean(),
  reversible: z.boolean(),
  dependencies: z.array(z.string()),
  evidenceReferences: z.array(z.string()),
  references: z.array(z.string()),
  tags: z.array(z.string()),
});

const planStatusSchema = z.enum([
  "draft",
  "review",
  "approved",
  "applying",
  "completed",
  "failed",
  "rolled-back",
]);

export const hardeningPlanSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  planId: z.string().min(1),
  serverId: z.string().min(1),
  inventoryId: z.string().min(1),
  createdAt: z.string().min(1),
  profile: z.string().min(1),
  controls: z.array(controlSchema),
  status: planStatusSchema,
});

export const changeRecordSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  changeId: z.string().min(1),
  controlId: z.string().min(1),
  serverId: z.string().min(1),
  timestamp: z.string().min(1),
  target: z.string().min(1),
  before: z.string().nullable(),
  after: z.string().nullable(),
  result: z.enum(["applied", "failed", "skipped", "rolled-back"]),
  verificationId: z.string().nullable(),
  rollbackId: z.string().nullable(),
});

export const exceptionRecordSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  exceptionId: z.string().min(1),
  controlId: z.string().min(1),
  serverId: z.string().min(1),
  reason: z.string().min(1),
  scope: z.enum(["server", "control", "parameter"]),
  createdAt: z.string().min(1),
  expiresAt: z.string().nullable(),
  acceptedRisk: z.string().min(1),
  evidence: z.array(z.string()),
});

export const rollbackRecordSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  rollbackId: z.string().min(1),
  changeId: z.string().min(1),
  serverId: z.string().min(1),
  timestamp: z.string().min(1),
  available: z.boolean(),
  strategy: z.string().nullable(),
  artifacts: z.array(z.string()),
  verificationId: z.string().nullable(),
});

export const verificationResultSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  verificationId: z.string().min(1),
  serverId: z.string().min(1),
  timestamp: z.string().min(1),
  target: z.string().min(1),
  check: z.string().min(1),
  expected: z.string().min(1),
  observed: z.string().nullable(),
  passed: z.boolean().nullable(),
  evidence: z.array(z.string()),
  error: z.string().nullable(),
});

// Type guards tying the zod schemas to the model contracts.
export type ValidatedPlan = z.infer<typeof hardeningPlanSchema>;
export type ValidatedChange = z.infer<typeof changeRecordSchema>;
export type ValidatedException = z.infer<typeof exceptionRecordSchema>;
export type ValidatedRollback = z.infer<typeof rollbackRecordSchema>;
export type ValidatedVerification = z.infer<typeof verificationResultSchema>;

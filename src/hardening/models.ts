/**
 * Domain models for the server hardening framework.
 *
 * Phase 1 covers discovery and inventory only. Models for controls, plans,
 * changes, exceptions, rollbacks and verifications are contracts for future
 * phases and are intentionally not populated or applied here.
 *
 * Design rules:
 * - Every inventory section records its own collection status; one failing
 *   section never aborts the whole inventory.
 * - Fields that depend on inference are wrapped in `Evidence` so the provenance
 *   of every value ("where did this come from?") can always be answered.
 * - Nothing in this module assumes Linux forever: `OSFamily` is an open set and
 *   collectors are selected per family.
 */

/** Schema version of every main persisted document produced by this phase. */
export const SCHEMA_VERSION = 1;

export type OSFamily = "linux" | "windows" | "bsd" | "unknown";

export type CollectionStatus =
  | "success"
  | "partial"
  | "unsupported"
  | "insufficient-permissions"
  | "unavailable"
  | "error";

export type Confidence = "observed" | "derived" | "unknown";

/**
 * A value plus its provenance. Use for fields where inference is possible:
 * - `observed`: read directly from a source of truth.
 * - `derived`: computed by a documented heuristic.
 * - `unknown`: could not be determined.
 */
export interface Evidence<T> {
  value: T | null;
  source: string;
  confidence: Confidence;
  collectedAt: string;
}

/** Common envelope for every inventory section. */
export interface Section<T> {
  status: CollectionStatus;
  data: T | null;
  error?: string;
  notes?: string[];
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

export interface IdentityData {
  hostname: string | null;
  fqdn: string | null;
  machineId: string | null;
  /** Virtualization technology (e.g. "kvm"), or null for bare metal. */
  virtualization: Evidence<string | null>;
  architecture: string | null;
}

// ---------------------------------------------------------------------------
// Operating system
// ---------------------------------------------------------------------------

export interface OperatingSystemData {
  family: OSFamily;
  distribution: string | null;
  version: string | null;
  versionId: string | null;
  kernel: string | null;
  kernelRelease: string | null;
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

export interface NetworkInterface {
  name: string;
  /** Explicitly distinguishes loopback interfaces from normal ones. */
  isLoopback: boolean;
  /** Operstate as reported by the OS ("UP", "DOWN", "UNKNOWN", ...). */
  state: string | null;
  macAddress: string | null;
  mtu: number | null;
  /** Observed IPv4 addresses in CIDR form (e.g. "192.0.2.10/24"). */
  ipv4Addresses: string[];
  /** Observed IPv6 addresses in CIDR form (e.g. "2001:db8::1/64"). */
  ipv6Addresses: string[];
}

export interface RouteEntry {
  destination: string;
  via: string | null;
  device: string | null;
}

export interface NetworkData {
  interfaces: NetworkInterface[];
  defaultGateways: RouteEntry[];
  routes: RouteEntry[];
  dnsServers: string[];
}

// ---------------------------------------------------------------------------
// Listening sockets
// ---------------------------------------------------------------------------

export type ListeningScope = "loopback" | "specific-address" | "wildcard" | "unknown";

export type SocketProtocol = "tcp" | "udp" | "unknown";

export type IpVersion = "ipv4" | "ipv6" | "unknown";

export interface ListeningSocket {
  protocol: SocketProtocol;
  ipVersion: IpVersion;
  /** Bind address without port; null when not observable. */
  address: string | null;
  port: number | null;
  processPid: number | null;
  processName: string | null;
  /** Executable path resolved via /proc when readable; null otherwise. */
  executable: string | null;
  /** Evidence only. A wildcard scope is NOT by itself a vulnerability signal. */
  scope: ListeningScope;
}

export interface SocketData {
  sockets: ListeningSocket[];
}

// ---------------------------------------------------------------------------
// Users and groups
// ---------------------------------------------------------------------------

export type AccountType = "system" | "human-like" | "service" | "unknown";

export interface InventoryUser {
  name: string;
  uid: number;
  gid: number;
  primaryGroup: string | null;
  supplementaryGroups: string[];
  shell: string | null;
  home: string | null;
  /**
   * Account locked state. Only `observed` when /etc/shadow was readable;
   * `unknown` when privileges were insufficient. Never guessed.
   */
  locked: Evidence<boolean | null>;
  /**
   * Heuristic classification. ALWAYS `derived` confidence: a UID threshold
   * never proves that an account belongs to a human.
   */
  accountType: Evidence<AccountType>;
}

export interface InventoryGroup {
  name: string;
  gid: number;
  members: string[];
}

export interface UsersData {
  users: InventoryUser[];
  groups: InventoryGroup[];
}

// ---------------------------------------------------------------------------
// Privileged access
// ---------------------------------------------------------------------------

export interface AdminGroup {
  name: string;
  gid: number;
  members: string[];
}

export interface SudoersFileRef {
  path: string;
  exists: boolean;
  kind: "main" | "drop-in";
}

export interface PrivilegedAccessData {
  rootAccountExists: boolean | null;
  /** Known administrative groups (wheel, sudo, adm, disk) when present. */
  administrativeGroups: AdminGroup[];
  sudo: {
    available: boolean;
    version: string | null;
  };
  /** Existence of well-known sudoers paths. Contents are never read or persisted. */
  sudoersFiles: SudoersFileRef[];
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

export type ServiceManager = "systemd" | "unknown";

export interface InventoryService {
  /** Unit name as reported by the service manager (e.g. "ssh.service"). */
  name: string;
  enabled: boolean | null;
  active: boolean | null;
  subState: string | null;
  /** Startup configuration as reported (enabled / disabled / static / masked / ...). */
  startup: string | null;
}

export interface ServicesData {
  serviceManager: ServiceManager;
  services: InventoryService[];
}

// ---------------------------------------------------------------------------
// Packages
// ---------------------------------------------------------------------------

export type PackageManager = "dpkg" | "rpm" | "unknown";

export interface InventoryPackage {
  manager: PackageManager;
  name: string;
  version: string | null;
  architecture: string | null;
}

export interface PackagesData {
  managersDetected: PackageManager[];
  packages: InventoryPackage[];
}

// ---------------------------------------------------------------------------
// Security controls
// ---------------------------------------------------------------------------

export interface SecurityControlState {
  /** Whether the control/tool is present on the system. */
  available: boolean;
  /** Raw reported status (e.g. "Enforcing", "active", "inactive"); null if unknown. */
  status: string | null;
}

export interface ServiceControlState {
  available: boolean;
  active: boolean | null;
  enabled: boolean | null;
}

export type EndpointKind = "antivirus" | "edr" | "hids" | "monitoring" | "other";

/** A security capability detected from observable evidence (binary or unit). */
export interface DetectedCapability {
  name: string;
  kind: EndpointKind;
  /** "active", "inactive", "installed" or similar; null if unknown. */
  status: string | null;
  source: string;
  confidence: Confidence;
}

export interface SecurityControlsData {
  selinux: SecurityControlState;
  appArmor: SecurityControlState;
  firewall: {
    /** Inferred from detected implementations; always `derived` confidence. */
    implementation: Evidence<string | null>;
    active: boolean | null;
    enabled: boolean | null;
    detectedImplementations: string[];
  };
  auditd: ServiceControlState;
  journald: ServiceControlState;
  rsyslog: ServiceControlState;
  sshServer: ServiceControlState & { unit: string | null };
  /** Antivirus/EDR/HIDS agents (Wazuh is one entry among others, not special). */
  endpointProtection: DetectedCapability[];
}

// ---------------------------------------------------------------------------
// Filesystems
// ---------------------------------------------------------------------------

export interface MountInfo {
  mountpoint: string;
  source: string | null;
  filesystemType: string | null;
  mountOptions: string[];
  capacityBytes: number | null;
  usedBytes: number | null;
  availableBytes: number | null;
  usedPercent: number | null;
}

export interface BlockDevice {
  name: string;
  type: string | null;
  size: string | null;
  filesystemType: string | null;
  mountpoint: string | null;
}

export interface FilesystemsData {
  mounts: MountInfo[];
  blockDevices: BlockDevice[];
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

export interface TimeData {
  timezone: string | null;
  /** NTP daemon inferred from service state; `derived` confidence. */
  ntpImplementation: Evidence<string | null>;
  ntpSynchronized: boolean | null;
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

export type ContainerRuntimeName = "docker" | "podman" | "containerd" | "kubelet" | "k3s" | "kubectl";

export interface ContainerRuntime {
  name: ContainerRuntimeName;
  /** Presence + version only in Phase 1. Workloads are not inspected. */
  version: string | null;
  active: boolean | null;
  detectedVia: string;
}

export interface ContainersData {
  runtimes: ContainerRuntime[];
}

// ---------------------------------------------------------------------------
// ServerInventory
// ---------------------------------------------------------------------------

export interface ServerInventory {
  schemaVersion: number;
  inventoryId: string;
  /** Stable identifier derived from machine identity (hashed), not the hostname. */
  serverId: string;
  generatedAt: string;
  identity: Section<IdentityData>;
  operatingSystem: Section<OperatingSystemData>;
  network: Section<NetworkData>;
  sockets: Section<SocketData>;
  users: Section<UsersData>;
  privilegedAccess: Section<PrivilegedAccessData>;
  services: Section<ServicesData>;
  packages: Section<PackagesData>;
  securityControls: Section<SecurityControlsData>;
  filesystems: Section<FilesystemsData>;
  time: Section<TimeData>;
  containers: Section<ContainersData>;
}

export type SectionName = keyof Omit<
  ServerInventory,
  "schemaVersion" | "inventoryId" | "serverId" | "generatedAt"
>;

// ---------------------------------------------------------------------------
// Operational context (Phase 2)
//
// Operational facts that cannot be inferred reliably from the server itself.
// They are supplied by the operator, never guessed. Absent values are
// explicitly null/unknown so "missing" is distinguishable from "false".
// ---------------------------------------------------------------------------

export type Environment = "production" | "staging" | "development" | "testing" | "unknown";

export type Criticality = "low" | "medium" | "high" | "critical" | "unknown";

export type InternetExposure = "direct" | "indirect" | "none" | "unknown";

/** Reusable server roles. A host can have several roles simultaneously. */
export type ServerRole =
  | "generic-server"
  | "web-server"
  | "application-server"
  | "database"
  | "container-host"
  | "kubernetes-node"
  | "bastion"
  | "monitoring"
  | "logging"
  | "file-server"
  | "directory-service"
  | "automation"
  | "unknown";

export type RoleConfidence = "confirmed" | "derived";

/**
 * A role assigned to the server. `confirmed` roles come from the operator;
 * `derived` roles are proposals backed by inventory evidence and must not be
 * treated as operational truth until confirmed.
 */
export interface RoleAssignment {
  role: ServerRole;
  confidence: RoleConfidence;
  source: string;
}

export type ManagementMethod =
  | "ssh"
  | "ssh-via-bastion"
  | "vpn"
  | "console"
  | "serial-console"
  | "out-of-band"
  | "rdp"
  | "web-console"
  | "automation"
  | "other";

export interface OperationalContext {
  schemaVersion: number;
  serverId: string;
  updatedAt: string;
  environment: Environment;
  criticality: Criticality;
  internetExposure: InternetExposure;
  roles: RoleAssignment[];
  management: {
    methods: ManagementMethod[];
    secondaryPathConfirmed: boolean | null;
    consoleAccess: boolean | null;
  };
  /** Operator-declared networks (CIDR). Empty when not declared. */
  networks: {
    administrative: string[];
    service: string[];
  };
  reboot: {
    allowed: boolean | null;
    maintenanceWindowAvailable: boolean | null;
  };
  highAvailability: boolean | null;
  operatorNotes: string | null;
}

// ---------------------------------------------------------------------------
// Control evaluation and planning (Phase 2)
// ---------------------------------------------------------------------------

export type ControlCategory =
  | "identity"
  | "privileged-access"
  | "ssh"
  | "network"
  | "firewall"
  | "services"
  | "packages"
  | "filesystem"
  | "kernel"
  | "logging"
  | "auditing"
  | "time"
  | "containers";

export type RiskLevel = "none" | "low" | "medium" | "high" | "critical" | "unknown";

export type ApplicabilityStatus =
  | "applicable"
  | "not-applicable"
  | "unknown"
  | "unsupported"
  | "requires-context";

/**
 * Explicit evaluation outcome. Deliberately richer than PASS/FAIL: a value
 * that is insecure-looking but operationally justified is not "non-compliant".
 */
export type ControlEvaluationStatus =
  | "compliant"
  | "non-compliant"
  | "not-applicable"
  | "unknown"
  | "requires-context"
  | "requires-review"
  | "blocked"
  | "unsupported"
  | "error";

/** A reference back into the inventory or context, never a duplicated copy. */
export interface EvidenceRef {
  inventoryPath: string;
  observed: string | null;
  note?: string;
}

export interface ApplicabilityDecision {
  status: ApplicabilityStatus;
  rationale: string;
  evidence: EvidenceRef[];
  missingContext: string[];
  confidence: Confidence;
}

export type PreconditionStatus = "satisfied" | "unsatisfied" | "unknown";

export interface Precondition {
  id: string;
  description: string;
  /** A critical precondition that is not satisfied blocks the control. */
  critical: boolean;
  status: PreconditionStatus;
  evidence: EvidenceRef[];
  missingContext: string[];
  reason: string | null;
}

export interface RiskAssessment {
  securityImpact: RiskLevel;
  availabilityRisk: RiskLevel;
  lockoutRisk: RiskLevel;
  operationalComplexity: RiskLevel;
  rationale: string;
}

/** Operational ordering buckets. Lower index = considered earlier. */
export type PlanPhase =
  | "prerequisites"
  | "foundational"
  | "logging-visibility"
  | "identity"
  | "services"
  | "network"
  | "access"
  | "disruptive";

/** A single evaluated control as persisted inside a plan. */
export interface PlannedControl {
  controlId: string;
  title: string;
  category: ControlCategory;
  phase: PlanPhase;
  phaseIndex: number;
  order: number;
  status: ControlEvaluationStatus;
  currentState: string | null;
  desiredState: string;
  applicability: ApplicabilityDecision;
  risk: RiskAssessment;
  preconditions: Precondition[];
  blockers: string[];
  missingContext: string[];
  evidence: EvidenceRef[];
  requiresApproval: boolean;
  reversible: boolean;
  tags: string[];
}

export type QuestionType = "boolean" | "single-choice" | "multi-choice" | "text" | "cidr-list";

/** A decision-changing question. Generated by the engine, not the LLM. */
export interface PlanningQuestion {
  id: string;
  prompt: string;
  reason: string;
  affectedControls: string[];
  type: QuestionType;
  options?: string[];
  /** Context field the answer populates, e.g. "management.secondaryPathConfirmed". */
  contextPath: string;
}

export interface PlanBlocker {
  controlId: string;
  reason: string;
  preconditionIds: string[];
}

export type PlanCounts = Record<ControlEvaluationStatus, number>;

export type PlanStatus =
  | "draft"
  | "review"
  | "approved"
  | "applying"
  | "completed"
  | "failed"
  | "rolled-back";

/** A hardening plan: evaluated controls plus everything needed for review. */
export interface HardeningPlan {
  schemaVersion: number;
  planId: string;
  serverId: string;
  inventoryId: string;
  /** Reference to the operational context revision used (updatedAt), if any. */
  contextUpdatedAt: string | null;
  generatedAt: string;
  profile: string;
  catalogVersion: string;
  controls: PlannedControl[];
  counts: PlanCounts;
  unresolvedQuestions: PlanningQuestion[];
  blockers: PlanBlocker[];
  warnings: string[];
  status: PlanStatus;
}

export type ChangeResult = "applied" | "failed" | "skipped" | "rolled-back";

/** Record of a single (future) change to a server. */
export interface ChangeRecord {
  schemaVersion: number;
  changeId: string;
  controlId: string;
  serverId: string;
  timestamp: string;
  target: string;
  before: string | null;
  after: string | null;
  result: ChangeResult;
  verificationId: string | null;
  rollbackId: string | null;
}

export type ExceptionScope = "server" | "control" | "parameter";

/** Documented operational exception to a control (not a workflow yet). */
export interface ExceptionRecord {
  schemaVersion: number;
  exceptionId: string;
  controlId: string;
  serverId: string;
  reason: string;
  scope: ExceptionScope;
  createdAt: string;
  expiresAt: string | null;
  acceptedRisk: string;
  evidence: string[];
}

export interface RollbackRecord {
  schemaVersion: number;
  rollbackId: string;
  changeId: string;
  serverId: string;
  timestamp: string;
  available: boolean;
  strategy: string | null;
  artifacts: string[];
  verificationId: string | null;
}

export interface VerificationResult {
  schemaVersion: number;
  verificationId: string;
  serverId: string;
  timestamp: string;
  target: string;
  check: string;
  expected: string;
  observed: string | null;
  passed: boolean | null;
  evidence: string[];
  error: string | null;
}

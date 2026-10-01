/**
 * Remediation contracts.
 *
 * A remediation knows, for one control id, how to preview, apply, verify and
 * roll back a change. Everything is code with fixed command argvs: no
 * remediation ever runs a shell or a caller-provided command.
 */
import type { CommandRunner } from "../exec";
import type {
  EvaluatedControl,
  OperationalContext,
  RiskAssessment,
  ServerInventory,
  VerificationResult,
} from "../models";

/** Filesystem locations the remediation engine writes to (overridable in tests). */
export interface SystemPaths {
  sshdConfig: string;
  sysctlConfDir: string;
  sysctlManagedFile: string;
  fstab: string;
}

export function defaultSystemPaths(): SystemPaths {
  return {
    sshdConfig: "/etc/ssh/sshd_config",
    sysctlConfDir: "/etc/sysctl.d",
    sysctlManagedFile: "/etc/sysctl.d/99-server-hardener.conf",
    fstab: "/etc/fstab",
  };
}

export interface RemediationContext {
  inventory: ServerInventory;
  context: OperationalContext;
  control: EvaluatedControl;
  storeRoot: string;
  runner: CommandRunner;
  paths: SystemPaths;
  hasRoot: boolean;
  now: () => string;
  /** Optional operator selection, e.g. an explicit service unit. */
  target?: string;
}

export interface FilePlan {
  path: string;
  willBackup: boolean;
}

export interface RemediationPreview {
  controlId: string;
  title: string;
  manual: boolean;
  manualReason: string | null;
  currentState: string | null;
  desiredState: string;
  steps: string[];
  files: FilePlan[];
  commands: string[];
  warnings: string[];
  risk: RiskAssessment;
  requiresRoot: boolean;
}

export interface RemediationApplyResult {
  changed: boolean;
  target: string;
  /** JSON string capturing state before/after, recorded in last-run.json. */
  before: string | null;
  after: string | null;
  backupIds: string[];
  verification: VerificationResult;
  strategy: string | null;
  reversible: boolean;
  message: string;
}

/** The previously applied change for a control, used to roll it back. */
export interface AppliedChange {
  controlId: string;
  target: string;
  before: string | null;
  after: string | null;
  backupIds: string[];
}

export interface Remediation {
  controlId: string;
  requiresRoot: boolean;
  manual: boolean;
  manualReason: string | null;
  preview: (ctx: RemediationContext) => Promise<RemediationPreview>;
  apply: (ctx: RemediationContext) => Promise<RemediationApplyResult>;
  verify: (ctx: RemediationContext) => Promise<VerificationResult>;
  rollback: (ctx: RemediationContext, previous: AppliedChange) => Promise<RemediationApplyResult>;
}

/** Build a manual-only remediation placeholder (no automatic change). */
export function manualRemediation(controlId: string, reason: string): Remediation {
  return {
    controlId,
    requiresRoot: false,
    manual: true,
    manualReason: reason,
    preview: async (ctx) => ({
      controlId,
      title: ctx.control.title,
      manual: true,
      manualReason: reason,
      currentState: ctx.control.currentState,
      desiredState: ctx.control.desiredState,
      steps: [`manual remediation required: ${reason}`],
      files: [],
      commands: [],
      warnings: [],
      risk: ctx.control.risk,
      requiresRoot: false,
    }),
    apply: async () => {
      throw new Error(`control ${controlId} requires manual remediation: ${reason}`);
    },
    verify: async (ctx) => ({
      verificationId: `ver-manual-${controlId.toLowerCase()}`,
      timestamp: ctx.now(),
      target: controlId,
      check: "manual remediation required",
      expected: ctx.control.desiredState,
      observed: null,
      passed: null,
      evidence: [reason],
      error: null,
    }),
    rollback: async () => {
      throw new Error(`control ${controlId} has no automatic rollback: ${reason}`);
    },
  };
}

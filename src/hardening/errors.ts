/**
 * Typed error hierarchy for the hardening framework.
 *
 * Every failure mode that the framework can produce has a dedicated error
 * class so that callers can branch on the error kind instead of parsing
 * message strings.
 */

export class HardeningError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** A document failed schema validation. `issues` lists human-readable paths. */
export class ValidationFailureError extends HardeningError {
  readonly issues: string[];

  constructor(message: string, issues: string[] = [], options?: { cause?: unknown }) {
    super(message, options);
    this.issues = issues;
  }
}

/** Persisted state is unreadable, corrupt, or incompatible. */
export class StateError extends HardeningError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** A persisted document declares a schema version we cannot handle. */
export class UnsupportedSchemaVersionError extends StateError {
  readonly found: number;
  readonly supported: number;

  constructor(found: number, supported: number) {
    super(`Unsupported schema version ${found}; this framework supports ${supported}`);
    this.found = found;
    this.supported = supported;
  }
}

/** An identifier or path attempted to escape the state directory. */
export class PathSafetyError extends StateError {
  constructor(message: string) {
    super(message);
  }
}

/** A command name/args failed the safety pre-checks (never executed). */
export class CommandSafetyError extends HardeningError {
  constructor(message: string) {
    super(message);
  }
}

/** A tool was called with arguments outside its declared contract. */
export class ToolArgumentError extends HardeningError {
  constructor(message: string) {
    super(message);
  }
}

/** A collection or orchestration step failed unexpectedly. */
export class DiscoveryError extends HardeningError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** Planning could not proceed (missing inventory, invalid context, ...). */
export class PlanningError extends HardeningError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

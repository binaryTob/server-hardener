/**
 * Typed error hierarchy. Callers branch on the class, never on message strings.
 */

export class HardeningError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** A document or value failed schema validation. `issues` lists offending paths. */
export class ValidationFailureError extends HardeningError {
  readonly issues: string[];

  constructor(message: string, issues: string[] = [], options?: { cause?: unknown }) {
    super(message, options);
    this.issues = issues;
  }
}

/** Local state (.server-hardener) is unreadable, corrupt, or unsafe. */
export class StateError extends HardeningError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** An identifier or path attempted to escape the local state directory. */
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

/** Assessment could not proceed (invalid context, unknown control, ...). */
export class AssessmentError extends HardeningError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** A target string is malformed or could enable command/option injection. */
export class TargetValidationError extends HardeningError {
  constructor(message: string) {
    super(message);
  }
}

/** A remote transport operation failed (connection, auth, host key, timeout). */
export class TransportError extends HardeningError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** No target selected for the session and none was provided. */
export class NoTargetError extends HardeningError {
  constructor(message = "No target selected. Connect to a server first.") {
    super(message);
  }
}

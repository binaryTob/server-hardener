/**
 * Shared helpers for Linux parsers.
 *
 * Parsers are pure functions: raw command/file output in, domain model out.
 * They never execute commands, touch the filesystem, or persist anything,
 * which makes them directly testable against fixtures.
 */

import type { CommandOutcome } from "../../exec";
import type { FileRead, ReadFailureStatus } from "../../fsio";
import type { CollectionStatus, Section } from "../../models";

/** Human-readable label for a failed source, used in section notes. */
export function failureNote(display: string, outcome: CommandOutcome): string | null {
  switch (outcome.status) {
    case "unavailable":
      return `${display}: not available on this system`;
    case "insufficient-permissions":
      return `${display}: insufficient permissions to run`;
    case "timeout":
      return `${display}: timed out`;
    case "error":
      return `${display}: failed (exit ${outcome.exitCode ?? "?"}) ${trimForNote(outcome.stderr)}`;
    case "ok":
      return null;
  }
}

export function trimForNote(text: string): string {
  const clean = text.trim().replace(/\s+/g, " ");
  if (!clean) return "";
  return clean.length > 160 ? `${clean.slice(0, 160)}...` : clean;
}

/**
 * Status of a primary source: a failed primary tool is a real gap for its
 * section (unavailable / insufficient-permissions / error), not a silent skip.
 */
export function primaryStatus(outcome: CommandOutcome): CollectionStatus {
  switch (outcome.status) {
    case "ok":
      return "success";
    case "unavailable":
      return "unavailable";
    case "insufficient-permissions":
      return "insufficient-permissions";
    case "timeout":
    case "error":
      return "error";
  }
}

/**
 * Status of an auxiliary source: its absence is tolerable when another source
 * covers the same field (e.g. hostnamectl without systemd). Failures are
 * downgraded to a note, never to a section-level error.
 */
export function auxiliaryStatus(outcome: CommandOutcome): CollectionStatus {
  return outcome.status === "ok" ? "success" : "unavailable";
}

export function fileReadStatus(read: FileRead): CollectionStatus {
  if (read.ok) return "success";
  return read.status === "insufficient-permissions" ? "insufficient-permissions" : "unavailable";
}

export function fileFailureNote(path: string, status: ReadFailureStatus): string | null {
  if (status === "insufficient-permissions") {
    return `${path}: insufficient permissions to read`;
  }
  return `${path}: not available`;
}

/**
 * Combine per-source statuses into a section status:
 * - a hard "error" always dominates;
 * - a denied/failed source degrades to "partial" when at least one other
 *   source of the section succeeded (e.g. users: passwd ok, /etc/shadow
 *   denied -> partial), or to the failure status when nothing succeeded
 *   (e.g. sockets: only source denied -> insufficient-permissions);
 * - otherwise "partial" / "success".
 */
export function combinedStatus(statuses: CollectionStatus[]): CollectionStatus {
  if (statuses.includes("error")) return "error";
  const hasSuccess = statuses.includes("success");
  if (statuses.includes("insufficient-permissions")) {
    return hasSuccess ? "partial" : "insufficient-permissions";
  }
  if (statuses.includes("unavailable")) {
    return hasSuccess ? "partial" : "unavailable";
  }
  if (statuses.includes("partial")) return "partial";
  return "success";
}

/** Build a section, dropping empty notes. */
export function makeSection<T>(status: CollectionStatus, data: T | null, notes?: string[]): Section<T> {
  const cleanNotes = notes?.filter((n) => n !== null && n.length > 0);
  if (cleanNotes && cleanNotes.length > 0) {
    return { status, data, notes: cleanNotes };
  }
  return { status, data };
}

/** Stdout text of an outcome (empty string when not ok). */
export function stdoutOf(outcome: CommandOutcome): string {
  return outcome.status === "ok" ? outcome.stdout : "";
}

/** First stdout line, trimmed; null when absent. */
export function firstLine(outcome: CommandOutcome): string | null {
  const text = stdoutOf(outcome).trim();
  if (!text) return null;
  return text.split("\n")[0] ?? null;
}

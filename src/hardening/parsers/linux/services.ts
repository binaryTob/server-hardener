/**
 * Parsers for services (systemd).
 *
 * The model is service-manager agnostic (`ServiceManager` is an open set);
 * only the systemd implementation exists in Phase 1. On systems without
 * systemd the section reports `unsupported` instead of failing.
 */

import type { LinuxRaw } from "../../collectors/linux";
import type { InventoryService, Section, ServicesData } from "../../models";
import { combinedStatus, failureNote, makeSection, primaryStatus } from "./shared";

/** Parse `systemctl list-units --type=service --all` lines. */
export function parseSystemctlUnits(text: string): Map<string, { active: string; sub: string }> {
  const units = new Map<string, { active: string; sub: string }>();
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const name = tokens[0] ?? "";
    // unit, load, active, sub, description...
    if (!name.endsWith(".service") || tokens.length < 4) continue;
    units.set(name, { active: tokens[2] ?? "", sub: tokens[3] ?? "" });
  }
  return units;
}

/** Parse `systemctl list-unit-files --type=service` lines. */
export function parseSystemctlUnitFiles(text: string): Map<string, string> {
  const states = new Map<string, string>();
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const name = tokens[0] ?? "";
    if (!name.endsWith(".service") || tokens.length < 2) continue;
    states.set(name, tokens[1] ?? "");
  }
  return states;
}

function mapActive(value: string): boolean | null {
  if (value === "active") return true;
  if (value === "inactive" || value === "failed") return false;
  return null;
}

function mapEnabled(state: string | undefined): boolean | null {
  if (state === undefined) return null;
  if (state === "enabled" || state === "enabled-runtime") return true;
  if (state === "disabled" || state === "masked") return false;
  return null;
}

export function parseServices(raw: LinuxRaw["services"]): Section<ServicesData> {
  const notes: string[] = [];

  if (!raw.systemdRunning) {
    notes.push("systemd is not the running init system on this host");
    const systemctlNote = failureNote(raw.systemctlUnits.display, raw.systemctlUnits.outcome);
    if (systemctlNote) notes.push(systemctlNote);
    return makeSection("unsupported", { serviceManager: "unknown", services: [] }, notes);
  }

  const unitsOk = raw.systemctlUnits.outcome.status === "ok";
  const unitFilesOk = raw.systemctlUnitFiles.outcome.status === "ok";
  const unitStates = unitsOk ? parseSystemctlUnits(raw.systemctlUnits.outcome.stdout) : null;
  const fileStates = unitFilesOk ? parseSystemctlUnitFiles(raw.systemctlUnitFiles.outcome.stdout) : null;

  for (const raw_ of [raw.systemctlUnits, raw.systemctlUnitFiles]) {
    const note = failureNote(raw_.display, raw_.outcome);
    if (note) notes.push(note);
  }

  const services: InventoryService[] = [];
  const names = new Set<string>([...(unitStates?.keys() ?? []), ...(fileStates?.keys() ?? [])]);
  for (const name of names) {
    const unitState = unitStates?.get(name);
    const fileState = fileStates?.get(name);
    services.push({
      name,
      enabled: mapEnabled(fileState),
      active: unitState ? mapActive(unitState.active) : null,
      subState: unitState ? unitState.sub : null,
      startup: fileState ?? null,
    });
  }
  services.sort((a, b) => a.name.localeCompare(b.name));

  const status = combinedStatus([
    unitsOk ? "success" : primaryStatus(raw.systemctlUnits.outcome),
    unitFilesOk ? "success" : primaryStatus(raw.systemctlUnitFiles.outcome),
  ]);

  return makeSection(
    status,
    {
      serviceManager: "systemd",
      services,
    },
    notes,
  );
}

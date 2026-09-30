/**
 * Parsers for installed packages (dpkg-query / rpm).
 *
 * Local queries only: no repository access, no updates, no network.
 */

import type { LinuxRaw } from "../../collectors/linux";
import type { InventoryPackage, PackageManager, PackagesData, Section } from "../../models";
import { failureNote, makeSection } from "./shared";

/** Parse dpkg-query tab-separated output: name, version, architecture. */
export function parseDpkgQuery(text: string): InventoryPackage[] {
  const packages: InventoryPackage[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trimEnd();
    if (!trimmed) continue;
    const fields = trimmed.split("\t");
    const name = fields[0];
    if (!name) continue;
    packages.push({
      manager: "dpkg",
      name,
      version: fields[1] ?? null,
      architecture: fields[2] ?? null,
    });
  }
  return packages;
}

/** Parse rpm tab-separated output: name, version-release, architecture. */
export function parseRpmQuery(text: string): InventoryPackage[] {
  const packages: InventoryPackage[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trimEnd();
    if (!trimmed) continue;
    const fields = trimmed.split("\t");
    const name = fields[0];
    if (!name) continue;
    packages.push({
      manager: "rpm",
      name,
      version: fields[1] ?? null,
      architecture: fields[2] ?? null,
    });
  }
  return packages;
}

export function parsePackages(raw: LinuxRaw["packages"]): Section<PackagesData> {
  const notes: string[] = [];
  const managersDetected: PackageManager[] = [];
  const packages: InventoryPackage[] = [];

  const dpkgOk = raw.dpkgQuery.outcome.status === "ok";
  const rpmOk = raw.rpmQuery.outcome.status === "ok";

  if (dpkgOk) {
    managersDetected.push("dpkg");
    packages.push(...parseDpkgQuery(raw.dpkgQuery.outcome.stdout));
  }
  if (rpmOk) {
    managersDetected.push("rpm");
    packages.push(...parseRpmQuery(raw.rpmQuery.outcome.stdout));
  }

  if (!dpkgOk && !rpmOk) {
    for (const raw_ of [raw.dpkgQuery, raw.rpmQuery]) {
      const note = failureNote(raw_.display, raw_.outcome);
      if (note) notes.push(note);
    }
    const anyPermissionIssue =
      raw.dpkgQuery.outcome.status === "insufficient-permissions" ||
      raw.rpmQuery.outcome.status === "insufficient-permissions";
    const anyHardFailure =
      raw.dpkgQuery.outcome.status === "error" ||
      raw.dpkgQuery.outcome.status === "timeout" ||
      raw.rpmQuery.outcome.status === "error" ||
      raw.rpmQuery.outcome.status === "timeout";
    return makeSection(
      anyHardFailure ? "error" : anyPermissionIssue ? "insufficient-permissions" : "unavailable",
      { managersDetected, packages },
      notes,
    );
  }

  if (!dpkgOk) {
    const note = failureNote(raw.dpkgQuery.display, raw.dpkgQuery.outcome);
    if (note) notes.push(note);
  }
  if (!rpmOk) {
    const note = failureNote(raw.rpmQuery.display, raw.rpmQuery.outcome);
    if (note) notes.push(note);
  }

  return makeSection("success", { managersDetected, packages }, notes);
}

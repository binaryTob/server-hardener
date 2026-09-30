/**
 * Parsers for time discovery: timedatectl, NTP daemon inference.
 */

import { type LinuxRaw, OBSERVED_UNITS } from "../../collectors/linux";
import type { Section, TimeData } from "../../models";
import { failureNote, makeSection, primaryStatus } from "./shared";

const UNIT_INDEX = new Map<string, number>(OBSERVED_UNITS.map((unit, index) => [unit, index]));

/** Parse `timedatectl show --property=...` key=value output. */
export function parseTimedatectl(text: string): {
  timezone: string | null;
  ntp: boolean | null;
  ntpSynchronized: boolean | null;
} {
  let timezone: string | null = null;
  let ntp: boolean | null = null;
  let ntpSynchronized: boolean | null = null;
  for (const line of text.split("\n")) {
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    if (key === "Timezone" && value) timezone = value;
    else if (key === "NTP") ntp = yesNo(value);
    else if (key === "NTPSynchronized") ntpSynchronized = yesNo(value);
  }
  return { timezone, ntp, ntpSynchronized };
}

function yesNo(value: string): boolean | null {
  if (value === "yes" || value === "1" || value === "true") return true;
  if (value === "no" || value === "0" || value === "false") return false;
  return null;
}

const NTP_UNITS: { unit: string; label: string }[] = [
  { unit: "systemd-timesyncd.service", label: "systemd-timesyncd" },
  { unit: "chronyd.service", label: "chrony" },
  { unit: "chrony.service", label: "chrony" },
  { unit: "ntpd.service", label: "ntp" },
  { unit: "ntp.service", label: "ntp" },
];

export function parseTime(
  raw: LinuxRaw["time"],
  services: LinuxRaw["services"],
  collectedAt: string,
): Section<TimeData> {
  const notes: string[] = [];
  const ok = raw.timedatectlShow.outcome.status === "ok";
  const timedatectl = ok
    ? parseTimedatectl(raw.timedatectlShow.outcome.stdout)
    : { timezone: null, ntp: null, ntpSynchronized: null };
  if (!ok) {
    const note = failureNote(raw.timedatectlShow.display, raw.timedatectlShow.outcome);
    if (note) notes.push(note);
  }

  // NTP implementation is inferred from active/enabled units: derived, not
  // directly observed as a single "the NTP daemon is X" source.
  let ntpImplementation: TimeData["ntpImplementation"] = {
    value: null,
    source: "systemctl is-active/is-enabled (systemd-timesyncd, chrony, ntp)",
    confidence: "unknown",
    collectedAt,
  };
  if (services.systemdRunning) {
    const activeLines = services.isActive.outcome.stdout.trim().split("\n");
    const enabledLines = services.isEnabled.outcome.stdout.trim().split("\n");
    const detected: string[] = [];
    for (const { unit, label } of NTP_UNITS) {
      const idx = UNIT_INDEX.get(unit);
      if (idx === undefined || activeLines[idx] === undefined || enabledLines[idx] === undefined) {
        continue;
      }
      const active = (activeLines[idx] ?? "").trim() === "active";
      const enabled = (enabledLines[idx] ?? "").trim();
      if (active || enabled === "enabled" || enabled === "enabled-runtime") {
        if (!detected.includes(label)) detected.push(label);
      }
    }
    if (detected.length > 0) {
      ntpImplementation = { ...ntpImplementation, value: detected.join(", "), confidence: "derived" };
    }
  }

  return makeSection(
    ok ? "success" : primaryStatus(raw.timedatectlShow.outcome),
    {
      timezone: timedatectl.timezone,
      ntpImplementation,
      ntpSynchronized: timedatectl.ntpSynchronized,
    },
    notes,
  );
}

/**
 * Text configuration editing helpers (pure string functions).
 *
 * sshd_config directives, the managed sysctl drop-in block and /etc/fstab
 * option lists. Pure so they are trivially testable; the caller writes the
 * result atomically after backing the file up.
 */

export const MANAGED_BEGIN = "# BEGIN server-hardener (managed)";
export const MANAGED_END = "# END server-hardener (managed)";
const MANAGED_HEADER = "# Managed by server-hardener. Local edits inside the block are overwritten.";

const MANAGED_BLOCK_RE = new RegExp(
  `${escapeRegExp(MANAGED_BEGIN)}\\n[\\s\\S]*?${escapeRegExp(MANAGED_END)}\\n?`,
  "m",
);

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// --- sshd_config -----------------------------------------------------------

/** Read the first active (uncommented) value of a directive. */
export function readDirective(text: string, key: string): string | null {
  const re = new RegExp(`^\\s*${key}\\b[ \\t]+(\\S+)`, "im");
  const match = re.exec(text);
  return match ? (match[1] ?? null) : null;
}

/**
 * Set (replace or append) an active directive. Commented lines are left alone.
 */
export function upsertDirective(
  text: string,
  key: string,
  value: string,
): { content: string; previous: string | null; changed: boolean } {
  const previous = readDirective(text, key);
  const lineRe = new RegExp(`^(\\s*)${key}\\b[ \\t]+\\S+.*$`, "im");
  if (lineRe.test(text)) {
    if (previous === value) return { content: text, previous, changed: false };
    return { content: text.replace(lineRe, `$1${key} ${value}`), previous, changed: true };
  }
  const separator = text.endsWith("\n") || text.length === 0 ? "" : "\n";
  return { content: `${text}${separator}${key} ${value}\n`, previous, changed: true };
}

// --- sysctl managed drop-in ------------------------------------------------

export interface SysctlEntry {
  key: string;
  value: string;
}

/** Build the managed sysctl drop-in content, replacing an existing block. */
export function buildManagedSysctlFile(existing: string | null, entries: SysctlEntry[]): string {
  const block = [MANAGED_BEGIN, ...entries.map((e) => `${e.key} = ${e.value}`), MANAGED_END].join("\n");
  if (existing === null) {
    return `# sysctl drop-in managed by server-hardener\n${block}\n`;
  }
  if (MANAGED_BLOCK_RE.test(existing)) {
    return existing.replace(MANAGED_BLOCK_RE, `${block}\n`);
  }
  return `${existing.replace(/\s*$/, "")}\n\n${block}\n`;
}

/** Remove the managed block; returns null when the file becomes empty. */
export function removeManagedSysctlBlock(existing: string | null): {
  content: string | null;
  removed: boolean;
} {
  if (existing === null || !MANAGED_BLOCK_RE.test(existing)) {
    return { content: existing, removed: false };
  }
  const stripped = existing
    .replace(MANAGED_BLOCK_RE, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  if (
    stripped === "" ||
    stripped === MANAGED_HEADER ||
    stripped === "# sysctl drop-in managed by server-hardener"
  ) {
    return { content: null, removed: true };
  }
  return { content: `${stripped}\n`, removed: true };
}

// --- /etc/fstab ------------------------------------------------------------

/** Current options for a mountpoint, or null when it is not in fstab. */
export function readFstabOptions(text: string, mountpoint: string): string[] | null {
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const fields = trimmed.split(/\s+/);
    if (fields[1] === mountpoint && fields[3]) {
      return fields[3].split(",").filter((o) => o.length > 0);
    }
  }
  return null;
}

/** Add options to the fstab entry for a mountpoint with minimal reformatting. */
export function setFstabOptions(
  text: string,
  mountpoint: string,
  addOptions: string[],
): { content: string; previousOptions: string[] | null; changed: boolean } {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const commentIndex = trimmed.indexOf("#");
    const core = (commentIndex >= 0 ? trimmed.slice(0, commentIndex) : trimmed).trim().split(/\s+/);
    const comment = commentIndex >= 0 ? trimmed.slice(commentIndex) : "";
    if (core[1] !== mountpoint || !core[3]) continue;
    const previous = core[3].split(",").filter((o) => o.length > 0);
    const merged = [...previous];
    for (const option of addOptions) if (!merged.includes(option)) merged.push(option);
    const updated = [...core];
    updated[3] = merged.join(",");
    const rebuilt = `${updated.join(" ")}${comment ? ` ${comment}` : ""}`;
    if (rebuilt === trimmed) return { content: text, previousOptions: previous, changed: false };
    const next = [...lines];
    next[i] = rebuilt;
    return { content: next.join("\n"), previousOptions: previous, changed: true };
  }
  return { content: text, previousOptions: null, changed: false };
}

# Architecture — Server Hardening Framework (Phase 1)

## 1. Objectives

Build the **foundation** of an interactive server hardening framework whose
final purpose is to harden servers *safely, traceably, reversibly and
interactively*, favouring security **without** causing service outages or loss
of administrative access.

Phase 1 delivers exactly one capability:

> Produce a **reliable, persistent, validated and safe inventory** of a
> server's current state — with **zero modifications** to the server.

Everything else (controls, plans, changes, rollback, verification) is defined
as **contracts only**, so later phases can implement them without redesigning
the domain.

### Project philosophy (enforced structurally, not just by convention)

1. Never modify a server before understanding its current state.
2. Never assume a service, port, user or setting is unnecessary merely because
   it looks insecure.
3. Security and availability are equally important.
4. Future changes must be explicit, traceable, verifiable and reversible when
   technically possible.
5. Every future recommendation must preserve the evidence that motivated it.
6. **Phase 1 executes no remediation whatsoever.**
7. No destructive commands, no configuration changes, no package installs or
   removals.
8. Discovery is strictly read-only.

## 2. Trust boundaries

```
┌──────────────────────────────────────────────────────────────────────┐
│ LLM / agent / human operator                                          │
│   - can only invoke bounded tool actions (no free-form shell)         │
├──────────────────────────────────────────────────────────────────────┤
│ OpenCode custom tools                                                 │
│   hardening_inventory  (collect | show | validate)                    │
│   hardening_state      (status | list-inventories | load-inventory |  │
│                         validate-state)                               │
│   - validate every argument; reject unknown keys; reject traversal    │
├──────────────────────────────────────────────────────────────────────┤
│ Application core (src/hardening)                                      │
│   collector → parser → model → validation → state                     │
│   - commands are hardcoded argv; no shell; timeouts; output limits    │
├──────────────────────────────────────────────────────────────────────┤
│ Host                                                                  │
│   - read-only inspection commands and well-known system files only    │
└──────────────────────────────────────────────────────────────────────┘
```

Key boundary property: **the LLM never supplies a command string.** The only
command text that can reach the host is the fixed argv hardcoded in
`src/hardening/collectors/linux.ts`.

## 3. Architectural layers

```
src/hardening/
├── models.ts                 domain models (inventory + future contracts)
├── errors.ts                 typed error hierarchy
├── exec.ts                   CommandRunner: safe argv execution (no shell)
├── fsio.ts                   FileReader: bounded read-only file access
├── collectors/linux.ts       fixed, read-only Linux commands -> raw results
├── parsers/linux/*.ts        pure functions: raw -> domain sections
├── inventory.ts              orchestrator + summary (no persistence)
├── validation.ts             zod schemas + validators (single schema gate)
└── state.ts                  server-id derivation, atomic persistence, listing
```

Data always flows one way:

```
Collector ──▶ raw result ──▶ Parser ──▶ domain model ──▶ validation ──▶ storage
   (I/O)        (strings)     (pure)      (typed)         (zod)        (atomic)
```

The split is deliberate: **parsers are pure and fixture-testable without
executing anything**.

### Collector / parser separation

- Collectors run commands and read well-known files; they never parse.
- Parsers transform raw text into typed sections; they never execute or read.
- A failing parser degrades **one section** to `error`; it never aborts the
  inventory (`safeSection` in `inventory.ts`).

## 4. Domain models

### ServerInventory

`ServerInventory` is the single observable-state document. Every section is
wrapped in `Section<T>`:

```ts
interface Section<T> {
  status: "success" | "partial" | "unsupported" |
          "insufficient-permissions" | "unavailable" | "error";
  data: T | null;
  error?: string;
  notes?: string[];
}
```

Sections: `identity`, `operatingSystem`, `network`, `sockets`, `users`,
`privilegedAccess`, `services`, `packages`, `securityControls`, `filesystems`,
`time`, `containers`.

### Evidence and provenance

Fields prone to inference are wrapped so the question *"where did this come
from?"* is always answerable:

```ts
interface Evidence<T> {
  value: T | null;
  source: string;                       // command or file
  confidence: "observed" | "derived" | "unknown";
  collectedAt: string;
}
```

Used for: virtualization, account lock state, account type heuristic, firewall
implementation and NTP implementation. Not every field is wrapped — only those
where inference is possible — to keep the model workable.

Notably:

- `users[].accountType` is **always** `derived`: it is a heuristic over UID and
  shell, and a UID ≥ 1000 never proves a human account.
- `users[].locked` is `observed` only when `/etc/shadow` was readable;
  otherwise `unknown`. It is never guessed.
- `firewall.implementation` is `derived` from unit + binary evidence; a
  wildcard listener is not evidence of an active firewall.

### CollectionStatus semantics

Each section reports independently, so the failure of one collection never
aborts the rest. The orchestrator can produce, for example:

```
network: success
users: partial            (shadow unreadable -> lock state unknown)
firewall: insufficient-permissions
packages: success
```

Statuses are combined with `combinedStatus`: `error` > `insufficient-permissions`
> `unavailable` (→ `partial` if any source succeeded) > `partial` > `success`.

### Future-phase contracts (defined, not implemented)

`hardening_control`, `HardeningPlan` (`draft`…`rolled-back`), `ChangeRecord`,
`ExceptionRecord`, `RollbackRecord`, `VerificationResult`. Their zod schemas
exist in `validation.ts`; nothing populates or applies them in Phase 1.

## 5. Discovery flow

```
runDiscovery()
  ├─ platform != linux?  ──▶ every section = "unsupported" (no commands run)
  └─ collectLinuxRaw()
        ├─ hardcoded argv commands via CommandRunner (no shell, timeout, capped)
        ├─ reads /etc/os-release, /etc/machine-id, /etc/passwd, /etc/group,
        │        /etc/shadow, /etc/resolv.conf, /proc/mounts, AppArmor param
        └─ binary presence checks (existence only: docker, nft, ufw, wazuh-control, …)
  ├─ parsers per section  (pure)
  ├─ socket executable enrichment via /proc/<pid>/exe (best effort)
  └─ serverId derivation (hashed machine-id)
```

Then, in the tool/CLI layer: `validateServerInventory()` → `saveInventory()`.

### Linux sources

`hostnamectl`, `hostname`, `uname`, `systemd-detect-virt`, `ip addr`,
`ip route`, `ss -tulpn`, `sudo --version`, `systemctl` (list-units,
list-unit-files, is-active, is-enabled), `dpkg-query`, `rpm`, `getenforce`,
`findmnt`, `df`, `lsblk`, `timedatectl show`, and `--version` probes for
container runtimes. None of these mutate state; missing tools degrade
gracefully (no installation is ever attempted).

## 6. Persistence

```
state/
└── <server-id>/
    ├── inventory.json
    ├── plans/
    ├── changes/
    ├── exceptions/
    ├── rollbacks/
    └── verification/
```

- **Stable server-id**: `srv-` + first 16 hex chars of `SHA-256("machine-id:" + machine-id)`.
  The raw machine-id never appears in the id. If `/etc/machine-id` is
  unavailable, a hostname-based fallback is used and flagged `stable: false`.
- **Atomic writes**: validate → write `inventory.json.tmp-<pid>-<ts>` (mode
  `0600`) → `rename()` over the target. A partially written document can never
  be observed, and failed writes leave no `inventory.json` and no temp files.
- **Path safety**: ids must match `^[a-z0-9][a-z0-9-]{3,63}$`; every resolved
  path is re-checked to stay inside the state root, rejecting `../../etc`,
  `../server`, `/tmp/foo`, etc.
- **Schema versioning**: every main document carries `"schemaVersion": 1`;
  incompatible versions raise `UnsupportedSchemaVersionError`. The architecture
  is ready for migrations, but no migration framework exists yet.

## 7. Error handling

Typed errors in `errors.ts`:

- `ValidationFailureError` (with per-path `issues`)
- `StateError`, `UnsupportedSchemaVersionError`, `PathSafetyError`
- `CommandSafetyError`, `ToolArgumentError`
- `DiscoveryError`

Rules: no silent coercion; a single collection failure degrades its own
section; a total collector failure degrades every section to `error` rather
than throwing the inventory away.

## 8. Security restrictions

- Discovery executes **only** fixed argv commands defined in code; there is no
  `run_shell(userString)` interface anywhere.
- No shell is used (`execFile`, `shell: false`); metacharacters in args are
  literal.
- Every command has a timeout and an output size limit.
- No `sudo` is run; when information requires privileges, the section reports
  `insufficient-permissions` instead of failing.
- `sudoers` **contents** are never read or stored — only path existence.
- `/etc/shadow` is read (when readable) solely to derive lock state; hashes are
  never persisted. SSH private keys, tokens, environment variables and personal
  files are never read.
- Persisted state is git-ignored; only directory placeholders are committed.

## 9. What belongs to Phase 1 — and what does not

**In scope:** domain models, inventory, persistence, validation, main agent,
discovery skill, controlled tools, tests, architecture docs.

**Out of scope (contracts may exist; implementations must not):** CIS benchmark
engine, OpenSCAP, SSH/firewall/PAM/sysctl hardening, filesystem remediation,
package upgrades, Wazuh configuration, rollback execution, hardening profiles,
scoring, full Windows discovery, penetration testing.

## 10. Future extension

- **Windows/BSD**: add a collector + parsers per platform behind the existing
  `Section`/`Evidence` contracts; `OSFamily` is already an open set. No Linux
  assumption is baked into models, validation or storage.
- **Hardening**: controls produce `HardeningPlan`s (approval-gated) whose
  `ChangeRecord`s carry before/after evidence and a `RollbackRecord`; each
  change is verified with `VerificationResult`. Exceptions capture documented,
  accepted risks (e.g. "/tmp cannot use noexec because Application X runs
  temporary scripts"). None of this is implemented in Phase 1.

## 11. Testing

| Suite | Covers |
| --- | --- |
| `parsers.test.ts` | os-release, ip addr/route, resolv.conf, ss, systemctl, dpkg/rpm, findmnt/df/lsblk, passwd/group/shadow, timedatectl |
| `inventory.test.ts` | complete, partial (shadow denied), missing command, insufficient-permissions, unknown data, total collector failure, non-Linux, no-secrets |
| `persistence.test.ts` | write/read, layout, corruption, schema version, atomicity, permissions, traversal, listing/latest |
| `security.test.ts` | no arbitrary shell, arg rejection, traversal rejection, tool contracts |

All tests are deterministic and use fakes/fixtures; no real system command runs
in the suite.

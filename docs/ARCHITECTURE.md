# Architecture — Server Hardening Framework

> Phase 1: read-only discovery and a validated, persistent `ServerInventory`.
> Phase 2: deterministic planning — turn `ServerInventory` + `OperationalContext`
> into a draft `HardeningPlan`, still with **zero changes to the server**.

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

---

# Phase 2 — Planning

Phase 2 answers, deterministically and auditably:

> which controls apply, what their state is, what changing them would risk,
> what preconditions exist, what information is missing, and in what order they
> should be considered.

It does **not** apply anything. Execution begins in a later phase.

## 12. Pipeline

```
             Server
               ↓
          Discovery                    (Phase 1, read-only)
               ↓
        ServerInventory ─────────────┐
               │                     │
               ↓                     ↓
       OperationalContext       ControlCatalog
               │                     │
               └──────────┬──────────┘
                          ↓
                 Applicability
                          ↓
                   Risk Engine
                          ↓
                 Preconditions
                          ↓
                  HardeningPlan
                          ↓
                     REVIEW
```

Data flows one way. All four engines are pure functions over
`(ServerInventory, OperationalContext, ControlDefinition)`; no engine executes a
command or reads the host.

## 13. Trust boundary between the LLM and the engine

This is the central Phase 2 design rule:

> The **engine** decides applicability, compliance, risk, preconditions,
> blockers and ordering. The **LLM** gathers missing context and explains the
> result. The LLM never decides whether a control is compliant or risky.

Concretely:

- Control definitions are **code** (`src/hardening/controls/*.ts`) whose
  `applicability`, `assess`, `adjustRisk` and `preconditions` are pure
  functions. The model cannot alter them through prompts or tool arguments.
- Tool arguments are bounded: `hardening_context` writes only schema-validated
  context paths; `hardening_plan` only generates/reads/validates plans.
  Neither accepts a command, a file path, or an arbitrary write.
- The context is operator-supplied truth, never inferred by the model.

## 14. OperationalContext

Operational facts that cannot be inferred reliably from the server. Stored at
`state/<server-id>/context.json` (schema-validated, atomic, path-safe).

- `environment`, `criticality`, `internetExposure`, `highAvailability`
- `roles`: `RoleAssignment[]` with `confidence: "confirmed" | "derived"`.
  Detection only **proposes** derived roles from inventory evidence; the
  operator confirms or corrects them.
- `management`: `methods`, `secondaryPathConfirmed`, `consoleAccess`
- `networks`: `administrative`, `service` (CIDR)
- `reboot`: `allowed`, `maintenanceWindowAvailable`
- `operatorNotes`

Absent values are explicit (`null` / `unknown` / `[]`), so "missing" is never
confused with "false". `contextCompleteness()` lists the decision-critical
fields.

## 15. Control catalog

`src/hardening/controls/` — one module per domain (`ssh`, `identity`,
`privileged`, `services`, `firewall`, `network`, `logging`, `auditing`, `time`,
`kernel`, `filesystem`, `packages`, `containers`), aggregated by `catalog.ts`
with a `catalogVersion`. ~40 controls. Each definition declares metadata
(category, phase, platform, desired state, approval, reversibility,
references, tags) plus its pure evaluation functions. No proprietary benchmark
text is copied; controls are expressed from public guidance.

## 16. Evaluation states

`compliant`, `non-compliant`, `not-applicable`, `unknown`,
`requires-context`, `requires-review`, `blocked`, `unsupported`, `error`.

Deliberately richer than PASS/FAIL: a value that looks insecure but is
operationally justified is not "non-compliant". Missing evidence yields
`unknown`; missing operational truth yields `requires-context`; human judgement
yields `requires-review`.

## 17. Applicability engine

`decideApplicability()` gates on `operatingSystem.family` first (→
`unsupported`/`unknown`), then delegates to the control's `applicability`. It
distinguishes "no SSH server" (`not-applicable`) from "SSH state could not be
read" (`unknown`).

## 18. Risk engine

`assessRisk()` starts from the control's context-independent `baseRisk` and lets
the control adjust for context. Levels are explicit
(`none|low|medium|high|critical|unknown`); **no numeric score exists**. The same
control carries different risk on different hosts. Example: disabling SSH
password authentication is `lockout=low` when a secondary management path and
console access are confirmed, and `lockout=critical` when neither exists.

## 19. Precondition engine

Controls declare preconditions (`alternative-admin-user`,
`privilege-escalation-available`, `secondary-management-path`,
`console-access-confirmed`, ...). Status is `satisfied | unsatisfied | unknown`.
A **critical unsatisfied precondition blocks the control** (not merely "risky");
a critical unknown precondition with missing context surfaces as
`requires-context`, and without a question path as `blocked`.

## 20. Plan generator and ordering

`generatePlan()` evaluates the catalog, then orders controls by
`(phaseIndex, declared order, controlId)`:

```
prerequisites → foundational → logging-visibility → identity →
services → network → access → disruptive
```

Deterministic: same inventory + context + catalog ⇒ identical evaluations and
order. Only ids/timestamps vary (injectable). The plan stores evaluated controls,
counts by state, unresolved questions, blockers and warnings, with status
`draft`. Questions are generated **only** for context the engine actually
needed, each listing the controls it affects.

## 21. Evidence linkage

Every conclusion references the inventory/context by path (`EvidenceRef`), e.g.
`securityControls.data.firewall.active`. The full inventory is never duplicated
inside a plan; references and observed values only.

## 22. Persistence (Phase 2 additions)

```
state/<server-id>/
├── inventory.json
├── context.json
└── plans/<plan-id>.json
```

Same guarantees as Phase 1: validated before write, atomic rename, path-safe
identifiers (`SERVER_ID_PATTERN`, `PLAN_ID_PATTERN`), `schemaVersion: 1`.
Existing inventories remain valid.

## 23. Tools (Phase 2)

- `hardening_context` — `show` / `set` (values keyed by context path) /
  `answer` (by generated question id) / `validate`.
- `hardening_plan` — `generate` / `show` / `validate` / `explain-control`.

Both reject unknown arguments and traversal ids; neither can run a command or
write outside `state/`.

## 24. Testing (Phase 2)

| Suite | Covers |
| --- | --- |
| `context.test.ts` | valid/invalid/partial context, role proposals, answers, persistence, corruption, schema mismatch |
| `applicability.test.ts` | applicable / not-applicable / unknown / unsupported / requires-context |
| `risk.test.ts` | same control, different risk by context (SSH password auth) |
| `preconditions.test.ts` | satisfied / unsatisfied / unknown; critical unsatisfied → blocked |
| `plan.test.ts` | determinism, ordering, counts, questions, blockers, unknowns, partial inventory, catalog integrity |
| `planning-security.test.ts` | bounded tool args, no shell, traversal rejection, no writes outside state |

## 25. What Phase 2 does not do

No remediation, no configuration changes (firewall, SSH, services, users,
packages, sysctl), no approval workflow, no execution/rollback/verification, no
scoring. Controls whose evidence is not yet collected (SSH config, sysctl) are
reported as `unknown` — never invented — and become evaluable when collection is
extended.

## 26. Future extension

- **Execution**: approved plans produce `ChangeRecord`s with before/after
  evidence and `RollbackRecord`s, each verified with a `VerificationResult`;
  exceptions capture documented, accepted risks (e.g. "`/tmp` cannot use
  `noexec` because Application X runs temporary scripts").
- **Windows/BSD**: catalog controls declare `platform`; only OSFamily/Linux
  controls exist today.
- **Evidence expansion**: collect SSH effective config and sysctl values to turn
  the current `unknown` kernel/SSH controls into evaluable ones.

---

# Phase 3 — Guided execution

Phase 3 makes the product usable end to end: the agent now applies hardening
**interactively, one control at a time, with backup, verification and rollback**.

## 27. Pipeline addition

```
HardeningPlan (draft)
        ↓  operator selects controls
   hardening_execute
        ↓
  preview → confirm → apply → verify → (rollback)
        ↓
state/<server-id>/{backups,changes,verification,rollbacks}/
```

## 28. Safety model

- **No arbitrary shell.** `hardening_execute` accepts only
  `action`, `serverId`, `planId`, `controlId`, `target`, `confirm`. Commands are
  fixed argvs defined in the remediation modules, executed through the same
  `CommandRunner` used by discovery (no shell, timeouts, output caps).
- **Explicit confirmation.** `apply` and `rollback` require `confirm: true`; the
  agent is instructed to obtain it from the operator first.
- **Approved controls only.** Apply is allowed only when the plan status is
  `non-compliant` or `requires-review`. `unknown`, `requires-context`,
  `blocked`, `compliant`, `not-applicable` are refused.
- **Root required, never sudo.** Changes that need root refuse to run without
  it; the framework never escalates privileges itself.
- **Manual-only fallback.** Controls without a safe automatic remediation return
  `manual remediation required` and never apply.

## 29. Backups, changes, rollback

- Every file edit is preceded by a `BackupRecord` (content + SHA-256) stored at
  `state/<server-id>/backups/`.
- Each apply writes a `ChangeRecord` (target, before/after JSON, result) and,
  when reversible, a `RollbackRecord` (strategy + backup artifacts).
- Rollback restores the backup (and service/state) from those records. When a
  change cannot be reversed automatically (e.g. package installation) the
  framework reports `manual rollback required`.

## 30. Verification (not exit codes)

Each remediation verifies real state: runtime sysctl values; `sshd -t` plus the
effective directive plus the service being active; `systemctl is-active` /
`is-enabled`; `ufw status` / `firewall-cmd --state`; the resulting fstab entry.

## 31. Remediation coverage (Phase 3)

| Domain | Controls | Notes |
| --- | --- | --- |
| sysctl | KRN-001..004 | managed drop-in + runtime, conflict detection |
| SSH | SSH-001..005 | backup, edit, `sshd -t`, reload; lockout controls gated |
| firewall | FW-001 | ufw/firewalld, admin access preserved; nftables manual |
| services | SVC-001 | disable/stop known-insecure services only |
| logging/audit | AUD-001/002, LOG-001 | install (confirmed) / enable |
| filesystem | FS-001/002 | fstab options; no automatic remount |

Everything else is manual by design.

## 32. Testing (Phase 3)

`execution.test.ts` covers preview-is-read-only, backup contents, apply, verify,
rollback, `sshd -t` failure restoration, sysctl runtime+persistence, service
change, firewall safety (nftables never automated; ufw allows admin port first),
fstab edits, refusal of non-approved controls, root gate, and tool argument
safety. Tests never touch the real host (temporary paths + a mutable fake
runner).


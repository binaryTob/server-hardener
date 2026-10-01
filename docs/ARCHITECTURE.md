# Architecture — server-hardener (local agent)

`server-hardener` is a **local OpenCode agent** for hardening the Linux machine
it runs on. You clone it inside the server, open OpenCode and say
*"harden this server"*.

It is not a platform, daemon, service, fleet manager or Ansible replacement.
There is no remote administration, no per-server identity, no plan database.

## 1. Product

```
ssh server
cd server-hardener
opencode
> harden this server
```

The agent inspects the local host, proposes hardening grouped by risk, asks only
the operational questions it needs, applies approved changes locally, verifies
them and can roll them back.

## 2. Layers

```
src/hardening/
├── exec.ts, fsio.ts, errors.ts     safe argv execution + read-only file reader
├── collectors/linux.ts             read-only commands (fixed argv, no shell)
├── parsers/linux/*.ts              pure text -> domain model
├── inventory.ts                    discovery orchestrator + summary
├── models.ts                       inventory, context, evaluation, tiers, backups
├── validation.ts                   zod schemas + validators
├── store.ts                        .server-hardener/ (backups, last-run, context)
├── controls/                       catalog: applicability, assessment, risk,
│                                   preconditions (pure functions)
├── planning/                       context, applicability, risk, preconditions,
│                                   evaluate (+ tier), questions
├── remediation/                    sysctl, ssh, firewall, services, logging,
│                                   filesystem + config/fsop helpers + run
└── agent.ts                        high-level API + text rendering
.opencode/
├── agents/server-hardener.md       the agent experience
├── skills/                         linux-discovery, linux-hardening,
│   ssh/firewall/services/kernel/filesystem/logging-hardening, verification
└── tools/                          inspect_system, inspect_security,
    harden_sysctl, harden_ssh, harden_firewall, harden_service,
    harden_logging, harden_filesystem
scripts/inspect.ts                  CLI: read-only assessment
```

Data flows one way:

```
Collector → parser → ServerInventory
                       │
        OperationalContext (optional)
                       │
                  ControlCatalog → applicability → assessment → risk →
                  preconditions → tier → remediation (preview/apply/verify/rollback)
```

The **engine**, not the LLM, decides applicability, compliance, risk,
preconditions and tiers. The LLM gathers context and explains results.

## 3. Local state (`.server-hardener/`)

```
.server-hardener/
├── backups/               one JSON per backed-up file (content + sha256 + mode/uid/gid)
├── last-run.json          applied/skipped/failed/rolled-back entries + verification
└── optional-context.json  operator-supplied operational context
```

No per-server tree, no plan store, no database. Writes are atomic; ids are
validated and cannot escape the directory.

## 4. Discovery and evaluation

- **Discovery** runs fixed, read-only commands (no shell) and reads well-known
  files. Each section reports `success|partial|unsupported|insufficient-permissions|unavailable|error`;
  one failing section never aborts the inspection.
- **Controls** are code with pure `applicability`, `assess`, `adjustRisk` and
  `preconditions` functions. Statuses: `compliant`, `non-compliant`,
  `not-applicable`, `unknown`, `requires-context`, `requires-review`, `blocked`,
  `unsupported`, `error`.
- **Tiers** group actionable controls for the operator: `safe`, `review`,
  `risky` (and `skip`). Classification uses risk levels (no numeric score): a
  change that can cut access or disrupt availability is `risky`.
- **Risk** is context-sensitive. Example: disabling SSH password authentication
  is `lockout=low` with a confirmed secondary path and `lockout=critical`
  without one.
- **Questions** are generated only for context that actually changes a decision
  (e.g. secondary management path, console access, administrative networks).

## 5. Remediation

Supported: sysctl (KRN-001..004), SSH (SSH-001..005), firewall (FW-001,
ufw/firewalld only), services (SVC-001 known-insecure only), logging/audit
(AUD-001/002, LOG-001), filesystem fstab (FS-001/002). Everything else is
`manual remediation required`.

Each remediation:
1. **preview** (read-only) — current, desired, steps, files, commands, warnings;
2. **apply** — back up files, edit atomically, reload (not restart), then verify;
3. **verify** — real state, not exit codes;
4. **rollback** — restore backups / previous state, or say
   `manual rollback required`.

## 6. Safety model

- Tools accept only bounded arguments (`action`, `controlId`, `target`,
  `confirm`); the model cannot supply a command.
- Commands are fixed argvs executed without a shell (timeouts, output caps).
- `apply`/`rollback` require `confirm: true` after explicit operator approval.
- Only `non-compliant`/`requires-review` controls can be applied.
- Root is required where needed; **no sudo escalation** is performed.
- SSH lockout controls refuse to run without a confirmed secondary path;
  firewalls never close administrative access automatically; nftables and
  package removal are never automated.

## 7. Tests

`tests/`: parsers, discovery/inventory, assessment (applicability/risk/
preconditions/tiers), local store, execution (preview/backup/apply/verify/
rollback/safety gates) and tool security. Deterministic fakes and a temporary
system tree; no real host is modified.

## 8. Deliberately out of scope

Windows, remote administration, fleet management, database, API/server, web UI,
scheduler, daemon, cloud service, multi-tenancy, orchestration, compliance
dashboard, pentesting/offensive security, scoring, complex plan/state engines.

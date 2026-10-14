# Server-Hardener

An **OpenCode agent running on your workstation** that hardens **one target Linux
server over SSH**. The target does not need OpenCode, Bun, Node, this repository,
API keys, or a framework agent/daemon installed.

It is reusable across servers you can administer over SSH. Each session operates
on one target; there is no fleet-management platform.

```text
Workstation (OpenCode + server-hardener)  ── SSH ──▶  Target server (sshd)
```

SSH transports the tools' operations. TypeScript implements discovery,
deterministic assessment and bounded remediation; OpenCode provides reasoning and
operator interaction. The runtime has no embedded LLM or unattended execution of
all controls.

## Requirements

- [Bun](https://bun.sh) ≥ 1.4.3, OpenCode and OpenSSH **on the workstation**.
- SSH access using your normal configuration: a `~/.ssh/config` alias,
  `user@host`, `user@IP`, or `host:port` for a non-standard port. SSH agent,
  `IdentityFile`, `ProxyJump` and `known_hosts` settings are honored.
- On the target: root SSH access **or** an administrator with passwordless
  `sudo -n`.
- Authentication is delegated to your own `ssh`; the framework does not collect
  or store passwords or private keys.

## Getting started (workstation only)

```bash
git clone https://github.com/binaryTob/server-hardener.git
cd server-hardener
bun install --frozen-lockfile --ignore-scripts
opencode
```

Select the `server-hardener` agent in OpenCode and provide a target:

```text
> Harden example-server
> Harden admin@192.0.2.10
> Harden root@192.0.2.10:2222     # non-standard port
```

If you ask to *"harden this server"* without specifying a target, the agent asks
which server to use. It never assumes `localhost`.

## Workflow

1. Validate the target and test SSH connectivity.
2. Run **read-only remote discovery**: OS, network, sockets, users, services,
   packages, firewall/logging, mounts and containers.
3. Evaluate the control catalog and group candidates into **SAFE / REVIEW /
   RISKY**, without a numeric score.
4. Ask only for operational context that affects a decision.
5. For each selected control: `preview` → **explicit confirmation** → remote
   `apply` → `verify`. File changes have remote backups; services/firewall record
   their previous state. An SSH syntax failure restores configuration, and a
   reconnect failure triggers a rollback attempt. Other failures require review
   and an explicit rollback request; there is no global transaction.
6. Report applied, skipped, failed and rolled-back controls.

### Read-only CLI

```bash
bun run inspect admin@192.0.2.10
```

## Tools

- `target` — `connect` | `info` | `clear`: the active session target.
- `inspect_system` — target summary: `inspect`, `last-run`.
- `inspect_security` — assessment: `assess`, `explain`.
- `harden_sysctl` (KRN-*), `harden_ssh` (SSH-*), `harden_firewall` (FW-*),
  `harden_service` (SVC-*), `harden_logging` (LOG-*/AUD-*),
  `harden_filesystem` (FS-*): `inspect | preview | apply | verify | rollback`.

`apply` and `rollback` require `confirm: true` following explicit operator
approval. Tools do not accept arbitrary commands: they execute predefined SSH
operations using argv, without a local shell, with backup and verification.

## Safety rules

- Never assume `localhost`: ask for a target if none is selected.
- Apply only `non-compliant` / `requires-review` controls.
- **Lockout = stop:** setting `PasswordAuthentication no` is refused without a
  confirmed secondary management path.
- Do not replace firewalls or generate nftables rules. Automatic UFW activation
  requires known administrative ports and successful allow rules before enabling
  it. Firewalld requires manual review of zones, interfaces and ports.
- After SSH/firewall changes, verify a **new SSH connection** from the workstation
  with up to three attempts. On failure, attempt rollback through the retained
  session and check again. A listening socket is not proof of access.
- Rollback depends on the retained session remaining usable. There is no remote
  recovery timer: keep a verified console/secondary path for access-affecting
  changes. No individual control guarantees that lockout cannot occur.
- Switching target or port clears previous operational context; one server's
  approvals are not reused for another. Reconfirm context if an SSH alias is
  repointed to a different destination.
- Do not install framework dependencies on the target. Installing `auditd` is an
  explicit hardening decision, not a framework prerequisite.
- Never collect or save passwords. Privileged changes require root or `sudo -n`.

## Backups and state

- Backups live **on the target** at
  `/var/backups/server-hardener/<run-id>/`, including content, owner/group/mode
  and hash. Restore checks integrity; backup files are written with mode `0600`.
- Reading/editing configuration and creating/restoring backups passes content
  through workstation memory. Treat the OpenCode session and operational records
  as sensitive information.
- Minimal local state is stored **on the workstation** and ignored by Git:

```text
.server-hardener/
├── session.json           active session target
├── last-run.json          applied/skipped/failed/rolled-back controls + verification
└── optional-context.json  operator-supplied operational context
```

## Automated coverage

- sysctl (KRN-001..004).
- SSH directives (SSH-001..005) and **SSH-007** (expose only the administrative
  port), with backup, `sshd -t`, reload and reconnect verification.
- Firewall (FW-001): UFW activation; firewalld/nftables are manual.
- Known insecure services (SVC-001).
- Logging/auditing (AUD-001/002, LOG-001).
- fstab (FS-001/002).

Other controls return `manual remediation required`. Checks represent unknown
states and unmet preconditions explicitly; SAFE does not mean "apply without
authorization". Explicit `localhost` targets use local transport.

## Architecture and limits

```text
OpenCode agent + skills -> tools with bounded arguments
  -> agent.ts -> discovery / controls / planning
  -> remediation -> Host (SSH by default) -> OS utilities
```

`controls/` and `planning/` separate applicability, compliance and risk from
execution in `remediation/`. `transport/` validates targets and constructs argv
with remote quoting. `store.ts` holds minimal local state.

`preview` and `verify` do not create backup directories. Automated verification
uses fixtures and `FakeHost`; it is not a validation matrix covering every Linux
distribution, firewall, PAM configuration, SSH Include/Match rule or socket-activated
service. Unrepresented configurations require manual review. Firewall rollback
restores activation state, not a complete ruleset snapshot; added allow rules
need review if an operation fails.

## Development

```bash
bun run format     # biome format --write
bun run lint       # biome check
bun run typecheck  # tsc --noEmit
bun test           # bun:test
bun run build      # tsc -> dist/
bun run inspect <target>   # read-only assessment
```

See [architecture](docs/ARCHITECTURE.md) and [verification](docs/VERIFICATION.md).
GitHub Actions runs offline checks, audits dependencies and scans Git history
with Gitleaks. Quit and restart OpenCode after changing agents, skills or tools
so it reloads their definitions.

## Deliberately out of scope

Fleet management, remote agents/daemons, API server, queues/schedulers, database,
web UI, orchestration, Ansible/Terraform, remote deployment of the framework,
Windows, scoring, penetration testing, compliance dashboards and complex
plan/state engines.

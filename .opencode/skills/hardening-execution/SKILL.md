---
name: hardening-execution
description: Apply approved hardening controls from a HardeningPlan interactively, one at a time, with preview, backup, verification and rollback. Use when the operator has a plan and wants to actually harden the server. Nothing is applied without explicit confirmation.
---

# Hardening Execution (Phase 3)

## Purpose

Turn a reviewed `HardeningPlan` into real, safe, verified changes — one control
at a time, always with the operator's explicit confirmation.

## Rules

1. **Preview first, always.** `hardening_execute` with `action: "preview"` is
   read-only. Show current state, desired state, impact, files to back up,
   commands and warnings before doing anything.
2. **Explicit confirmation.** Apply only after the operator says yes. `apply`
   and `rollback` require `confirm: true`; never set it pre-emptively.
3. **One control at a time.** Apply, report the verification, then move on.
4. **Only approved controls.** Apply only controls the plan marked
   `non-compliant` or `requires-review`. Everything else is refused.
5. **Lockout = stop.** Never disable SSH password authentication without a
   confirmed secondary management path. Surface lockout warnings verbatim.
6. **Backups happen automatically** under `state/<server-id>/backups/`; every
   change is recorded under `state/<server-id>/changes/` with a rollback record.
7. **Verify, don't trust exit codes.** Each remediation checks real state
   (runtime sysctl value, `sshd -t` + effective config + service active,
   `systemctl is-active/is-enabled`, firewall status, fstab options).
8. **Roll back on failure.** If a change fails verification, offer rollback. If
   automatic rollback is not safe, say `manual rollback required`.

## Workflow

```
plan (draft)
   ↓
group controls by risk; ask what to apply
   ↓
for each selected control:
      preview  → show → confirm → apply → verify → report
      on failure: rollback (or "manual rollback required")
   ↓
STOP when the operator stops
```

## What the tool supports

- sysctl (KRN-001..004): managed drop-in + runtime, conflict detection.
- SSH (SSH-001..005): backup, edit, `sshd -t`, reload (never restart).
- firewall (FW-001): ufw/firewalld only, admin access preserved; nftables manual.
- services (SVC-001): disable/stop known-insecure services only.
- logging/audit (AUD-001/002, LOG-001): install (confirmed) / enable.
- filesystem (FS-001/002): add safe mount options to fstab (no auto-remount).

Everything else is `manual remediation required` and is never applied
automatically.

## Tools

- `hardening_execute` — `preview` / `apply` / `verify` / `rollback`.

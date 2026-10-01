---
name: linux-hardening
description: Overall workflow to harden the local host safely. Use when the user asks to harden the server, to group candidates by risk, or to decide what to apply.
---
# Linux hardening workflow

1. `inspect_security` → candidates grouped SAFE / REVIEW / RISKY, plus
   decision-critical questions.
2. Ask only the questions the engine needs (they change a decision).
3. Operator selects; for each control: preview → confirm → apply → verify →
   (rollback on failure).
4. Always protect availability and access.

Classification:
- SAFE: low operational impact, no lockout.
- REVIEW: needs the operator's intent (why a service exists, is a setting
  justified).
- RISKY: can cut access or disrupt services (SSH, firewall).

Rules:
- Never apply controls the assessment did not mark actionable.
- No numeric score. Backup before edit; verify after; roll back on failure.
- Prefer the least disruptive method (reload over restart, runtime+persistent for
  sysctl).

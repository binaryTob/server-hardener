---
name: linux-hardening
description: Overall workflow to harden the target server safely over SSH. Use when the user asks to harden a server, to group candidates by risk, or to decide what to apply.
---
# Hardening workflow (remote)

1. Select/confirm the target (`target` connect).
2. `inspect_security` → SAFE / REVIEW / RISKY + decision-critical questions.
3. Ask only the questions the engine needs.
4. For each selected control: preview → confirm → apply → verify → (rollback).
5. Summarize applied / skipped / failed / rolled back.

Classification:
- SAFE: low operational impact, no lockout.
- REVIEW: needs the operator's intent.
- RISKY: can cut access or disrupt services (SSH, firewall).

Rules:
- Only apply controls marked non-compliant/requires-review.
- Backups are stored ON THE TARGET (`/var/backups/server-hardener/<run-id>/`).
- Verify real state, not exit codes. Roll back on failure.
- Never touch localhost unless it was explicitly selected as the target.

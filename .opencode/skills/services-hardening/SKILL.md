---
name: services-hardening
description: Service hardening rules. Use before disabling or stopping any service.
---
# Services hardening

Tool: `harden_service` (SVC-*).

Rules:
- **Never disable an unknown service automatically.** For a service the operator
  has not justified, explain its process, listening ports and dependencies, and
  ask whether it is needed.
- Only disable/stop services the assessment flagged (`non-compliant` for known
  insecure protocols, or `requires-review` after confirmation).
- Show current state (enabled/active), associated listeners and possible impact.
- The tool records the previous state and can re-enable/start on rollback.
- Prefer `disable --now` only after confirmation; never touch services that
  could cut your own access without a confirmed recovery path.

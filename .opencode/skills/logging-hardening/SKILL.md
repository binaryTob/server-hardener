---
name: logging-hardening
description: Logging and auditing rules (journald, rsyslog, auditd, agents). Use before changing logging/auditing state.
---
# Logging / auditing hardening

Tool: `harden_logging` (LOG-*, AUD-*).

Rules:
- Prefer enabling/starting an existing service (`auditd`, `rsyslog`) over
  installing packages. Installing a package requires **explicit confirmation**
  (repository access) and is **not automatically reversible**.
- Detect but never require a specific agent; Wazuh is one capability among
  others. Absence of a local agent is not proof that monitoring is missing.
- Verify the service is active **and** enabled afterwards.
- Persistent-storage specifics (journald `Storage=`) may be unobservable; report
  `unknown` rather than guessing.

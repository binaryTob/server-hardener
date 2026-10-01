---
name: linux-discovery
description: Read-only discovery of the local Linux host. Use to understand the OS, services, listeners, users, firewall/logging state before proposing any hardening.
---
# Linux discovery

Run `inspect_system` to get a read-only picture of THIS host. It reports OS,
interfaces, listening sockets (with scope), users/groups, services, packages,
firewall/MAC/logging state, mounts, time and container runtimes, plus collection
gaps.

Rules:
- Discovery is strictly read-only; never install a missing tool.
- Absence of evidence is not insecurity (a wildcard listener or a missing tool
  is evidence, not a finding).
- Communicate gaps: a section can be `partial`, `insufficient-permissions`,
  `unavailable` or `unsupported`.
- Never invent values; report unknowns as unknown.

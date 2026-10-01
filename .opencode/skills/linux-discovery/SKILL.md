---
name: linux-discovery
description: Read-only discovery of the target server over SSH. Use to understand the target's OS, services, listeners, users, firewall/logging state before proposing hardening.
---
# Target discovery

Ensure a target is selected (`target` tool). Then run `inspect_system`: it
connects over SSH and reports the target's OS, interfaces, listening sockets,
users/groups, services, packages, firewall/MAC/logging state, mounts, time and
container runtimes, plus collection gaps.

Rules:
- Discovery is read-only and runs over SSH with the operator's ssh config/keys.
- Never assume localhost; the target is explicit or from the session.
- Never install anything on the target to complete discovery.
- Absence of evidence is not insecurity; report gaps and unknowns honestly.

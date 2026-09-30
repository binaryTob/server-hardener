---
name: server-discovery
description: Run read-only server discovery to build and persist a validated ServerInventory. Use when the user asks to inspect, inventory, or understand the current state of a server. Phase 1: discovery only, no hardening.
---

# Server Discovery (Phase 1)

## Purpose

Collect an evidence-based, validated, persisted inventory of the current state
of a server without modifying anything. Discovery is **strictly read-only**.

## Non-negotiable rules

1. **Read-only.** Discovery never modifies services, firewall, SSH, users,
   packages, or any system configuration. Never install missing tools.
2. **Absence of evidence is not evidence of insecurity.** A wildcard listener,
   a missing firewall, or a locked-unknown account is recorded as evidence
   only — it is NOT a vulnerability finding and must not be reported as one.
3. **Never invent values.** Report only what was observed. If a value could
   not be determined, report it as unknown/insufficient rather than guessing.
4. **Communicate partial results.** Sections can report `success`, `partial`,
   `unsupported`, `insufficient-permissions`, `unavailable`, or `error`. A
   partial discovery is a normal outcome, not a failure — always surface the
   collection gaps to the user.
5. **Phase 1 has no hardening.** Do not recommend or apply configuration
   changes yet. If the user asks for hardening, explain that only discovery
   exists in this phase and that control evaluation, plans, and changes arrive
   in later phases.
6. **No scoring.** Do not compute or present security scores; there is no
   objective weighting yet.
7. **No secrets.** The inventory must never contain passwords, private keys,
   tokens, environment variables, or sudoers contents.

## When to run discovery

- The user asks to inspect/inventory the current state of this server.
- A later phase needs fresh evidence before proposing any change.
- The user asks "what is running on this host?" in a hardening context.

## Workflow

1. **Confirm target.** Phase 1 discovers the local host only. If the user
   points at a remote server, explain that remote discovery is not available
   yet and stop.
2. **Collect.** Call the `hardening_inventory` tool with
   `{"action": "collect"}`. It runs read-only discovery, validates the
   result, and persists `state/<server-id>/inventory.json`.
3. **Validate.** The tool validates before persisting; if you need to
   re-check persisted state afterwards, call `hardening_state` with
   `{"action": "validate-state"}`.
4. **Summarize.** Present the detected characteristics: OS, kernel,
   interfaces, listening sockets (with scope), users and groups, privileged
   access, services, packages, security controls, filesystems, time, and
   container runtimes.
5. **Highlight gaps.** List every section whose status is not `success`
   (partial, insufficient-permissions, unavailable, etc.) and what evidence
   is missing and why.
6. **Stop.** Do not proceed to recommendations, changes, or plans.

## Tool reference

- `hardening_inventory` — `collect` / `show` / `validate`.
- `hardening_state` — `status` / `list-inventories` / `load-inventory` /
  `validate-state`.

Both tools accept bounded actions only; neither can run arbitrary commands.

## Reading the inventory

- Fields wrapped in `Evidence` record where the value came from
  (`source`) and whether it was `observed`, `derived` (heuristic), or
  `unknown`. Derived values (e.g. "human-like" accounts, firewall
  implementation) must always be presented as inferences, never as facts.
- Listening socket `scope` distinguishes `loopback`, `specific-address`,
  `wildcard`, and `unknown` — descriptive, not evaluative.

---
name: hardening-planning
description: Turn a ServerInventory plus operational context into a draft HardeningPlan with deterministic applicability, compliance, risk, preconditions and ordering. Use when asked to assess what should change, what blocks it, and what information is missing. Phase 2 is planning only — no changes are applied.
---

# Hardening Planning (Phase 2)

## Purpose

Evaluate the control catalog against the current inventory and the operational
context, and produce a **draft `HardeningPlan`** that answers:

- which controls apply;
- what each control's state is; and
- how risky, blocked or context-dependent changing it would be.

The engine — not you, the model — decides applicability, compliance, risk,
preconditions and ordering. Your job is to gather the missing operational
context and explain the result.

## Non-negotiable rules

1. **No remediation.** Phase 2 does not modify the server. Never apply,
   suggest applying, or imply that a change has been made.
2. **Do not invent context.** Operational facts come from the operator (via
   the `hardening_context` tool). Never guess environment, exposure, networks,
   management paths or roles.
3. **Absence of evidence is not insecurity.** `unknown`, `requires-context` and
   `requires-review` are legitimate, expected outcomes. Never turn them into
   findings.
4. **An unrecognised service is not an unnecessary service.** Never recommend
   disabling something just because it is unfamiliar.
5. **Inferred values stay inferred.** Roles detected from evidence are
   proposals (`derived`); present them as such until the operator confirms.
6. **No scoring.** Report counts by state; never produce a number out of 100.
7. **Interrupt only to ask decision-changing questions.** Ask only what the
   engine marked as missing context.

## Workflow

```
Inventory
   ↓
Load existing context        (hardening_context: show)
   ↓
Detect missing decision-critical context
   ↓
Ask the MINIMAL questions     (only those that change a decision)
   ↓
Persist context               (hardening_context: set / answer)
   ↓
Generate plan                 (hardening_plan: generate)
   ↓
Explain blockers and risky controls (hardening_plan: explain-control)
   ↓
STOP
```

## Steps

1. **Ensure an inventory exists.** If not, run the `server-discovery` skill
   (`hardening_inventory` with `action: "collect"`).
2. **Load context.** `hardening_context` with `action: "show"`. Note the
   decision-critical gaps it reports.
3. **Answer only decision-critical questions.** Generate a plan first
   (`hardening_plan` `generate`); its `unresolvedQuestions` list the fields the
   engine actually needs. Answer them with `hardening_context` (`set` with
   `values`, or `answer` with a `questionId`).
4. **Regenerate** the plan once context is supplied.
5. **Explain.** Use `hardening_plan` `explain-control` for specific controls:
   evidence, applicability, current/desired state, risk, preconditions and
   blockers. Present high-impact and lockout-risk controls prominently, and be
   explicit about blockers and missing context.
6. **Stop.** Do not transition the plan beyond `draft` and do not apply it.

## Interpreting states

| State | Meaning |
| --- | --- |
| `compliant` | Evidence shows the desired state. |
| `non-compliant` | Evidence shows the undesired state. |
| `not-applicable` | The control does not apply (e.g. no SSH server). |
| `unknown` | The inventory does not contain the evidence to decide. |
| `requires-context` | A decision-critical operational fact is missing. |
| `requires-review` | Needs human judgement (e.g. why a service is enabled). |
| `blocked` | A critical precondition is unsatisfied or unresolved. |
| `unsupported` | The control targets another platform. |
| `error` | Evaluation failed; report it, do not guess. |

## Tools

- `hardening_context` — `show` / `set` / `answer` / `validate`.
- `hardening_plan` — `generate` / `show` / `validate` / `explain-control`.

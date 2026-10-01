/**
 * Kernel (sysctl) controls.
 *
 * Phase 1 discovery does not collect kernel parameters, so every control in
 * this module reports `unknown` with an explicit evidence gap. They exist now
 * so that the catalog, ordering and risk model are exercised end to end, and
 * will become evaluable when sysctl collection is added.
 *
 * This is deliberate: an unobserved setting is never assumed to be insecure.
 */

import { applicable, missingEvidence, unknownState } from "./helpers";
import type { ControlDefinition } from "./types";

interface KernelControlSpec {
  id: string;
  title: string;
  setting: string;
  path: string;
  desiredState: string;
  description: string;
  rationale: string;
  securityImpact: "low" | "medium" | "high";
  references: string[];
  tags: string[];
}

function kernelUnknownControl(spec: KernelControlSpec): ControlDefinition {
  return {
    id: spec.id,
    title: spec.title,
    category: "kernel",
    platform: ["linux"],
    description: spec.description,
    rationale: spec.rationale,
    desiredState: spec.desiredState,
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: spec.tags,
    references: spec.references,
    baseRisk: {
      securityImpact: spec.securityImpact,
      availabilityRisk: "low",
      lockoutRisk: "none",
      operationalComplexity: "low",
    },
    applicability: () => applicable("kernel parameters apply on Linux hosts"),
    assess: () =>
      unknownState(
        null,
        `${spec.setting} is not collected by current discovery, so its value cannot be asserted`,
        [missingEvidence(spec.path, "kernel sysctl values are not part of the current inventory")],
      ),
  };
}

export const kernelControls: ControlDefinition[] = [
  kernelUnknownControl({
    id: "KRN-001",
    title: "IP source routing is disabled",
    setting: "net.ipv4.conf.all.accept_source_route",
    path: "kernel.data.sysctl['net.ipv4.conf.all.accept_source_route']",
    desiredState: "net.ipv4.conf.all.accept_source_route=0",
    description: "Source-routed packets should not be accepted.",
    rationale:
      "Source routing lets a sender dictate the path a packet takes, which can be used to bypass network controls.",
    securityImpact: "medium",
    references: ["CIS Controls v8 4.4", "NIST SP 800-53 SC-7"],
    tags: ["kernel", "network"],
  }),
  kernelUnknownControl({
    id: "KRN-002",
    title: "ICMP redirects are not accepted",
    setting: "net.ipv4.conf.all.accept_redirects",
    path: "kernel.data.sysctl['net.ipv4.conf.all.accept_redirects']",
    desiredState: "net.ipv4.conf.all.accept_redirects=0",
    description: "ICMP redirects should not be accepted (unless the host is a router).",
    rationale: "Accepting ICMP redirects allows an attacker on-path to alter the host's routing decisions.",
    securityImpact: "medium",
    references: ["CIS Controls v8 4.4"],
    tags: ["kernel", "network"],
  }),
  kernelUnknownControl({
    id: "KRN-003",
    title: "Address space layout randomization is enabled",
    setting: "kernel.randomize_va_space",
    path: "kernel.data.sysctl['kernel.randomize_va_space']",
    desiredState: "kernel.randomize_va_space=2",
    description: "Full ASLR should be enabled.",
    rationale:
      "ASLR raises the difficulty of exploiting memory-corruption vulnerabilities by randomising process memory layout.",
    securityImpact: "medium",
    references: ["CIS Controls v8 4.1", "NIST SP 800-53 SC-30"],
    tags: ["kernel", "exploit-mitigation"],
  }),
  kernelUnknownControl({
    id: "KRN-004",
    title: "Kernel pointer exposure and ptrace are restricted",
    setting: "kernel.kptr_restrict / kernel.yama.ptrace_scope",
    path: "kernel.data.sysctl['kernel.kptr_restrict']",
    desiredState: "kernel.kptr_restrict=1 and kernel.yama.ptrace_scope>=1",
    description: "Kernel pointers should be hidden and ptrace restricted.",
    rationale:
      "Exposing kernel pointers aids exploitation, and unrestricted ptrace allows one process to inspect another, weakening process isolation.",
    securityImpact: "medium",
    references: ["CIS Controls v8 4.1"],
    tags: ["kernel", "exploit-mitigation"],
  }),
];

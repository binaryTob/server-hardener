/**
 * Container controls.
 *
 * Presence and versions are observed; workload inspection is out of scope.
 * The controls that can be asserted are the ones visible from listening
 * sockets, which are exactly the high-risk misconfigurations.
 */

import {
  applicable,
  compliant,
  missingEvidence,
  nonCompliant,
  ref,
  sectionGap,
  sockets,
  unknownState,
} from "./helpers";
import type { ControlDefinition } from "./types";

function hasRuntime(inv: Parameters<ControlDefinition["applicability"]>[0], name: string): boolean {
  return (inv.containers.data?.runtimes ?? []).some((r) => r.name === name);
}

export const containerControls: ControlDefinition[] = [
  {
    id: "CTN-001",
    title: "Docker TCP API is not exposed unauthenticated",
    category: "containers",
    phase: "network",
    order: 70,
    platform: ["linux"],
    description: "The Docker API must not listen on an unauthenticated TCP port.",
    rationale:
      "The Docker daemon API on port 2375 is unauthenticated and grants effective root on the host to anyone who can reach it. This is a well-known, high-impact exposure.",
    desiredState: "no listener on port 2375",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["containers", "exposure", "critical"],
    references: ["NIST SP 800-190", "OWASP Docker Security"],
    baseRisk: {
      securityImpact: "critical",
      availabilityRisk: "low",
      lockoutRisk: "none",
      operationalComplexity: "low",
    },
    applicability: (inv) => {
      if (sectionGap(inv.sockets)) {
        return {
          status: "unknown",
          rationale: "the listening-socket inventory is not reliable",
          evidence: [ref("sockets.status", inv.sockets.status)],
          missingContext: [],
          confidence: "unknown",
        };
      }
      if (!hasRuntime(inv, "docker")) {
        return {
          status: "not-applicable",
          rationale: "no Docker runtime was detected",
          evidence: [ref("containers.data.runtimes", "no docker")],
          missingContext: [],
          confidence: "observed",
        };
      }
      return applicable("Docker is present and sockets are available", [
        ref("containers.data.runtimes[name=docker]", "present"),
      ]);
    },
    assess: (inv) => {
      const exposed = sockets(inv).filter((s) => s.port === 2375);
      const evidence = [
        ref("sockets.data.sockets[port=2375]", exposed.map((s) => `${s.scope}`).join(", ") || "none"),
      ];
      if (exposed.length === 0) {
        return compliant(
          "port 2375 not listening",
          "the unauthenticated Docker API port is not listening",
          evidence,
        );
      }
      return nonCompliant(
        `Docker API on ${exposed.map((s) => s.scope).join(", ")}`,
        "port 2375 exposes the Docker API without authentication",
        evidence,
      );
    },
  },
  {
    id: "CTN-002",
    title: "Kubernetes control-plane APIs are not on wildcard addresses",
    category: "containers",
    phase: "network",
    order: 80,
    platform: ["linux"],
    description: "The Kubernetes API and kubelet should not be exposed on all interfaces.",
    rationale:
      "The Kubernetes API server (6443) and kubelet (10250/10255) grant cluster or node control. Wildcard exposure dramatically increases reachable attack surface.",
    desiredState: "Kubernetes control ports bound to specific addresses",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["containers", "kubernetes", "exposure"],
    references: ["NIST SP 800-190", "CIS Kubernetes Benchmark (concept)"],
    baseRisk: {
      securityImpact: "high",
      availabilityRisk: "medium",
      lockoutRisk: "low",
      operationalComplexity: "medium",
    },
    applicability: (inv) =>
      sectionGap(inv.sockets)
        ? {
            status: "unknown",
            rationale: "the listening-socket inventory is not reliable",
            evidence: [ref("sockets.status", inv.sockets.status)],
            missingContext: [],
            confidence: "unknown",
          }
        : applicable("listening sockets are available"),
    assess: (inv) => {
      const k8sPorts = new Set([6443, 10250, 10255]);
      const listeners = sockets(inv).filter((s) => s.port !== null && k8sPorts.has(s.port));
      const wildcard = listeners.filter((s) => s.scope === "wildcard");
      const evidence = [
        ref(
          "sockets.data.sockets[kubernetes ports]",
          listeners.map((s) => `${s.port}(${s.scope})`).join(", ") || "none observed",
        ),
      ];
      if (listeners.length === 0) {
        return compliant(
          "no Kubernetes control ports listening",
          "no control-plane port was observed",
          evidence,
        );
      }
      if (wildcard.length > 0) {
        return nonCompliant(
          `${wildcard.length} control-plane listener(s) on wildcard`,
          "Kubernetes control ports are reachable from all interfaces",
          evidence,
        );
      }
      return compliant(
        "control-plane ports bound to specific addresses",
        "no wildcard control-plane listener",
        evidence,
      );
    },
  },
  {
    id: "CTN-003",
    title: "Container runtime isolation is configured",
    category: "containers",
    phase: "disruptive",
    order: 90,
    platform: ["linux"],
    description: "Container runtime isolation (rootless, userns, seccomp) should be configured.",
    rationale:
      "Container escape is the main risk of running containers; isolation features mitigate it. Their configuration is not observable from the current inventory, so the control is unknown rather than assumed.",
    desiredState: "runtime isolation features enabled",
    requiresApproval: true,
    reversible: true,
    dependencies: [],
    tags: ["containers", "isolation", "evidence"],
    references: ["NIST SP 800-190"],
    baseRisk: {
      securityImpact: "medium",
      availabilityRisk: "medium",
      lockoutRisk: "low",
      operationalComplexity: "high",
    },
    applicability: (inv) =>
      inv.containers.data?.runtimes.length
        ? applicable("container runtimes are present")
        : {
            status: "not-applicable",
            rationale: "no container runtime was detected",
            evidence: [ref("containers.data.runtimes", "none")],
            missingContext: [],
            confidence: "observed",
          },
    assess: () =>
      unknownState(null, "container runtime isolation configuration is not collected by current discovery", [
        missingEvidence("containers.data.runtimes[isolation]", "runtime config not inspected"),
      ]),
  },
];

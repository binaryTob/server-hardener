# Server Hardener — Fases 1, 2 y 3 (Discovery + Planning + Ejecución)

Framework interactivo de hardening de servidores.

- **Fase 1 — Discovery (read-only):** observa el estado actual y genera un
  **inventario validado y persistente**.
- **Fase 2 — Planning:** convierte `ServerInventory` + contexto operativo en un
  **`HardeningPlan` determinista y auditable**, sin aplicar cambios.
- **Fase 3 — Guided execution:** aplica los controles aprobados **de a uno**,
  con **backup, verificación y rollback**, siempre con confirmación explícita.

> Ninguna operación modifica el servidor sin confirmación. Discovery es
> read-only; el plan es un `draft`; y la ejecución hace backup de cada archivo,
> valida y verifica cada cambio, y puede revertirse.

## Filosofía

1. Nunca modificar un servidor antes de comprender su estado actual.
2. Nunca asumir que un servicio, puerto, usuario o configuración es innecesario
   solo porque parece inseguro.
3. Seguridad y disponibilidad tienen igual importancia.
4. Los cambios futuros serán explícitos, trazables, verificables y reversibles.
5. Toda recomendación conserva la evidencia que originó la decisión.
6. Ninguna fase actual ejecuta remediaciones, comandos destructivos ni cambios
   de configuración; discovery es estrictamente read-only y planning no aplica.

## Requisitos

- [Bun](https://bun.sh) ≥ 1.4 (runtime, gestor de paquetes y test runner).
- Linux (para discovery real). La Fase 1 solo implementa discovery de Linux;
  Windows/BSD quedan como extensión futura.

```bash
bun install
```

## Uso

### 1. CLI (rápido)

Ejecuta discovery sobre la máquina actual, valida y persiste:

```bash
bun run collect          # persiste en ./state
bun run collect ./otro   # persiste en ./otro
```

Salida: resumen con identidad, OS, secciones y **gaps de recolección**
(por ejemplo `insufficient-permissions` al no poder leer `/etc/shadow`).

### 2. Desde OpenCode (agente + tools)

El proyecto incluye:

- Agente: `.opencode/agents/server-hardening-agent.md`
- Skills: `.opencode/skills/server-discovery/`, `hardening-planning/`, `hardening-execution/`
- Tools:
  - `hardening_inventory` — `collect` | `show` | `validate`
  - `hardening_state` — `status` | `list-inventories` | `load-inventory` | `validate-state`
  - `hardening_context` — `show` | `set` | `answer` | `validate`
  - `hardening_plan` — `generate` | `show` | `validate` | `explain-control`
  - `hardening_execute` — `preview` | `apply` | `verify` | `rollback`

Ejemplos de invocación del agente:

```text
Lee el skill server-discovery y ejecuta discovery sobre este servidor.
```

```text
hardening_inventory { "action": "collect" }
hardening_inventory { "action": "show" }
hardening_state    { "action": "list-inventories" }
hardening_state    { "action": "validate-state" }
```

Las tools aceptan **solo acciones acotadas**: no existe ningún modo de ejecutar
comandos arbitrarios ni shell.

## Fase 2 — Planning

La Fase 2 responde, de forma **determinista**, qué controles aplican, su estado,
su riesgo, sus precondiciones, qué información falta y en qué orden considerarlos.
El **engine** decide (no el LLM); el agente solo recoge el contexto que falta y
explica el resultado. No aplica cambios.

### Contexto operativo (`hardening_context`)

Hechos que no pueden inferirse del servidor (entorno, exposición, redes de
gestión, rutas de administración, roles, ventana de mantenimiento).

```text
hardening_context { "action": "show" }
hardening_context { "action": "set", "values": {
  "environment": "production",
  "internetExposure": "direct",
  "management.secondaryPathConfirmed": true
}}
hardening_context { "action": "answer", "questionId": "q-management-consoleAccess", "value": true }
```

Los roles se **proponen** (`derived`) a partir de la evidencia y el operador los
confirma o corrige (`roles`). Se persiste en `state/<server-id>/context.json`.

### Plan (`hardening_plan`)

```text
hardening_plan { "action": "generate" }
hardening_plan { "action": "show" }
hardening_plan { "action": "validate" }
hardening_plan { "action": "explain-control", "controlId": "SSH-002" }
```

`generate` carga inventario + contexto, evalúa ~40 controles (~13 categorías),
ordena por fases operativas y persiste un plan `draft` en
`state/<server-id>/plans/<plan-id>.json`, con conteos por estado, preguntas sin
resolver, blockers y warnings.

### Estados de evaluación

`compliant` · `non-compliant` · `not-applicable` · `unknown` ·
`requires-context` · `requires-review` · `blocked` · `unsupported` · `error`.

No todo es PASS/FAIL: un valor que parece inseguro pero está justificado no es
`non-compliant`; la falta de evidencia es `unknown`; la falta de contexto es
`requires-context`; lo que necesita criterio humano es `requires-review`; una
precondición crítica no satisfecha **bloquea** el control.

### Riesgo

Niveles explícitos (`none|low|medium|high|critical|unknown`) **sin score
numérico**. El mismo control cambia de riesgo según contexto: deshabilitar el
password de SSH es `lockout=low` con ruta secundaria confirmada y
`lockout=critical` sin ella.

### Flujo recomendado

```text
inventory → contexto → preguntas mínimas → contexto → plan → explicar y PARAR
```

Ejemplo de resumen de plan:

```text
Controls evaluated: 40

  compliant            12
  non-compliant         7
  requires-context      6
  requires-review       5
  blocked               3
  unknown               5

High security impact: SSH-001, FW-001, AUD-001 ...
Potential lockout:    SSH-002, SSH-001 ...
Blocked: SSH-001 (secondary-management-path no confirmado)
Questions required before continuing: ...
Status: draft — review only. No changes are applied by Phase 2.
```

## Fase 3 — Ejecución guiada (`hardening_execute`)

Aplica los controles aprobados **de a uno**, con preview, backup, verificación y
rollback. Nunca sin confirmación.

```text
hardening_execute { "action": "preview", "controlId": "KRN-003" }
hardening_execute { "action": "apply",   "controlId": "KRN-003", "confirm": true }
hardening_execute { "action": "verify",  "controlId": "KRN-003" }
hardening_execute { "action": "rollback","controlId": "KRN-003", "confirm": true }
```

- `preview` es **read-only**: muestra estado actual/deseado, impacto, archivos a
  respaldar, comandos y advertencias.
- `apply`/`rollback` requieren `confirm: true` (el agente pide confirmación antes).
- Solo se aplican controles que el plan marcó `non-compliant` o `requires-review`.
- Requiere root para los cambios que lo necesitan (no se ejecuta `sudo`).
- Cada cambio se **respalda**, se **verifica** (no solo exit code) y se registra.

Ejemplo de diálogo del agente:

```text
Encontré 14 cambios recomendados.

Bajo riesgo:  1. ASLR   2. Restringir ptrace   3. Deshabilitar ICMP redirects
Medio:        4. Habilitar auditd   5. SSH MaxAuthTries
Alto riesgo:  6. Deshabilitar password de SSH   7. Firewall default deny

¿Qué querés aplicar?  [A] Bajo riesgo   [S] Seleccionar   [D] Ver detalles

KRN-003 — Restringir ptrace
Current: kernel.yama.ptrace_scope = 0
Target:  kernel.yama.ptrace_scope = 1
Impact:  Low
Apply? [yes/no]
```

Cobertura automática: sysctl (KRN-001..004), SSH (SSH-001..005), firewall
(FW-001, ufw/firewalld), servicios inseguros (SVC-001), auditd/rsyslog
(AUD-001/002, LOG-001), fstab (FS-001/002). El resto es `manual remediation
required`.

## Salida / persistencia

```
state/
└── <server-id>/
    ├── inventory.json
    ├── context.json
    ├── plans/<plan-id>.json
    ├── backups/<backup-id>.json      # contenido + sha256 del archivo
    ├── changes/<change-id>.json      # target, before/after, resultado
    ├── rollbacks/<rollback-id>.json  # estrategia + artefactos
    ├── verification/<ver-id>.json
    └── exceptions/
```

- `server-id` es estable: `srv-` + SHA-256 del `machine-id` (nunca el hostname
  desnudo, nunca el machine-id en claro). Si no hay `machine-id`, se usa un
  fallback por hostname y se marca como inestable.
- Escritura **atómica**: se escribe a un temporal, se valida y se hace `rename`.
  Nunca queda un JSON parcial.

> `state/` está en `.gitignore`: el inventario contiene datos del host.

## Qué registra el inventario

- **Identidad**: hostname, FQDN, machine-id, virtualización, arquitectura.
- **SO**: familia, distribución, versión, kernel.
- **Red**: interfaces (loopback vs normal), IPv4/IPv6, MAC, MTU, estado, rutas,
  gateways por defecto, DNS. (No modifica nada.)
- **Sockets en escucha**: protocolo, dirección, puerto, PID/proceso/ejecutable,
  y scope (`loopback` / `specific-address` / `wildcard` / `unknown`).
- **Usuarios/grupos**: UID/GID, shell, home, grupos, estado de bloqueo y tipo de
  cuenta (heurística marcada como *derived*).
- **Acceso privilegiado**: root, grupos admin, sudo disponible, sudoers
  (solo existencia de rutas, nunca contenido).
- **Servicios**: systemd (enabled/active/startup).
- **Paquetes**: dpkg y rpm (local, sin repos remotos).
- **Controles de seguridad**: SELinux, AppArmor, firewall, auditd, journald,
  rsyslog, SSH, agentes AV/EDR/HIDS (Wazuh es una capacidad más, no especial).
- **Filesystems**: mounts, opciones, capacidad, block devices.
- **Hora**: timezone, NTP, sincronización.
- **Contenedores**: presencia y versión de Docker, Podman, containerd,
  kubelet/k3s (sin inspeccionar workloads).

### Evidencia y procedencia

Los campos sujetos a inferencia usan `Evidence<T>` con `source`, `confidence`
(`observed` / `derived` / `unknown`) y `collectedAt`, para poder responder
siempre *"¿de dónde salió este dato?"*.

### Estados de recolección

Cada sección reporta su propio estado: `success`, `partial`, `unsupported`,
`insufficient-permissions`, `unavailable`, `error`. El fallo de una sección no
aborta el inventario.

## Desarrollo

```bash
bun run format     # biome format --write
bun run lint       # biome check
bun run typecheck  # tsc --noEmit
bun test           # tests (bun:test)
bun run build      # tsc -> dist/
```

Estructura:

```
src/hardening/            models, errors, exec, fsio, collectors, parsers,
                          inventory, validation, state
src/hardening/controls/   catálogo de controles (por dominio) + catalog.ts
src/hardening/planning/   context, applicability, risk, preconditions,
                          evaluate, questions, plan, presentation
src/hardening/remediation/ fsops, config, sysctl, ssh, firewall, services,
                          logging, filesystem, registry, run
.opencode/                agente, skills (discovery/planning/execution), tools
scripts/collect.ts        CLI de discovery
tests/                    discovery, planning y ejecución (+fixtures)
docs/ARCHITECTURE.md      arquitectura detallada (Fases 1-3)
```

## Seguridad

- Sin shell: los comandos son `argv` fijos definidos en el código
  (`execFile`, `shell: false`), con timeout y límite de salida.
- Sin `sudo`: si un dato requiere privilegios, la sección reporta
  `insufficient-permissions` en vez de fallar.
- Sin secretos: nunca se persisten hashes de `/etc/shadow`, claves, tokens ni
  variables de entorno. De sudoers solo se registra la existencia de rutas.
- Sin traversal: los `server-id` se validan y todo path resuelto debe quedar
  dentro de `state/`.

## Limitaciones (no implementado a propósito)

- Windows, remote fleet management, web UI, scheduler, orchestration, HA;
- scoring, pentesting, dashboards de compliance, policy-as-code complejo;
- remediación automática de controles que requieren criterio humano (el resto
  queda como `manual remediation required`);
- nftables: solo preview (no se generan reglas automáticamente);
- desinstalación de paquetes: no automática (`manual rollback required`);
- controles Windows/BSD y evidencia aún no recolectada (config SSH ampliada,
  sysctl en discovery): quedan `unknown`, nunca se inventan.

El motor transaccional es intencionalmente simple: backup + apply + verify +
rollback por control; no hay transacciones distribuidas ni event sourcing.

## Licencia

Uso interno. Ajustá la licencia según corresponda.

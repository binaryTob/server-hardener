# Server Hardener — Fase 1 (Discovery)

Framework interactivo de hardening de servidores. Esta **Fase 1** implementa
únicamente el núcleo de **descubrimiento (discovery) read-only**: observa el
estado actual del servidor y genera un **inventario validado y persistente**.

> La Fase 1 **no modifica** nada del servidor. No aplica hardening, no toca
> servicios, firewall, SSH, usuarios ni paquetes. Solo observa y registra
> evidencia.

## Filosofía

1. Nunca modificar un servidor antes de comprender su estado actual.
2. Nunca asumir que un servicio, puerto, usuario o configuración es innecesario
   solo porque parece inseguro.
3. Seguridad y disponibilidad tienen igual importancia.
4. Los cambios futuros serán explícitos, trazables, verificables y reversibles.
5. Toda recomendación futura conservará la evidencia que originó la decisión.
6. La Fase 1 no ejecuta remediaciones, comandos destructivos ni cambios de
   configuración; discovery es estrictamente read-only.

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
- Skill: `.opencode/skills/server-discovery/SKILL.md`
- Tools:
  - `hardening_inventory` — `collect` | `show` | `validate`
  - `hardening_state` — `status` | `list-inventories` | `load-inventory` | `validate-state`

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
comandos arbitrarios ni shell. Si pedís hardening en Fase 1, el agente explica
que todavía no está implementado.

## Salida / persistencia

```
state/
└── <server-id>/
    ├── inventory.json      # ServerInventory (schemaVersion: 1)
    ├── plans/  changes/  exceptions/  rollbacks/  verification/
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
src/hardening/        models, errors, exec, fsio, collectors, parsers,
                      inventory, validation, state
.opencode/            agent, skill, tools
scripts/collect.ts    CLI de discovery
tests/                parsers, inventory, persistence, security (+fixtures)
docs/ARCHITECTURE.md  arquitectura detallada
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

## Limitaciones de Fase 1 (no implementado a propósito)

- hardening, remediación, rollback y verificación de cambios;
- cambios de firewall, SSH, PAM, sysctl, filesystem o paquetes;
- motor de benchmarks CIS, OpenSCAP, perfiles de hardening, scoring;
- discovery completo de Windows/BSD.

Los contratos (`HardeningControl`, `HardeningPlan`, `ChangeRecord`,
`ExceptionRecord`, `RollbackRecord`, `VerificationResult`) ya existen en
`src/hardening/models.ts` para las fases siguientes.

## Licencia

Uso interno. Ajustá la licencia según corresponda.

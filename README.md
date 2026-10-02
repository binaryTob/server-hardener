# server-hardener

Agente **de OpenCode que corre en tu workstation** y hardeniza **un servidor
Linux objetivo por SSH**. El servidor objetivo **no instala nada**: ni OpenCode,
ni Bun, ni Node, ni este repo, ni API keys, ni un agente/daemon.

Es reutilizable para cualquier servidor al que tengas acceso SSH: no es fleet
management, no es multi-servidor, no es una plataforma.

```text
Workstation (OpenCode + server-hardener)  ── SSH ──▶  Servidor objetivo (sshd)
```

SSH es solo el transporte de las tools.

## Requisitos

- [Bun](https://bun.sh) ≥ 1.4 **en la workstation**.
- Acceso SSH al target con tu configuración normal: alias de `~/.ssh/config`,
  `user@host`, `user@IP`, o `host:puerto` para puertos no estándar; ssh-agent,
  `IdentityFile`, `ProxyJump` y `known_hosts` se respetan tal cual.
- En el target: root por SSH **o** un usuario admin con `sudo -n` sin password.
- No se usan ni almacenan credenciales: se delega en tu propio `ssh`.

## Puesta en marcha (solo en la workstation)

```bash
git clone <repo> server-hardener
cd server-hardener
bun install
opencode
```

Luego, dentro de OpenCode:

```text
> Hardenizá srv-ejemplo
> Hardenizá admin@192.0.2.10
> Hardenizá root@192.0.2.10:2222     # puerto no estándar
```

Si escribís *"hardenizá este servidor"* sin target, el agente **pregunta cuál**
(no asume `localhost`).

## Qué hace

1. Valida el target y prueba la conexión SSH.
2. Ejecuta **discovery remoto read-only** (SO, red, sockets, usuarios,
   servicios, paquetes, firewall/logging, mounts, contenedores).
3. Evalúa el catálogo de controles y agrupa en **SAFE / REVIEW / RISKY**
   (sin score numérico).
4. Pregunta **solo** el contexto operativo que cambia una decisión.
5. Por cada control elegido: `preview` → **confirmación explícita** → `apply`
   remoto (con backup en el target) → `verify` → `rollback` si falla.
6. Entrega un resumen final (aplicados / omitidos / fallidos / revertidos).

### CLI (read-only)

```bash
bun run inspect admin@192.0.2.10
```

## Tools

- `target` — `connect` | `info` | `clear` (target activo de la sesión).
- `inspect_system` — resumen del target (`inspect`, `last-run`).
- `inspect_security` — evaluación (`assess`, `explain`).
- `harden_sysctl` (KRN-*), `harden_ssh` (SSH-*), `harden_firewall` (FW-*),
  `harden_service` (SVC-*), `harden_logging` (LOG-*/AUD-*),
  `harden_filesystem` (FS-*): `inspect | preview | apply | verify | rollback`.

`apply` y `rollback` requieren `confirm: true` tras confirmación explícita. Las
tools **no aceptan comandos**: ejecutan operaciones predefinidas por `ssh` con
argv (sin shell local), con backup y verificación.

## Reglas de seguridad

- Nunca asume `localhost`: sin target, pregunta.
- Solo aplica controles `non-compliant` / `requires-review`.
- **Lockout = stop:** `PasswordAuthentication no` se rechaza sin ruta secundaria
  confirmada.
- Nunca reemplaza un firewall ni genera reglas nftables automáticamente; nunca
  cierra el acceso del operador (nunca default-deny primero).
- Tras cambios de SSH/firewall, verifica una **conexión SSH nueva** desde la
  workstation; si no puede confirmarla, verifica que el puerto admin siga
  escuchando y, si no, hace rollback.
- No instala dependencias del framework en el target (instalar `auditd` es una
  decisión explícita de hardening, no una dependencia).
- No captura ni guarda passwords. Requiere root o `sudo -n`.

## Backups y estado

- Backups **en el target**: `/var/backups/server-hardener/<run-id>/` con
  contenido, owner/group/mode y hash → rollback remoto.
- Estado mínimo **en la workstation** (se ignora en git):

```text
.server-hardener/
├── session.json           target activo de la sesión
├── last-run.json          aplicados/omitidos/fallidos/revertidos + verificación
└── optional-context.json  contexto operativo provisto por el operador
```

## Cobertura automática

- sysctl (KRN-001..004)
- SSH: perfil de directivas (SSH-001..005) y **SSH-007** (exponer solo el puerto
  admin), con backup + `sshd -t` + reload + verificación de reconexión
- firewall (FW-001, ufw/firewalld)
- servicios inseguros conocidos (SVC-001)
- logging/auditoría (AUD-001/002, LOG-001)
- fstab (FS-001/002)

Todo lo demás es `manual remediation required` (nunca se aplica a ciegas).

## Desarrollo

```bash
bun run format     # biome format --write
bun run lint       # biome check
bun run typecheck  # tsc --noEmit
bun test           # bun:test
bun run build      # tsc -> dist/
bun run inspect <target>   # evaluación read-only
```

Arquitectura: `docs/ARCHITECTURE.md`.

## Fuera de alcance (a propósito)

Fleet management, agentes/daemon remotos, API server, queue/scheduler, DB, web
UI, orchestrator, Ansible/Terraform, deployment remoto del framework, Windows,
scoring, pentesting, dashboards de compliance, motores de plan/estado complejos.

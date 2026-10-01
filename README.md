# server-hardener

Agente **de OpenCode que corre en tu workstation** y administra **un servidor
Linux objetivo por SSH**. El servidor objetivo no necesita nada instalado: ni
OpenCode, ni Bun, ni Node, ni el repo, ni API keys, ni un agente.

```text
git clone <repo> server-hardener && cd server-hardener
bun install
opencode
> Hardenizá admin@server.example
```

```text
Workstation (OpenCode + server-hardener)  ── SSH ──▶  Servidor objetivo (sshd)
```

SSH es solo el transporte de las tools. No es fleet management ni multi-servidor.

## Requisitos

- [Bun](https://bun.sh) ≥ 1.4 **en la workstation**.
- Acceso SSH al target (alias de `~/.ssh/config`, `user@host` o `user@IP`),
  con ssh-agent/claves y `known_hosts` configurados normalmente.
- En el target: root por SSH o un usuario admin con `sudo -n` sin password.

## Uso

Desde la workstation:

```text
opencode
```

Luego:

```text
> Hardenizá db.example
> Hardenizá admin@192.0.2.10
> Hardenizá root@server.example
```

El agente:

1. selecciona/valida el target y prueba la conexión SSH;
2. ejecuta discovery remoto read-only;
3. identifica SO, servicios, red y controles;
4. agrupa en **SAFE / REVIEW / RISKY** (sin score);
5. pregunta solo el contexto que cambia una decisión;
6. preview → confirmación → apply remoto (con backup en el target) → verify;
7. rollback cuando corresponde (incluida verificación de **nueva conexión SSH**
   tras cambios de SSH/firewall);
8. entrega un resumen.

### CLI (read-only)

```bash
bun run inspect admin@server.example
```

## Tools

- `target` — `connect` | `info` | `clear` (target por sesión).
- `inspect_system` / `inspect_security`.
- `harden_sysctl` (KRN-*), `harden_ssh` (SSH-*), `harden_firewall` (FW-*),
  `harden_service` (SVC-*), `harden_logging` (LOG-*/AUD-*),
  `harden_filesystem` (FS-*): `inspect|preview|apply|verify|rollback`.

`apply`/`rollback` requieren `confirm: true` (tras confirmación explícita). Las
tools no aceptan comandos: ejecutan operaciones predefinidas por `ssh` con
argv (sin shell local) y backup/verificación.

## Reglas de seguridad

- Nunca asume `localhost`: si no hay target, pregunta.
- Solo aplica controles `non-compliant`/`requires-review`.
- Lockout = stop: `PasswordAuthentication no` se rechaza sin ruta secundaria
  confirmada.
- Nunca reemplaza un firewall ni genera reglas nftables automáticamente; nunca
  cierra el acceso del operador (nunca default-deny primero).
- Tras SSH/firewall, verifica una **nueva** conexión SSH desde la workstation;
  si falla, intenta rollback.
- No instala nada en el target (instalar `auditd` es una decisión explícita de
  hardening, no una dependencia del framework).
- No captura ni guarda passwords. Requiere root o `sudo -n`.

## Backups y estado

- Backups **en el target**: `/var/backups/server-hardener/<run-id>/` con
  contenido, owner/group/mode y hash (rollback remoto).
- Estado mínimo **en la workstation**:

```text
.server-hardener/
├── session.json           target activo de la sesión
├── last-run.json          aplicados/omitidos/fallidos/revertidos + verificación
└── optional-context.json  contexto operativo provisto por el operador
```

## Cobertura automática

sysctl (KRN-001..004), SSH (SSH-001..005), firewall (FW-001, ufw/firewalld),
servicios inseguros conocidos (SVC-001), logging/auditoría (AUD-001/002,
LOG-001), fstab (FS-001/002). El resto es `manual remediation required`.

## Desarrollo

```bash
bun run format     # biome format --write
bun run lint       # biome check
bun run typecheck  # tsc --noEmit
bun test           # bun:test
bun run build      # tsc -> dist/
bun run inspect admin@server.example   # evaluación read-only de un target
```

Estructura: ver `docs/ARCHITECTURE.md`.

## Fuera de alcance (a propósito)

Fleet management, agentes/daemon remotos, API server, queue/scheduler, DB, web
UI, orchestrator, Ansible/Terraform, deployment remoto del framework, Windows,
scoring, pentesting, dashboards de compliance, motores de plan/estado complejos.

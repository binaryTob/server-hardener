# server-hardener

Agente **local** de OpenCode para hardenizar el servidor Linux donde corre.
No administra servidores remotos, no maneja flotas, no es un daemon ni una
plataforma.

```text
ssh servidor
git clone <repo> server-hardener && cd server-hardener
bun install
opencode
> Hardenizá este servidor.
```

El agente inspecciona el host local, propone cambios agrupados por riesgo,
pregunta solo lo necesario, aplica los aprobados y verifica cada uno. Podés
revertir si algo falla.

## Requisitos

- [Bun](https://bun.sh) ≥ 1.4 en el propio servidor.
- Linux (target del agente).

## Uso

### CLI (read-only)

```bash
bun run inspect
```

Imprime el resumen del host y la evaluación agrupada en SAFE / REVIEW / RISKY.

### Desde OpenCode

Agente: `.opencode/agents/server-hardener.md`.

> Hardenizá este servidor.

Workflow que sigue el agente:

```text
inspección local → clasificación por riesgo (SAFE/REVIEW/RISKY)
→ preguntas mínimas → selección del operador
→ preview → confirmación → backup → apply → verify → (rollback) → resumen
```

Tools disponibles:

- `inspect_system` — resumen del host (`inspect`, `last-run`).
- `inspect_security` — evaluación (`assess`, `explain`).
- `harden_sysctl` — KRN-* (`inspect|preview|apply|verify|rollback`).
- `harden_ssh` — SSH-*.
- `harden_firewall` — FW-*.
- `harden_service` — SVC-*.
- `harden_logging` — LOG-*/AUD-*.
- `harden_filesystem` — FS-*.

`apply` y `rollback` requieren `confirm: true` (el agente pide confirmación
explícita antes). Las tools no aceptan comandos: ejecutan operaciones
predefinidas, con backup y verificación.

Ejemplo de interacción:

```text
Host: srv-app-03 · OS: Ubuntu 24.04
Detected: OpenSSH, nginx, docker, ufw

SAFE (3)
- KRN-003 ASLR
- KRN-004 kernel pointers / ptrace
- NET-002 plaintext protocols
REVIEW (2)
- SVC-002 enabled services vs role
- FS-001 /tmp mount options
RISKY (2)
- SSH-002 SSH password authentication
- FW-001 firewall default policy

¿Empezamos por los SAFE?
```

## Estado local

```text
.server-hardener/
├── backups/               contenido + sha256 + modo/uid/gid del archivo
├── last-run.json          aplicados / omitidos / fallidos / revertidos
└── optional-context.json  contexto operativo provisto por el operador
```

Sin árboles por servidor, sin base de datos de planes.

## Qué hace automáticamente

- sysctl (KRN-001..004): drop-in `/etc/sysctl.d/99-server-hardener.conf` + runtime,
  detecta conflictos.
- SSH (SSH-001..005): backup, edición, `sshd -t`, **reload** (nunca restart);
  si `sshd -t` falla restaura el backup. `PasswordAuthentication no` se rechaza
  sin ruta secundaria confirmada.
- Firewall (FW-001): solo ufw/firewalld ya presentes; asegura el puerto admin
  antes de habilitar; **nunca** reemplaza un firewall ni genera reglas nftables.
- Servicios (SVC-001): solo protocolos inseguros conocidos; nunca servicios
  desconocidos.
- Logging/auditoría (AUD-001/002, LOG-001): habilitar; instalar solo con
  confirmación explícita y sin rollback automático.
- Filesystem (FS-001/002): opciones en `/etc/fstab`; nunca remonta solo.

Todo lo demás es `manual remediation required`.

## Desarrollo

```bash
bun run format     # biome format --write
bun run lint       # biome check
bun run typecheck  # tsc --noEmit
bun test           # bun:test
bun run build      # tsc -> dist/
bun run inspect    # evaluación read-only del host local
```

Estructura: ver `docs/ARCHITECTURE.md`.

## Fuera de alcance (a propósito)

Windows, administración remota, fleet management, base de datos, API server,
web UI, scheduler, daemon, multi-tenant, orquestación, dashboards de compliance,
pentesting, scoring numérico, motores de plan/estado complejos.

## Licencia

Uso interno. Ajustá según corresponda.

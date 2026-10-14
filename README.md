# Server-Hardener

Agente **de OpenCode que corre en tu workstation** y hardeniza **un servidor
Linux objetivo por SSH**. El servidor objetivo **no instala nada**: ni OpenCode,
ni Bun, ni Node, ni este repo, ni API keys, ni un agente/daemon.

Es reutilizable para cualquier servidor al que tengas acceso SSH: no es fleet
management, no es multi-servidor, no es una plataforma.

```text
Workstation (OpenCode + server-hardener)  ── SSH ──▶  Servidor objetivo (sshd)
```

SSH es solo el transporte de las tools.

El código TypeScript implementa discovery, evaluación determinista y operaciones
acotadas; OpenCode aporta la sesión de razonamiento y la interacción con el
operador. No hay un LLM embebido en el runtime ni una ejecución desatendida de
todos los controles.

## Requisitos

- [Bun](https://bun.sh) ≥ 1.4.3, OpenCode y OpenSSH **en la workstation**.
- Acceso SSH al target con tu configuración normal: alias de `~/.ssh/config`,
  `user@host`, `user@IP`, o `host:puerto` para puertos no estándar; ssh-agent,
  `IdentityFile`, `ProxyJump` y `known_hosts` se respetan tal cual.
- En el target: root por SSH **o** un usuario admin con `sudo -n` sin password.
- No se usan ni almacenan credenciales: se delega en tu propio `ssh`.

## Puesta en marcha (solo en la workstation)

```bash
git clone https://github.com/binaryTob/server-hardener.git
cd server-hardener
bun install --frozen-lockfile --ignore-scripts
opencode
```

Luego, dentro de OpenCode:

Seleccioná el agente `server-hardener` y proporcioná el target:

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
   remoto → `verify`. Los cambios de archivos guardan backups en el target;
   servicios/firewall registran su estado previo. Un fallo de sintaxis SSH restaura
   la configuración; un fallo de reconexión intenta rollback. Otros fallos deben
   revisarse y solicitar rollback explícito: no existe una transacción global.
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
- No reemplaza firewalls ni genera reglas nftables. La activación automática de
  UFW requiere puertos administrativos conocidos y reglas allow exitosas antes
  de habilitarlo. Firewalld requiere revisión manual de zonas/interfaces y puertos.
- Tras cambios de SSH/firewall, verifica una **conexión SSH nueva** desde la
  workstation, con hasta tres intentos; si falla, intenta rollback mediante la
  sesión conservada y vuelve a probar. Un socket escuchando no demuestra acceso.
- El rollback depende de que la sesión conservada siga operativa. No hay un timer
  remoto de recuperación: mantené una consola/ruta secundaria verificada para
  cambios de acceso. Ningún control garantiza por sí solo ausencia de lockout.
- Cambiar de target o puerto descarta el contexto operativo anterior; las
  confirmaciones de un servidor no se reutilizan para otro. Los aliases SSH que
  cambien de destino requieren reconfirmar el contexto.
- No instala dependencias del framework en el target (instalar `auditd` es una
  decisión explícita de hardening, no una dependencia).
- No captura ni guarda passwords. Requiere root o `sudo -n`.

## Backups y estado

- Backups **en el target**: `/var/backups/server-hardener/<run-id>/` con
  contenido, owner/group/mode y hash → rollback remoto con comprobación de
  integridad. Los archivos de backup se escriben con modo `0600`.
- La lectura/edición de configuración y el backup pasan por memoria de la
  workstation; no son una transferencia exclusivamente interna al servidor.
  Tratá la sesión de OpenCode y los registros operativos como información sensible.
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
- firewall (FW-001, activación UFW; firewalld/nftables son manuales)
- servicios inseguros conocidos (SVC-001)
- logging/auditoría (AUD-001/002, LOG-001)
- fstab (FS-001/002)

Todo lo demás es `manual remediation required` (nunca se aplica a ciegas).
Los checks modelan estados desconocidos y precondiciones pendientes; SAFE no
significa “aplicar sin autorización”. `localhost` explícito usa transporte local.

## Arquitectura y límites

```text
OpenCode agent + skills -> tools con argumentos acotados
  -> agent.ts -> discovery / controls / planning
  -> remediation -> Host (SSH por defecto) -> herramientas del SO
```

`controls/` y `planning/` separan aplicabilidad, compliance y riesgo de la
ejecución en `remediation/`. `transport/` valida el target y construye argv con
quoting remoto. `store.ts` guarda el estado local mínimo.

`preview` y `verify` no crean directorios de backup. La verificación automatizada
usa fixtures y `FakeHost`; no equivale a una matriz de validación sobre todas las
distribuciones, firewalls, PAM, includes/Match de SSH o servicios socket-activated.
Una configuración no representada debe revisarse manualmente. El rollback de
firewall restaura activación, no un snapshot completo de reglas; las reglas allow
añadidas necesitan revisión si la operación falla.

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
GitHub Actions ejecuta estos checks sin conectarse a servidores, audita las
dependencias y escanea el historial con Gitleaks. Reiniciá OpenCode después de
cambiar agentes, skills o tools para que recargue las definiciones.

## Fuera de alcance (a propósito)

Fleet management, agentes/daemon remotos, API server, queue/scheduler, DB, web
UI, orchestrator, Ansible/Terraform, deployment remoto del framework, Windows,
scoring, pentesting, dashboards de compliance, motores de plan/estado complejos.

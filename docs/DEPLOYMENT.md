# Deployment guide / Guía de despliegue

AUTOPRIV is a single static binary with **zero runtime dependencies** on every supported platform. This page is the complete deployment reference: requirements, build matrix, transfer, and platform coverage.

---

## English

### Requirements at a glance

| | Linux (full suite) | Windows (v1.9 enumeration) |
|---|---|---|
| Binary | `autoprivilege-linux-amd64` / `-arm64` | `autoprivilege-windows-amd64.exe` / `-arm64.exe` |
| OS | Any modern distro (glibc-free, kernel ≥ 2.17 in practice) | Windows 10 1809+ / Server 2019+ (arm64: 11+ / Server 2022+) |
| Runtime deps | **None** — static, `CGO_ENABLED=0` | **None** — uses only `reg.exe`, `whoami.exe`, `powershell.exe` (all built-in) |
| Privileges to run | Unprivileged user (root finds nothing new) | Unprivileged user (elevated token reports "already admin") |
| Build from source | Go 1.26+ | Go 1.26+ (cross-compiles from any OS) |

### Linux deployment

1. **Download a release binary** (statically linked, no glibc binding):

   ```bash
   curl -LO https://github.com/Ruby570bocadito/Auto-Privilege/releases/latest/download/autoprivilege-linux-amd64
   chmod +x autoprivilege-linux-amd64 && mv autoprivilege-linux-amd64 autoprivilege
   ./autoprivilege --help
   ```

2. **Or build from source** (no module dependencies to fetch — fully offline build):

   ```bash
   git clone https://github.com/Ruby570bocadito/Auto-Privilege.git
   cd Auto-Privilege
   CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o autoprivilege ./cmd/autoprivilege
   ```

3. **Transfer to the target** — the binary is a single ~8 MB file, `scp`/`curl`/base64-in-clipboard all work. Nothing to install, nothing to configure.

4. **Run it**: `./autoprivilege` scans read-only. Auto-exploitation is opt-in (`--exploit`), sorted safest-first under the `--risk` cap, and stops at the first `uid=0`.

### Windows deployment

1. **Download a release binary**:

   ```powershell
   curl -LO https://github.com/Ruby570bocadito/Auto-Privilege/releases/latest/download/autoprivilege-windows-amd64.exe
   .\autoprivilege-windows-amd64.exe --help
   ```

2. **Or build from source** (cross-compiles from Linux/macOS — no Windows toolchain needed):

   ```bash
   CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o autoprivilege.exe ./cmd/autoprivilege
   ```

3. **Antivirus note**: like every privilege-escalation auditor, the `.exe` inspects security-sensitive surfaces (SAM/SYSTEM paths, registry autologon keys, scheduled tasks). Some AV/EDR products flag that behavior pattern for unsigned binaries — test in your lab first, and only deploy on systems you are **authorized** to audit.

4. **Run it**: `.\autoprivilege.exe` enumerates read-only: token privileges (SeImpersonate → potato family), AlwaysInstallElevated, AutoLogon passwords, unquoted service paths, service/autorun/scheduled-task writable binaries, unattend/GPP credentials, PATH hijacks. Auto-exploitation is Linux-only in v1.9 — Windows findings come with the exact manual command for each technique (`--dry-run` shows the full plan).

### Platform coverage

| Phase | Linux | Windows |
|---|---|---|
| Scan (read-only) | 20 scanners (SUID/SGID, sudo, cron, passwd/shadow, docker, caps, NFS, services, kernel CVEs, creds, preload, sudoers, group, hooks, polkit, …) | 8 scanners (WINOS, WINPRIV, WINREG, WINSVC, WINAUTO, WINTASK, WINCRED, WINPATH) |
| Enumerate | vectors from the embedded GTFOBins db | manual technique vectors (PrintSpoofer/GodPotato, msiexec AIE, service planting, GPP decrypt, PATH hijack, …) |
| Auto-exploit | yes — safest-first, `--risk` cap, stops at uid=0 | not in v1.9 (honest no-op with the manual commands printed) |
| Reports | terminal, `--json`, `--report`, `--html`, `--sarif`, score, baseline diff | same five formats, same envelope |
| CI gates | `--fail-on`, `--fail-on-new`, `--min-score` | same three gates on Windows findings |

### CTF vs real engagements

- **CTF**: drop the binary, `./autoprivilege --exploit` (Linux) or `.\autoprivilege.exe --dry-run` (Windows — every vector prints its technique). The embedded GTFOBins db works air-gapped.
- **Real engagements**: scan-only by default; `--json --output` for evidence, `--sarif` for the dashboard, `--baseline`/`--fail-on-new=high` for progressive hardening. Windows enumeration is read-only by design — the only probe is a create+delete 0-byte temp file to test directory writability (ACLs are not readable from permission bits).

---

## Español

### Requisitos de un vistazo

| | Linux (suite completa) | Windows (enumeración v1.9) |
|---|---|---|
| Binario | `autoprivilege-linux-amd64` / `-arm64` | `autoprivilege-windows-amd64.exe` / `-arm64.exe` |
| SO | Cualquier distro moderna (sin glibc, estático) | Windows 10 1809+ / Server 2019+ (arm64: 11+ / Server 2022+) |
| Dependencias | **Ninguna** — estático, `CGO_ENABLED=0` | **Ninguna** — usa solo `reg.exe`, `whoami.exe`, `powershell.exe` (integrados) |
| Privilegios | Usuario sin privilegios (como root no encuentra nada nuevo) | Usuario sin privilegios (con token elevado informa "ya eres admin") |
| Compilar | Go 1.26+ | Go 1.26+ (cross-compile desde cualquier SO) |

### Despliegue en Linux

1. **Descarga el binario** (estático, sin dependencia de glibc):

   ```bash
   curl -LO https://github.com/Ruby570bocadito/Auto-Privilege/releases/latest/download/autoprivilege-linux-amd64
   chmod +x autoprivilege-linux-amd64 && mv autoprivilege-linux-amd64 autoprivilege
   ```

2. **O compila desde fuente** (sin dependencias que descargar — build 100 % offline):

   ```bash
   git clone https://github.com/Ruby570bocadito/Auto-Privilege.git
   cd Auto-Privilege
   CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o autoprivilege ./cmd/autoprivilege
   ```

3. **Transfiérelo** — un único fichero de ~8 MB; scp/curl/base64 sirven. Nada que instalar, nada que configurar.

4. **Ejecútalo**: `./autoprivilege` escanea en solo-lectura. El auto-exploit es opt-in (`--exploit`), ordenado de más seguro a más destructivo bajo el tope `--risk`, y se detiene al primer `uid=0`.

### Despliegue en Windows

1. **Descarga el binario**:

   ```powershell
   curl -LO https://github.com/Ruby570bocadito/Auto-Privilege/releases/latest/download/autoprivilege-windows-amd64.exe
   .\autoprivilege-windows-amd64.exe --help
   ```

2. **O compila desde fuente** (cross-compile desde Linux/macOS — sin toolchain de Windows):

   ```bash
   CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o autoprivilege.exe ./cmd/autoprivilege
   ```

3. **Nota sobre antivirus**: como todo auditor de escalada de privilegios, el `.exe` inspecciona superficies sensibles (rutas SAM/SYSTEM, claves de autologon del registro, tareas programadas). Algunos AV/EDR marcan ese patrón en binarios sin firma — pruébalo primero en tu lab y despliégalo solo en sistemas que estás **autorizado** a auditar.

4. **Ejecútalo**: `.\autoprivilege.exe` enumera en solo-lectura: privilegios del token (SeImpersonate → familia potato), AlwaysInstallElevated, contraseñas AutoLogon, rutas de servicio sin comillas, binarios escribibles de servicios/autoruns/tareas, credenciales unattend/GPP, secuestros de PATH. El auto-exploit es solo Linux en v1.9 — cada hallazgo Windows incluye el comando manual exacto de su técnica (`--dry-run` muestra el plan completo).

### CTF vs entornos reales

- **CTF**: suelta el binario, `./autoprivilege --exploit` (Linux) o `.\autoprivilege.exe --dry-run` (Windows — cada vector imprime su técnica). La base GTFOBins embebida funciona sin red.
- **Entornos reales**: solo-escaneo por defecto; `--json --output` como evidencia, `--sarif` para el dashboard, `--baseline`/`--fail-on-new=high` para endurecimiento progresivo. La enumeración Windows es solo-lectura por diseño — la única sonda es crear+borrar un fichero temporal de 0 bytes para probar la escritura de un directorio (las ACL no se leen de los bits de permiso).

<p align="center"><img src="docs/images/banner.png" alt="Banner de AUTOPRIV" width="820"></p>

<h1 align="center">AUTOPRIV</h1>

<p align="center"><b>Suite automatizada de escalada de privilegios en Linux — escanea, enumera, hazte root.</b><br>
Un binario Go. Cero dependencias. Resultados honestos.</p>

<p align="center">
  <a href="https://github.com/Ruby570bocadito/Auto-Privilege/actions/workflows/ci.yml"><img src="https://github.com/Ruby570bocadito/Auto-Privilege/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white" alt="Go 1.26">
  <img src="https://img.shields.io/github/v/tag/Ruby570bocadito/Auto-Privilege?label=release&sort=semver" alt="Release">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/tests-58%20passing-brightgreen" alt="Tests">
</p>

<p align="center"><img src="docs/images/demo-lab.gif" alt="Demo de AUTOPRIV: escaneo, plan dry-run, escalada SUID hasta uid=0 en el laboratorio rootless" width="720"></p>

---

## Qué es AUTOPRIV?

AUTOPRIV es una herramienta post-explotación para trabajo de seguridad Linux **autorizado**: laboratorios, CTFs y sistemas propios. Dejas el binario estático en una máquina, audita el sistema en modo solo-lectura en segundos y te dice — con evidencias — cada vía de escalada local que encuentra. Si se lo pides, recorre esas vías por ti, siempre de la técnica más segura a la más agresiva, y se detiene en cuanto consigue `uid=0`.

Está pensada para dos momentos muy distintos. En un engagement es la forma más rápida de responder "puede esta máquina ser root, y cómo?". En una sesión de estudio es un profesor: cada hallazgo explica el vector, el riesgo y el comando exacto que ejecutaría un operador, para que puedas reproducirlo a mano y aprender la técnica de verdad.

Todo en ella es deliberadamente honesto. Los vectores que no puede verificar automáticamente se marcan `manual` en vez de fingir. Los CVEs de kernel coincidentes avisan *verify before use (heuristic)*. Cuando llega a root imprime la evidencia `uid=0` desde la propia shell, y cuando no llega, lo dice y sale con código 1.

## Lo más importante

| | |
|---|---|
| **16 escáneres de solo-lectura** | SUID/SGID, reglas y versión de sudo, cron escribible, inyección en passwd/shadow, grupo docker, contexto de runtimes de contenedores (podman/containerd/daemon docker), capabilities (bitmask y file caps), NFS, directorios PATH escribibles, servicios systemd, CVEs de kernel, credenciales en history/configs, metadata cloud |
| **75 técnicas GTFOBins + 31 sgid** | embebidas en el binario — funciona air-gapped; actualizable desde upstream con un comando (`--list-gtfo` muestra la sección sgid) |
| **Auto-explotación de más seguro a más agresivo** | técnicas ordenadas por riesgo, tope con `--risk`, parada con `--one-shot` al primer root |
| **Dos modos de salida** | terminal humano con rampa de color, o `--json` para máquinas (`--output fichero` lo persiste, 0600); `--report` markdown opcional con evidencias |
| **Laboratorio rootless** | `lab/rootless_lab.sh` monta una caja fake-vulnerable dentro de un user namespace — sin Docker, sin root real, no toca tu sistema |
| **Amigable para scripts** | `--quiet` + códigos de salida (`0` root, `1` sin root, `2` error), `--no-color` automático al pipear, `NO_COLOR` respetado |

## Cómo funciona

**1 — Escaneo.** Cada escáner corre en solo-lectura y emite hallazgos con etiquetas de riesgo: `[.]` informativo, `[+]` explotable, `[!]` destacable. La fase nunca modifica la máquina — lee sudoers, cron, passwd/shadow, mounts, capabilities, versión de kernel, history y ficheros de configuración.

**2 — Enumeración.** Los hallazgos se convierten en vectores. Cada vector recibe una técnica concreta y el comando exacto que se ejecutaría, sacado de la base GTFOBins embebida cuando aplica (SUID `python3`, `find`, `vim`, ...). Los vectores que necesitan decisión humana se marcan `manual`.

**3 — Explotación (opt-in).** Con `--exploit`, los vectores se ordenan de más seguro a más agresivo y se ejecutan bajo el tope de riesgo. La sesión termina en cuanto se confirma `uid=0` — o tras agotar la lista, con un honesto `no root` y código de salida 1.

## Inicio rápido

**Descarga un binario de release** (linux amd64 / arm64, enlazado estático):

```bash
curl -LO https://github.com/Ruby570bocadito/Auto-Privilege/releases/latest/download/autoprivilege-linux-amd64
chmod +x autoprivilege-linux-amd64 && mv autoprivilege-linux-amd64 autoprivilege
./autoprivilege --help
```

**O compílalo desde fuente** (Go 1.26+, sin dependencias que descargar):

```bash
git clone https://github.com/Ruby570bocadito/Auto-Privilege.git
cd Auto-Privilege
go build -o autoprivilege .
./autoprivilege
```

**O pruébalo primero en el laboratorio seguro:**

```bash
lab/rootless_lab.sh                  # escaneo solo-lectura de una caja fake vulnerable
lab/rootless_lab.sh --exploit        # míralo escalar hasta uid=0 en un namespace
```

## Uso

```
autoprivilege [opciones]

Modos:
  (por defecto)             escaneo + enumeración (solo-lectura, sin cambios)
  --exploit                 auto-explota los vectores encontrados, del riesgo menor al mayor
  --dry-run                 escanea y muestra qué ejecutaría sin correr nada
  --list-gtfo               imprime la base GTFOBins embebida
  --update-gtfobins         refresca la base GTFOBins desde upstream (persistida)

Filtrado:
  --vector lista            separada por comas: suid,sgid,sudo,cron,passwd,shadow,
                            docker,container,caps,nfs,path,service,kernel,cred
  --risk nivel              riesgo máximo de auto-explotación: safe|low|medium|high|danger
  --one-shot                parar tras el primer exploit exitoso
  --lhost ip                host del listener de reverse-shell (autodetectado)
  --lport puerto            puerto del listener (por defecto 4444)

Salida:
  --json                    informe legible por máquina en stdout
  --output fichero          escribe el informe JSON a un fichero (0600)
  --report fichero          escribe además un informe markdown con evidencias
  --quiet                   sin salida; código 0 = root, 1 = sin root
  --no-color                desactiva colores ANSI (auto al pipear)
  --verbose                 logging de debug en stderr
  --log fmt                 formato de log: text|json (stderr)

Varios:
  --stealth                 jitter entre escáneres y exploits
  --scan-timeout dur        timeout para comandos externos del escaneo (por defecto 5s)
  --rooteame ruta           carga un módulo .ko al conseguir root (solo lab)
  --version                 imprime versión
  -h, --help                esta ayuda
```

Códigos de salida: `0` root conseguido · `1` sin root · `2` error de uso o ejecución.

## Vectores cubiertos

| Vector | Qué comprueba | Auto? |
|---|---|---|
| `suid` | Binarios SUID (walk recursivo) + coincidencia GTFOBins (`python3`, `find`, ...) | sí |
| `sgid` | Binarios SGID con grupo root — escalación de grupo, vector manual (técnica `sgid` de GTFOBins preferente; el fallback SUID se declara en la nota) | manual |
| `sudo` | reglas sudo -l, entradas NOPASSWD, CVEs por versión de sudo (rango Baron Samedit) | parcial |
| `cron` | `/etc/cron*` escribible, jobs cron con PATH | sí |
| `passwd` | `/etc/passwd` escribible — inyección de usuario root | sí |
| `shadow` | `/etc/shadow` legible — extracción de hashes | sí |
| `docker` | grupo docker / acceso al socket → root del host | parcial |
| `container` | indicador del contenedor actual con evidencia de privilegio/namespace de PID, sockets podman/containerd, daemon docker alcanzable | parcial |
| `caps` | procesos cap_setuid, file capabilities (`getcap -r /`) | sí |
| `nfs` | exports no_root_squash | manual |
| `path` | directorios escribibles en el PATH de root | sí |
| `service` | unidades systemd escribibles / secuestro PathChanged | sí |
| `kernel` | CVEs por rango de kernel: Dirty Pipe, OverlayFS, StackRot, nf_tables; PwnKit vía pkexec | parcial |
| `cred` | contraseñas en history, configs, metadata cloud (imds, timeout 800 ms) | sí |

`parcial` significa que AUTOPRIV prepara el terreno (checks de versión, parseo de reglas) pero un humano confirma el paso final — la herramienta lo dice en vez de fingirlo.

## Formatos de salida

**Terminal** — hallazgos coloreados con evidencia por línea y resumen final:

```
[!] CRON → Writable cron job — inject command (/etc/cron.d/backup)
[+] SUID → SUID binary: find (GTFOBins: true) (/usr/bin/find)

Summary — 9 exploitable
  vectors  9  (auto 6 · manual 3)
  risks    LOW 1  MEDIUM 1  HIGH 6  DANGER 1
  rooted   NO
```

**JSON** (`--json`) — un objeto en stdout, listo para `jq`:

```bash
$ autoprivilege --json | jq '.summary'
{
  "findings": 11,
  "exploitable": 2,
  "vectors": 2,
  "auto": 0,
  "manual": 2,
  "risks": { "MEDIUM": 9, "HIGH": 2 },
  "rooted": false
}
```

**Markdown** (`--report audit.md`) — secciones por vector con el comando, el riesgo y las líneas de evidencia, ideal como apéndice de un engagement.

## El laboratorio rootless

El lab es una caja fake comprometida construida dentro de un **user namespace** (`unshare -r -m`): un `/etc` temporal con passwd/shadow/cron escribibles, un `/usr/bin` bindeado con `python3` y `find` SUID. Los bits SUID solo dan el root mapeado del namespace — nunca el tuyo. Es la forma más segura de demostrar, testear y capturar el ciclo completo escaneo → enumeración → root sin Docker ni permisos especiales:

```bash
lab/rootless_lab.sh                             # solo escaneo
lab/rootless_lab.sh --exploit --dry-run         # muestra el plan
lab/rootless_lab.sh --exploit --risk=danger     # escalada completa hasta uid=0
lab/rootless_lab.sh --shell                     # shell interactiva del namespace
```

## Testing con Docker

Cuatro contenedores cubren la matriz: `vulnerable` (debe encontrar vectores), `clean` (no debe encontrar ninguno), `edgecases` (permisos raros, symlinks) y `autoprivilege-test` (ejecuta la suite completa):

```bash
cd docker && docker compose up --build
./docker/test_runner.sh
```

## Seguridad y ética

AUTOPRIV es solo para **trabajo de seguridad autorizado**: tus propias máquinas, laboratorios, CTFs y engagements con permiso por escrito. Por defecto no cambia nada; la explotación solo ocurre tras `--exploit`, e incluso así prefiere técnicas reversibles y se detiene en el riesgo que permitiste. No lo ejecutes en sistemas que no poseas o no tengas autorización explícita para auditar.

## Tests y CI

58 tests unitarios cubren los puntos delicados a propósito: el arte del banner se verifica decodificándolo rune a rune (se acabó el ASCII art mal escrito), el parseo de CSV de vectores, la ordenación de riesgos, los rangos de CVEs de kernel, los rangos de versiones de sudo, los timeouts de explotación, las regresiones de quoting de shell, los guards de spool, los formatos de hash y el escape de markdown, además del walk recursivo SUID/SGID (recursión, salto de symlinks, deduplicación, límite de profundidad y las raíces lib64), la clasificación honesta de SGID con procedencia de técnica declarada, el timeout configurable de escaneo, las heurísticas de runtimes de contenedores (evidencia de cgroups, sockets objetivo, vectores de breakout, detección de privileged/namespace de PID), la tabla estructural de simetría de selección de vectores (cada nombre de `--vector` produce solo su propia categoría), la captura/persistencia de técnicas sgid de GTFOBins y el fichero JSON de `--output` (forma y permisos 0600). La CI ejecuta build, vet, gofmt y la suite completa con `-count=1` en cada push.

## Licencia

MIT — ver [LICENSE](LICENSE).

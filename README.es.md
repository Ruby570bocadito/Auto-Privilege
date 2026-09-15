<p align="center"><img src="docs/images/banner.png" alt="Banner de AUTOPRIV" width="820"></p>

<h1 align="center">AUTOPRIV</h1>

<p align="center"><b>Suite automatizada de escalada de privilegios en Linux — escanea, enumera, hazte root.</b><br>
Un binario Go. Cero dependencias. Resultados honestos.</p>

<p align="center">
  <a href="https://github.com/Ruby570bocadito/Auto-Privilege/actions/workflows/ci.yml"><img src="https://github.com/Ruby570bocadito/Auto-Privilege/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white" alt="Go 1.26">
  <img src="https://img.shields.io/github/v/tag/Ruby570bocadito/Auto-Privilege?label=release&sort=semver" alt="Release">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
</p>

<p align="center"><img src="docs/images/demo-scan.gif" alt="Escaneo real de AUTOPRIV: banner, hallazgos y score de endurecimiento" width="820"></p>
<p align="center"><img src="docs/images/demo-ci-gate.gif" alt="Puerta de regresión CI: baseline, aterriza un secreto, --fail-on-new=high tripia con exit 3" width="820"></p>
<p align="center"><i>Salida real de terminal — sin maquetas. Más medios abajo: el <a href="#formatos-de-salida">informe HTML</a>, el playbook de endurecimiento y el catálogo de vectores.</i></p>

---

## Qué es AUTOPRIV?

AUTOPRIV es una herramienta post-explotación para trabajo de seguridad Linux **autorizado**: laboratorios, CTFs y sistemas propios. Dejas el binario estático en una máquina, audita el sistema en modo solo-lectura en segundos y te dice — con evidencias — cada vía de escalada local que encuentra. Si se lo pides, recorre esas vías por ti, siempre de la técnica más segura a la más agresiva, y se detiene en cuanto consigue `uid=0`.

Está pensada para dos momentos muy distintos. En un engagement es la forma más rápida de responder "puede esta máquina ser root, y cómo?". En una sesión de estudio es un profesor: cada hallazgo explica el vector, el riesgo y el comando exacto que ejecutaría un operador, para que puedas reproducirlo a mano y aprender la técnica de verdad.

Todo en ella es deliberadamente honesto. Los vectores que no puede verificar automáticamente se marcan `manual` en vez de fingir. Los CVEs de kernel coincidentes avisan *verify before use (heuristic)*. Cuando llega a root imprime la evidencia `uid=0` desde la propia shell, y cuando no llega, lo dice y sale con código 1.

## Lo más importante

| | |
|---|---|
| **20 escáneres de solo-lectura** | SUID/SGID, reglas y versión de sudo, cron escribible (+ candidatos de inyección wildcard), inyección en passwd/shadow, grupo docker, contexto de runtimes de contenedores (podman/containerd/daemon docker), capabilities (bitmask y file caps), NFS (no_root_squash + exports rw sin host), directorios PATH escribibles, servicios systemd, CVEs de kernel, credenciales en history/configs, metadata cloud, `ld.so.preload`, sudoers escribible (fichero, directorio y drop-ins por fichero), `/etc/group` escribible, hooks de login escribibles (`/etc/environment`, `/etc/profile.d`, `/etc/profile`, `/etc/bash.bashrc`) |
| **75 técnicas GTFOBins + 31 sgid** | embebidas en el binario — funciona air-gapped; actualizable desde upstream con un comando (`--list-gtfo` muestra la sección sgid) |
| **Score de endurecimiento** | cada escaneo termina con una cifra determinista 0–100 de postura — ponderada por riesgo y explotabilidad — para que los diffs `--baseline` lean `score 60 → 85` en lugar de recuentos crudos |
| **Playbook de endurecimiento** | `--explain cron` (o `all`) imprime los pasos exactos de remediación por fuente de hallazgo; `--report` incrusta una sección `## Hardening plan` construida con las fuentes realmente detectadas |
| **Auto-explotación de más seguro a más agresivo** | técnicas ordenadas por riesgo, tope con `--risk`, parada con `--one-shot` al primer root |
| **Cinco formatos de salida** | terminal humano con rampa de color, `--json` para máquinas (`--output fichero` lo persiste, 0600), `--report` markdown con evidencias, página `--html` autocontenida para stakeholders, y `--sarif` para los dashboards de code-scanning de GitHub/GitLab |
| **Tres puertas CI** | `--fail-on riesgo` falla cuando la superficie EXISTE en/por encima de un riesgo; `--fail-on-new` (umbral opcional: `--fail-on-new=high`) falla solo cuando CRECE — el veredicto de regresión para pipelines de endurecimiento progresivo; `--min-score n` falla mientras la cifra de postura esté bajo el suelo |
| **Laboratorio rootless** | `lab/rootless_lab.sh` monta una caja fake-vulnerable dentro de un user namespace — sin Docker, sin root real, no toca tu sistema |
| **Amigable para scripts** | `--quiet` + códigos de salida (`0` root, `1` sin root, `2` error, `3` puerta de política), `--no-color` automático al pipear, `NO_COLOR` respetado, `--parallel` recorta el tiempo de escaneo con resultados byte-idénticos |

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
  --list-vectors            imprime el catálogo de vectores soportados
  --completion shell        imprime un script de completado: bash, zsh o fish
  --explain fuente          playbook de endurecimiento de una fuente (o all)
  --update-gtfobins         refresca la base GTFOBins desde upstream (persistida)

Filtrado:
  --vector lista            separada por comas: suid,sgid,sudo,cron,passwd,shadow,
                            docker,container,caps,nfs,path,service,kernel,cred,
                            preload,sudoers,group,hooks,all
  --risk nivel              riesgo máximo de auto-explotación: safe|low|medium|high|danger
  --one-shot                parar tras el primer exploit exitoso
  --lhost ip                host del listener de reverse-shell (autodetectado)
  --lport puerto            puerto del listener (por defecto 4444)

Salida:
  --json                    informe legible por máquina en stdout
  --output fichero          escribe el informe JSON a un fichero (0600)
  --report fichero          escribe además un informe markdown con evidencias
  --html fichero            escribe un informe HTML autocontenido (0600)
  --sarif fichero           informe SARIF 2.1.0 para dashboards de code-scanning
  --sarif-stdout            imprime el log SARIF a stdout (no con --json)
  --baseline fichero        compara los hallazgos contra un informe previo --json/--output
  --quiet                   sin salida; código 0 = root, 1 = sin root
  --no-color                desactiva colores ANSI (auto al pipear)
  --verbose                 logging de debug en stderr
  --log fmt                 formato de log: text|json (stderr)

Varios:
  --ignore lista            excluye fuentes de hallazgos por completo: p. ej. CRED,CONTAINER
  --parallel                ejecuta los escáneres en paralelo (mismos resultados, más rápido)
  --stealth                 jitter entre escáneres y exploits
  --scan-timeout dur        timeout para comandos externos del escaneo (por defecto 5s)
  --fail-on riesgo          código 3 si hay hallazgos explotables >= riesgo
                            (low|medium|high|danger) — puerta de endurecimiento CI
  --fail-on-new [riesgo]    código 3 si aparecen hallazgos explotables NUEVOS vs
                            --baseline — puerta de regresión (la exige); umbral
                            opcional: --fail-on-new=low|medium|high|danger
  --min-score n             código 3 mientras el score de endurecimiento esté
                            bajo el suelo (1-100) — puerta de postura; 0 la desactiva
  --rooteame ruta           carga un módulo .ko al conseguir root (solo lab)
  --version                 imprime versión
  -h, --help                esta ayuda

Ejemplos:
  autoprivilege                          auditoría solo-lectura de esta máquina
  autoprivilege --parallel               la misma auditoría, escáneres concurrentes
  autoprivilege --exploit --risk=low     solo los auto-exploits más seguros
  autoprivilege --vector=suid,sudo       centrarse en dos vectores
  autoprivilege --json > report.json     salida amigable para CI
  autoprivilege --report audit.md        informe markdown con evidencias
  autoprivilege --html audit.html       página HTML para stakeholders
  autoprivilege --sarif audit.sarif      subida al code-scanning de GitHub
  autoprivilege --quiet --sarif-stdout | visor-sarif   el log por pipe
  autoprivilege --explain cron           cómo cerrar los hallazgos CRON
  autoprivilege --ignore CRED,CONTAINER  scan CI sin las fuentes ruidosas
  autoprivilege --output base.json       instantánea, endurecer, y luego:
  autoprivilege --baseline base.json     muestra hallazgos nuevos/resueltos
  autoprivilege --quiet --fail-on high   puerta: exit 3 en HIGH explotables
  autoprivilege --baseline base.json --fail-on-new   CI: falla solo en regresiones
  autoprivilege --baseline base.json --fail-on-new=high   solo regresiones HIGH+
  lab/rootless_lab.sh --exploit          demo rootless en un lab seguro
```

Códigos de salida: `0` root conseguido · `1` sin root · `2` error de uso o ejecución · `3` una puerta CI tripó — `--fail-on` política, `--fail-on-new` regresión o `--min-score` postura (las puertas ganan sobre `1`; todos los informes se escriben igualmente).

¿No sabes qué acepta `--vector`? `--list-vectors` imprime el catálogo — cada nombre de vector con una descripción de una línea de qué inspecciona realmente, leída de la misma tabla que usa el binario, así la documentación nunca puede divergir del código:

<p align="center"><img src="docs/images/screenshot-vectors.png" alt="--list-vectors: el catálogo de 18 vectores" width="640"></p>

## Vectores cubiertos

| Vector | Qué comprueba | Auto? |
|---|---|---|
| `suid` | Binarios SUID (walk recursivo) + coincidencia GTFOBins (`python3`, `find`, ...) | sí |
| `sgid` | Binarios SGID con grupo root — escalación de grupo, vector manual (técnica `sgid` de GTFOBins preferente; el fallback SUID se declara en la nota) | manual |
| `sudo` | reglas sudo -l, entradas NOPASSWD, CVEs por versión de sudo (rango Baron Samedit) | parcial |
| `cron` | `/etc/cron*` escribible, jobs cron con PATH, candidatos de inyección wildcard en schedules de root (`tar`/`rsync`/`zip`/`7z` con argumentos `*`) | sí |
| `passwd` | `/etc/passwd` escribible — inyección de usuario root | sí |
| `shadow` | `/etc/shadow` legible — extracción de hashes | sí |
| `docker` | grupo docker / acceso al socket → root del host | parcial |
| `container` | indicador del contenedor actual con evidencia de privilegio/namespace de PID, sockets podman/containerd, daemon docker alcanzable | parcial |
| `caps` | procesos cap_setuid, file capabilities (`getcap -r /`) | sí |
| `nfs` | exports `no_root_squash` (explotable) y exports `rw` sin restricción de host (informativo) | manual |
| `path` | directorios escribibles en el PATH de root | sí |
| `service` | unidades systemd Y scripts init.d de SysV escribibles (ambos ejecutan como root en boot/restart) | sí |
| `kernel` | CVEs por rango de kernel: Dirty Pipe, Dirty Cow, OverlayFS, StackRot, nf_tables; PwnKit vía pkexec | parcial |
| `cred` | contraseñas en history, configs, metadata cloud (imds, timeout 800 ms) | sí |
| `preload` | `/etc/ld.so.preload` no vacío (se carga con euid 0 en cada binario SUID) y `ld.so.conf`/`ld.so.conf.d` escribibles (rutas de búsqueda de librerías absorbidas por el próximo ldconfig) — HIGH/explotable si es escribible, informativo si no | manual |
| `sudoers` | `/etc/sudoers` escribible (añadir regla NOPASSWD, auto) o `/etc/sudoers.d` escribible (drop-in, manual: sudo exige ficheros de root); el pase por fichero también detecta drop-ins root-owned escribibles tras un directorio cerrado | parcial |
| `group` | `/etc/group` escribible — añádete a sudo/wheel/docker, efectivo en el próximo login | manual |
| `hooks` | hooks de login escribibles: `/etc/environment` (LD_PRELOAD en cada sesión), `/etc/profile.d`, `/etc/profile`, `/etc/bash.bashrc` | manual |

`parcial` significa que AUTOPRIV prepara el terreno (checks de versión, parseo de reglas) pero un humano confirma el paso final — la herramienta lo dice en vez de fingirlo.

Los sondeos `docker`/`container` heredan el entorno de tu shell, así que un daemon configurado vía `DOCKER_HOST` (remoto o local) cuenta como alcanzable — el hallazgo dice "verify rootful vs rootless" porque un daemon rootless contiene el breakout clásico.

## Formatos de salida

**Terminal** — hallazgos coloreados con evidencia por línea y resumen final (salida real del laboratorio rootless; dentro del user namespace la herramienta arranca como root mapeado, por eso `rooted YES`):

```
  ── Findings ──
  [.] SUID → SUID binary: find (GTFOBins: true) (/usr/bin/find)
  [!] SUID → SUID binary: python3.13 (GTFOBins: true) (/usr/bin/python3.13)
  [!] CRON → Writable cron job — inject command (/etc/cron.d/backup)
  [!] FILE → Writable /etc/passwd — inject root user (/etc/passwd)
  [!] FILE → Readable /etc/shadow — crack root hash (/etc/shadow)
  [*] FILE → Writable /etc/shadow — set root password (/etc/shadow)
  [~] CAPS → Process holds CAP_SETUID — can become root in-process (cap_setuid)
  [!] SERVICE → Writable systemd service — hijack execution (/etc/systemd/system/vuln.service)

  ── Summary ─────────────────────────────
   findings   12  (exploitable 9)
   score      31/100
   vectors    9  (auto 6 · manual 3)
   risks      LOW 3  MEDIUM 1  HIGH 7  DANGER 1
   rooted     YES
   time       1.7s
```

**JSON** (`--json`) — un objeto en stdout, listo para `jq` (el progreso del lab va a stderr, así que el pipe queda limpio):

```bash
$ lab/rootless_lab.sh --json --quiet | jq '.summary'
{
  "findings": 12,
  "exploitable": 9,
  "score": 31,
  "vectors": 9,
  "auto": 6,
  "manual": 3,
  "risks": { "DANGER": 1, "HIGH": 7, "LOW": 3, "MEDIUM": 1 },
  "rooted": true
}
```

**Markdown** (`--report audit.md`) — una tabla resumen con los totales de un vistazo (hallazgos, explotables, score de endurecimiento, vectores auto/manual, distribución de riesgos), secciones por vector con el comando, el riesgo y las líneas de evidencia, y una sección `## Hardening plan`: el playbook exacto de remediación para cada fuente que el scan realmente detectó. Ideal como apéndice de un engagement que lleva su propia checklist.

**HTML** (`--html audit.html`) — la página para compartir: un único documento autocontenido (CSS inline, cero recursos externos, sin JavaScript) que abre desde `file://` en cualquier portátil, air-gapped incluido. Tarjetas de resumen, la barra de distribución de riesgos, la tabla de hallazgos con badges coloreados, el plan de endurecimiento como playbooks plegables por fuente y el comando de cada vector en un bloque listo para copiar — todo renderizado desde el mismo buildReport que produce la exportación JSON, así la página nunca puede discrepar de la salida de máquina. Cada valor dinámico pasa por escape HTML (un fichero de credenciales que contenga `<script>` se renderiza como texto, testeado) y el fichero cae a 0600 por la misma escritura atómica que los demás informes. Adjúntalo al informe del engagement y envíalo:

<p align="center"><img src="docs/images/screenshot-html-report.png" alt="El informe --html abierto en un navegador: tarjetas de resumen, barra de riesgos y tabla de hallazgos" width="820"></p>

**SARIF** (`--sarif audit.sarif`) — los hallazgos vestidos de log SARIF 2.1.0, el formato que el tab de code-scanning de GitHub, GitLab y cualquier visor SARIF ingieren de forma nativa: una regla por fuente de hallazgo, niveles `error`/`warning`/`note` mapeados desde la escala de riesgo, ubicaciones `file://` para targets que son rutas (los targets no-ruta como `ALL` o los CVE ids se incrustan en el mensaje). Escrito a 0600 como el resto de artefactos. Súbelo con `github/codeql-action/upload-sarif@v3` y el escaneo aparece en la pestaña Security — sin conversores, sin dependencias externas.

**Diff contra baseline** (`--baseline prev.json`) — el ciclo de endurecimiento, cerrado: haz una instantánea con `--output base.json`, corrige lo que puedas, vuelve a escanear contra la instantánea y la herramienta clasifica cada hallazgo como **nuevo** (la superficie creció) o **resuelto** (el arreglo funcionó), con clave fuente+objetivo para que un reordenado o un cambio de redacción nunca finja un cambio. El diff trae la trayectoria del score de endurecimiento (`score 60 → 85`; los baselines anteriores a la métrica muestran `baseline predates scoring` en vez de fingir una regresión) y aparece en el terminal, en el JSON (clave `"diff"` con `new`/`resolved`/`new_exploitable`/`score_after`/`summary_before`) y en una sección `## Diff vs baseline` del reporte markdown:

```bash
$ autoprivilege --output base.json          # día 0: instantánea
$ # ... endurecer la máquina ...
$ autoprivilege --baseline base.json        # día N: verificar
  ── Diff vs baseline ─────────────────────
   new        1  (exploitable 1)
   resolved   3
   score      60 → 85
```

**Puerta de endurecimiento CI** (`--fail-on`) — convierte el escaneo en una comprobación de política: `--quiet --fail-on high` sale con código `3` cuando existe al menos un hallazgo explotable en o por encima del umbral, así un pipeline (o un cron que envía informes) falla ruidosamente en cuanto la superficie medida regresa. **Puerta de regresión** (`--fail-on-new [riesgo]`, exige `--baseline`) — el veredicto CI más afilado: código `3` solo cuando aparece un hallazgo explotable NUEVO respecto a la instantánea, de modo que el progreso del endurecimiento nunca falla el pipeline y una regresión siempre lo falla. El umbral opcional afina el veredicto: `--fail-on-new` a secas tripia con cualquier hallazgo explotable nuevo, `--fail-on-new=high` solo cuando la regresión es HIGH o peor — el ruido de riesgo bajo sigue en verde mientras una vía de escalada real tumba el build (los umbrales inválidos fallan en el parseo, exit 2). **Puerta de postura** (`--min-score n`) — el tercer veredicto, por cifra en vez de por recuento: código `3` mientras el score de endurecimiento esté bajo el suelo (`--quiet --min-score 70` falla hasta que la máquina puntúe 70+), el compañero perfecto de la trayectoria del score del `--baseline` — endurece la caja, mira `score 40 → 85`, y la puerta se pone verde sola. Las tres puertas comparten el contrato de exit 3 y se componen; los veredictos de política y regresión (que nombran su hallazgo) llevan precedencia de mensaje sobre el de score. Combina el conjunto: `--parallel` para velocidad, `--sarif` para el dashboard, `--fail-on-new=high` para el veredicto de regresión, `--min-score 70` para el suelo de postura, `--report`/`--html` con el plan de endurecimiento para la lista de arreglos.

**Completado de shell** (`--completion bash|zsh|fish`) — tab-completion para todos los flags, generada desde la misma tabla de flags que el binario registra al arrancar: un flag nuevo aterriza en la siguiente completion automáticamente, y el script nunca puede ofrecer un flag que el binario rechace. `autoprivilege --completion bash >> ~/.bashrc` y cada flag se documenta mientras escribes.

**Playbook de endurecimiento** (`--explain cron`, `--explain all`) — la mitad de remediación del ciclo: para cada fuente de hallazgo, qué significa y los pasos exactos que la cierran, de lo más seguro a lo más agresivo. El mismo playbook viaja dentro de cada `--report`/`--html` como sección por fuente construida con las fuentes que el scan realmente detectó:

<p align="center"><img src="docs/images/screenshot-explain.png" alt="--explain cron: el playbook de endurecimiento CRON" width="760"></p>

## El laboratorio rootless

<p align="center"><img src="docs/images/demo-lab.gif" alt="Demo de AUTOPRIV: escaneo, plan dry-run, escalada SUID hasta uid=0 en el laboratorio rootless" width="720"></p>

El lab es una caja fake comprometida construida dentro de un **user namespace** (`unshare -r -m`): un `/etc` temporal con passwd/shadow/cron escribibles, un `/usr/bin` bindeado con `python3` y `find` SUID. Los bits SUID solo dan el root mapeado del namespace — nunca el tuyo. Es la forma más segura de demostrar, testear y capturar el ciclo completo escaneo → enumeración → root sin Docker ni permisos especiales:

```bash
lab/rootless_lab.sh                             # solo escaneo
lab/rootless_lab.sh --exploit --dry-run         # muestra el plan
lab/rootless_lab.sh --exploit --risk=danger     # escalada completa hasta uid=0
lab/rootless_lab.sh --shell                     # shell interactiva del namespace
lab/rootless_lab.sh --seeds                     # lista las vulnerabilidades sembradas
```

Lo que el lab siembra (ver `--seeds`): `python3` y `find` SUID en `/usr/bin`, un cron job de root escribible en `/etc/cron.d/backup`, `/etc/passwd` escribible, una `/etc/shadow` propia (legible y escribible), la unidad systemd `vuln.service` escribible y un directorio del PATH world-writable como cebo de plantado de binarios. Todo es FALSO y vive solo dentro del namespace.

## Testing con Docker

Cuatro contenedores cubren la matriz: `vulnerable` (debe encontrar vectores), `clean` (no debe encontrar ninguno), `edgecases` (permisos raros, symlinks) y `autoprivilege-test` (ejecuta la suite completa):

```bash
cd docker && docker compose up --build
./docker/test_runner.sh
```

## Seguridad y ética

AUTOPRIV es solo para **trabajo de seguridad autorizado**: tus propias máquinas, laboratorios, CTFs y engagements con permiso por escrito. Por defecto no cambia nada; la explotación solo ocurre tras `--exploit`, e incluso así prefiere técnicas reversibles y se detiene en el riesgo que permitiste. No lo ejecutes en sistemas que no poseas o no tengas autorización explícita para auditar.

## Tests y CI

140 tests unitarios cubren los puntos delicados a propósito: el arte del banner se verifica decodificándolo rune a rune (se acabó el ASCII art mal escrito), el parseo de CSV de vectores, la ordenación de riesgos, los rangos de CVEs de kernel, los rangos de versiones de sudo, los timeouts de explotación, las regresiones de quoting de shell, los guards de spool, los formatos de hash y el escape de markdown, además del walk recursivo SUID/SGID (recursión, salto de symlinks, deduplicación, límite de profundidad y las raíces lib64), la clasificación honesta de SGID con procedencia de técnica declarada, el timeout configurable de escaneo, las heurísticas de runtimes de contenedores (evidencia de cgroups, sockets objetivo, vectores de breakout, detección de privileged/namespace de PID), la tabla estructural de simetría de selección de vectores (cada nombre de `--vector` produce solo su propia categoría), la captura/persistencia de técnicas sgid de GTFOBins, el fichero JSON de `--output` (forma y permisos 0600), la sección de resumen del reporte markdown (totales que espejan el summary del JSON), el barrido de credenciales en DIRECTORIOS de configuración (el `psk=` de NetworkManager y los árboles por versión de PostgreSQL estaban muertos en silencio antes), el diff contra baseline (clasificación nuevo/resuelto con clave fuente+objetivo, forma JSON sin `null`, validación fail-fast de JSON ajenos, render de la trayectoria del score), la puerta `--fail-on` (parseo del umbral, recuento solo de explotables), los scanners de preload/sudoers (recuento de entradas, honestidad escribible-vs-informativo, escritura sudoers idempotente con compensación de salto de línea, pase por fichero condicionado a directorio cerrado), el score de endurecimiento (pesos exactos de penalización, determinismo, clamping, integración en summary/diff), la decisión de exit codes extraída a función pura (0/1 clásicos, ambas puertas forzando 3, precedencia del mensaje de la puerta de política), la puerta de regresión (`--fail-on-new`: un informativo nuevo no tripia, claves re-redactadas no son nuevas, fail-fast sin `--baseline`, umbral de riesgo opcional respetado), escrituras atómicas de reportes (contenido, 0600 fijado, sin temporales restantes), la exportación SARIF (dedup de reglas en orden de aparición, mapeo de niveles, ubicaciones solo para rutas, escrituras 0600), los scanners de grupo y hooks de login (honestidad escribible-vs-silencio, guard de forma incorrecta), el motor `--parallel` (merge byte-idéntico con finalización fuera de orden, stealth fuerza secuencial) y las adiciones de la ronda 12: el informe HTML (escape XSS del texto de hallazgos, estructura autocontenida sin referencias externas, permisos 0600, sección de diff, plan de endurecimiento vacío-seguro), el umbral de la puerta de regresión (`--fail-on-new=high` ignora una regresión MEDIUM y tripia con DANGER y el mensaje at/above; comportamiento bare fijado), el parseo del flag `--fail-on-new` (bare vs `=valor`, umbral inválido rechazado en parseo), el catálogo de vectores (anclado a `validVectors` en ambas direcciones, descripciones con contenido, la salida del printer cubre todos los nombres), la paridad flags↔usage como test HERMÉTICO (un FlagSet privado construido con el mismo registerFlags del binario — un flag nuevo no puede salir sin documentar, y el usage no puede anunciar un fantasma) y las adiciones de la ronda 13: la puerta de postura (`--min-score`: tripia con su mensaje, NO tripia exactamente en el suelo, desactivada en 0, precedencia de mensaje más baja tras política y regresión), el generador de completado de shell (`--completion bash|zsh|fish`: todos los flags registrados más help presentes en cada script, líneas estructurales fijadas, shells desconocidas rechazadas con las opciones válidas, generación dirigida por registerFlags así que nunca puede divergir) y la versión fijada a 1.8.0 por test (un revert es ahora un acto deliberado). Las escrituras de reportes (`--output`, `--report`, `--html`, `--sarif`) son atómicas (fichero temporal + rename): un crash a mitad de scan nunca deja un artefacto truncado que el `--baseline` o una puerta malinterpreten en la siguiente ejecución. La CI ejecuta build, vet, gofmt y la suite completa con `-count=1` Y `-race` en cada push a `main`, más un job `lab-smoke` que corre el lab rootless real y comprueba que el stdout de `--json --quiet` sigue siendo un único documento JSON limpio.

## Licencia

MIT — ver [LICENSE](LICENSE).

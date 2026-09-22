package autopriv

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ================================================================
// FASE 1 — Scanner: passivo, no modifica nada
// ================================================================

var scannerOrder = []func(*AutoPrivilege){
	scanSetBits, scanSudo, scanCron, scanPasswd, scanShadow, scanDocker,
	scanContainers, scanCapabilities, scanFileCaps, scanNFS, scanWritablePath,
	scanServices, scanKernelCVE, scanPwnKit, scanSudoVersion, scanCredentials,
	scanPreload, scanGroup, scanLoginHooks, scanPolkit,
}

func scanAll(p *AutoPrivilege) {
	logScanStart(p.Opts)
	// The scanner set is chosen by the platform layer: the Linux suite
	// (scannerOrder) on Linux and the other Unixes, the Windows suite
	// (windowsScannerOrder, windows_scan.go) on Windows. The parallel/
	// sequential engine below is OS-agnostic and serves whichever set it
	// was given.
	scanners := platformScanners()
	// --parallel runs the scanners concurrently to cut wall-clock time
	// (getcap -r alone can eat the whole budget on binary-heavy hosts).
	// Each goroutine scans into a PRIVATE AutoPrivilege whose Findings
	// slice it owns — scanners only ever append to p.Findings and read
	// p.Opts, so the shallow copy is the entire synchronization story —
	// and the merge walks scannerOrder in index order: the merged slice
	// is byte-identical to a sequential run, which the diff/gate/markdown
	// contracts depend on (TestScanAllParallelDeterministic pins it, and
	// the suite is race-clean under -race). --stealth forces sequential:
	// its jitter exists precisely to pace host-visible probes.
	if !p.Opts.Parallel || p.Opts.Stealth {
		for _, scanner := range scanners {
			start := time.Now()
			scanner(p)
			logScanDone(scannerName(scanner), time.Since(start), p.Opts)
			if p.Opts.Stealth {
				time.Sleep(time.Duration(100+rand.Intn(300)) * time.Millisecond)
			}
		}
		return
	}

	names := make([]string, len(scanners))
	for i, scanner := range scanners {
		names[i] = scannerName(scanner)
	}
	perScanner := make([][]Finding, len(scanners))
	var wg sync.WaitGroup
	for i, scanner := range scanners {
		wg.Add(1)
		go func(idx int, fn func(*AutoPrivilege), name string) {
			defer wg.Done()
			start := time.Now()
			lp := &AutoPrivilege{Opts: p.Opts, Started: p.Started}
			fn(lp)
			perScanner[idx] = lp.Findings
			logScanDone(name, time.Since(start), p.Opts)
		}(i, scanner, names[i])
	}
	wg.Wait()
	for _, findings := range perScanner {
		p.Findings = append(p.Findings, findings...)
	}
}

// scannerName recovers a scanner's identity for the --verbose timing log:
// the function's Go name (scanSudo → "scanSudo"). Runtime.FuncForPC is the
// only honest source — a parallel names slice would drift from scannerOrder
// the first time someone reorders it and nobody would notice.
func scannerName(fn func(*AutoPrivilege)) string {
	return runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
}

func addFinding(p *AutoPrivilege, source, target, desc string, risk RiskLevel, exploitable bool) {
	// Findings are stored only: main() prints the consolidated "── Findings ──"
	// section once, after the scan. Printing here too made every exploitable
	// finding appear twice in terminal output.
	p.Findings = append(p.Findings, Finding{
		Source:      source,
		Target:      target,
		Description: desc,
		Risk:        risk,
		Exploitable: exploitable,
	})
}

// --- SUID / SGID ---
// classifySUID decides whether a SUID binary is a root-escalation vector.
// The setuid bit only helps if the file is owned by root: a SUID binary
// owned by another user escalates to that user, never to uid 0. Without
// this check the scanner produced false positives for every stray SUID bin.
func classifySUID(bin string, ownerUID uint32) (risk RiskLevel, exploitable bool) {
	if ownerUID != 0 {
		return RiskLow, false
	}
	_, isGTFO := getCommand(bin)
	isShell := isSuidShellBin(bin)
	if !isGTFO && !isShell {
		return RiskLow, false
	}
	if isShell {
		return RiskHigh, true
	}
	return RiskLow, true
}

// classifySGID mirrors classifySUID for the setgid bit. An SGID binary never
// grants uid 0 — it only grants the owning group — so a finding counts as a
// real vector solely when the group is root AND a GTFOBins technique exists.
// Even then it becomes a manual vector downstream (honest results: no
// auto-exploit claiming root from a group privilege).
func classifySGID(bin string, ownerGID uint32) (risk RiskLevel, exploitable bool) {
	if _, ok := getCommand(bin); !ok {
		return RiskLow, false
	}
	if ownerGID != 0 {
		return RiskLow, false
	}
	return RiskMedium, true
}

// setBitRoots are the directory trees walked for SUID/SGID files.
// /usr/lib64 and /lib64 close the RHEL/Fedora gap (dbus-daemon-launch-helper
// and friends live there). On merged-usr distros /lib64 is a symlink to
// usr/lib64: the walk skips symlinks and the real-path dedup collapses any
// aliasing, so both entries are safe everywhere. Cost measured this round:
// ~1 ms for an empty /usr/lib64 here, one extra shallow tree at worst.
var setBitRoots = []string{
	"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin",
	"/usr/local/sbin", "/snap/bin", "/opt", "/usr/lib", "/usr/libexec",
	"/usr/lib64", "/lib64",
}

// maxSetBitDepth bounds the recursive walk so a pathological tree (or a
// symlink loop that survived our symlink guard) can never stall the scan.
const maxSetBitDepth = 4

// scanSetBits walks the binary trees once, reporting SUID and SGID files in
// the same pass. The old scanner used a flat os.ReadDir per path, which
// missed every binary inside a subdirectory (ssh-keysign,
// dbus-daemon-launch-helper) and never looked at SGID at all.
func scanSetBits(p *AutoPrivilege) {
	seen := map[string]bool{}
	for _, dir := range setBitRoots {
		walkSetBits(p, dir, 0, seen)
	}
}

// processSetBitEntryFn is the hook the walk uses to classify and store each
// regular file. It is a package variable so tests can simulate the setuid /
// setgid bits: hardened CI sandboxes silently clear them on chmod, and the
// walk logic (recursion, symlink skip, dedup, depth guard) must stay testable
// everywhere.
var processSetBitEntryFn = func(p *AutoPrivilege, full string, e os.DirEntry, info os.FileInfo) {
	// Numeric ownership comes from the platform layer: on Linux this is
	// the Stat_t uid/gid; on Windows there is no honest numeric owner and
	// the whole classification is skipped (ok=false) instead of guessed.
	uid, gid, ok := fileOwnerIDs(info)
	if !ok {
		return
	}
	if info.Mode()&os.ModeSetuid != 0 {
		risk, expl := classifySUID(e.Name(), uid)
		reportSetBit(p, "SUID", e.Name(), full, uid, risk, expl)
	}
	if info.Mode()&os.ModeSetgid != 0 {
		risk, expl := classifySGID(e.Name(), gid)
		reportSetBit(p, "SGID", e.Name(), full, gid, risk, expl)
	}
}

func walkSetBits(p *AutoPrivilege, dir string, depth int, seen map[string]bool) {
	if depth > maxSetBitDepth {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		// Never follow symlinks: merged-usr distros alias /bin → /usr/bin and
		// a hostile tree could point anywhere. Real binaries are reached
		// through their real directories, so nothing is missed.
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		if e.IsDir() {
			walkSetBits(p, full, depth+1, seen)
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		// Dedup by the resolved real path so bind-merged trees (/bin and
		// /usr/bin pointing at the same file) report each binary once.
		resolved, err := filepath.EvalSymlinks(full)
		if err != nil {
			resolved = full
		}
		if seen[resolved] {
			continue
		}
		seen[resolved] = true

		processSetBitEntryFn(p, full, e, info)
	}
}

// reportSetBit stores one SUID/SGID finding. Non-vector files stay as
// informational intel (counted in JSON, not printed) with the reason spelled
// out instead of a bare boolean.
func reportSetBit(p *AutoPrivilege, kind, bin, full string, ownerID uint32, risk RiskLevel, exploitable bool) {
	if exploitable {
		var desc string
		if kind == "SUID" {
			desc = fmt.Sprintf("SUID binary: %s (GTFOBins: true)", bin)
		} else {
			desc = fmt.Sprintf("SGID binary: %s (group root — GTFOBins: true) — group-level escalation, no uid 0", bin)
		}
		addFinding(p, kind, full, desc, risk, true)
		return
	}
	reason := "GTFOBins: false"
	if ownerID != 0 {
		// For SUID the id is the file owner's; for SGID it is the owning
		// group's — spell the difference out so the JSON stays unambiguous.
		label := fmt.Sprintf("%s owner id %d", kind, ownerID)
		if kind == "SGID" {
			label = fmt.Sprintf("group gid %d", ownerID)
		}
		reason = fmt.Sprintf("%s — not a root vector", label)
	}
	addFinding(p, kind, full, fmt.Sprintf("%s binary: %s (%s)", kind, bin, reason), RiskLow, false)
}

// --- Sudo ---
func scanSudo(p *AutoPrivilege) {
	// Canonical resolver: under su/sudo -s the USER env var lies (it keeps
	// pointing at the pre-su user, or disappears), and `groups <wrong>`
	// silently kills the sudo/wheel group check below. scanDocker already
	// used currentUsername(); this scanner now matches the standard.
	user := currentUsername()

	// sudo -n fails fast instead of prompting for a password (the old
	// `sudo -l` fallback hung forever in labs without a password).
	out, err := runCmdOut(p.Opts.scanCmdTimeout(), "sudo", "-n", "-l")
	if err != nil {
		return
	}

	output := string(out)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Matching") || strings.HasPrefix(line, "User") {
			continue
		}

		// Parse: (ALL) NOPASSWD: /usr/bin/find
		// Parse: (root) /usr/bin/awk
		if strings.Contains(line, "NOPASSWD:") || strings.Contains(line, "PASSWD:") ||
			(strings.HasPrefix(line, "(") && strings.Contains(line, "/")) {

			parts := strings.Fields(line)
			for _, part := range parts {
				part = strings.TrimRight(part, ",")
				if strings.HasPrefix(part, "/") {
					bin := filepath.Base(part)
					if cmd, ok := getCommand(bin); ok {
						addFinding(p, "SUDO", part,
							fmt.Sprintf("NOPASSWD sudo: %s → %s", part, strings.SplitN(cmd, " ", 2)[0]),
							RiskHigh, true)
					}
				}
			}
		}
	}

	// Check sudo ALL
	if strings.Contains(output, "(ALL) ALL") || strings.Contains(output, "(root) ALL") ||
		strings.Contains(output, "(ALL : ALL) ALL") {
		addFinding(p, "SUDO", "ALL",
			"Full sudo access — instant root",
			RiskHigh, true)
	}

	// Check if user is in sudo group
	if isInGroup(p.Opts, user, "sudo") || isInGroup(p.Opts, user, "wheel") {
		// Try passwordless sudo (timeout guard)
		out3, err3 := runCmdOut(p.Opts.scanCmdTimeout(), "sudo", "-n", "true")
		_ = out3
		if err3 == nil {
			addFinding(p, "SUDO", user,
				"User has passwordless sudo",
				RiskHigh, true)
		}
	}
}

func isInGroup(o Options, user, group string) bool {
	out, err := runCmdOut(o.scanCmdTimeout(), "groups", user)
	if err != nil {
		return false
	}
	for _, g := range strings.Fields(string(out)) {
		if g == group {
			return true
		}
	}
	return false
}

// --- Cron ---
func scanCron(p *AutoPrivilege) {
	cronDirs := []string{
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron/crontabs",
		"/var/spool/cron",
	}

	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			// Skip placeholder and hidden files
			if name == ".placeholder" || strings.HasPrefix(name, ".") {
				continue
			}
			// Skip directories
			if e.IsDir() {
				continue
			}
			full := filepath.Join(dir, name)
			info, err := os.Lstat(full)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			// Check if we can actually write
			if isWritableByCurrentUser(full) {
				addFinding(p, "CRON", full,
					"Writable cron job — inject command",
					RiskHigh, true)
				continue
			}
			// Not writable: the root-run schedule can still be
			// abused through wildcard-absorption (see the heuristic
			// below) — read-only content analysis, nothing executed.
			if isReadable(full) {
				scanCronWildcards(p, full)
			}
		}
	}

	// Check crontab -l for writable scripts referenced
	// (runCmdOut guard: the project standard — no bare exec calls in scans)
	out, err := runCmdOut(p.Opts.scanCmdTimeout(), "crontab", "-l")
	if err == nil && len(out) > 0 {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, "/") {
					info, err := os.Lstat(f)
					if err == nil && info.Mode().Perm()&0200 != 0 && !info.IsDir() {
						if isWritableByCurrentUser(f) {
							addFinding(p, "CRON", f,
								"Crontab references writable file",
								RiskHigh, true)
						}
					}
				}
			}
		}
	}
}

// wildcardProneBins are the archivers/synchronizers whose GTFOBins tricks
// absorb filenames as arguments: when a root cron runs `tar cf backup.tar *`
// in a directory where the user can create files, crafted filenames become
// the missing arguments (the classic --checkpoint-action injection). Only
// these four families are flagged — the heuristic stays honest by refusing
// to guess about binaries with no such technique.
var wildcardProneBins = map[string]bool{
	"tar": true, "rsync": true, "zip": true, "7z": true,
}

// cronWildcardLine inspects one cron line (already comment/blank-stripped)
// for a wildcard-prone binary invoked with a literal `*` argument. It works
// for both schedule shapes: /etc/cron.d lines (5 time fields + command) and
// the bare commands of cron.hourly/daily/weekly/monthly. Returns the binary
// name so the finding can name the technique. Pure function — fully
// table-testable without a cron installation.
func cronWildcardLine(line string) (string, bool) {
	fields := strings.Fields(line)
	// A schedule-prefixed line has at least 6 fields; a bare command has
	// at least 2 (binary + wildcard). Either way the command must appear
	// with a `*` argument somewhere after it.
	for i, f := range fields {
		base := filepath.Base(f)
		if !wildcardProneBins[base] {
			continue
		}
		for _, arg := range fields[i+1:] {
			if arg == "*" || strings.Contains(arg, "*") {
				return base, true
			}
		}
	}
	return "", false
}

// scanCronWildcards reports wildcard-injection CANDIDATES in a root cron
// file. Honest risk accounting: the schedule runs as root, but the classic
// trick also needs a writable working directory for the crafted filenames,
// and cron's cwd is the cron file's location only for spool entries — the
// tool cannot know it from here. So the finding is MEDIUM, exploitable=
// false: an investigation lead with the exact verification step spelled out.
// The user's own `crontab -l` output is deliberately NOT scanned for this:
// user crontabs run as their owner — no root schedule, no injection.
func scanCronWildcards(p *AutoPrivilege, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if bin, ok := cronWildcardLine(line); ok {
			addFinding(p, "CRON", path,
				fmt.Sprintf("root cron runs %s with wildcard arguments — file-absorption injection IF its working directory is user-writable (verify)", bin),
				RiskMedium, false)
			break // one candidate per file keeps the report noise-free
		}
	}
}

// --- /etc/passwd writable ---
func scanPasswd(p *AutoPrivilege) {
	if isWritableByCurrentUser("/etc/passwd") {
		addFinding(p, "FILE", "/etc/passwd",
			"Writable /etc/passwd — inject root user",
			RiskHigh, true)
	}
}

// --- /etc/shadow readable/writable ---
func scanShadow(p *AutoPrivilege) {
	// The old check tested the OWNER permission bit (root's), which is set on
	// every system on earth — a false positive machine. Test real access.
	if isReadable("/etc/shadow") {
		addFinding(p, "FILE", "/etc/shadow",
			"Readable /etc/shadow — crack root hash",
			RiskHigh, true)
	}
	if isWritableByCurrentUser("/etc/shadow") {
		addFinding(p, "FILE", "/etc/shadow",
			"Writable /etc/shadow — set root password",
			RiskDanger, true)
	}
}

// --- Docker ---
func scanDocker(p *AutoPrivilege) {
	// Real group parsing — substring matching produced false positives
	// for users like "dockerdb".
	if isInGroup(p.Opts, currentUsername(), "docker") {
		addFinding(p, "DOCKER", currentUsername(),
			"User in docker group — container breakout to root",
			RiskHigh, true)
	}

	// The socket must be genuinely writable by us, not merely group-flagged.
	if info, err := os.Lstat("/var/run/docker.sock"); err == nil && info.Mode()&os.ModeSocket != 0 {
		if isWritableByCurrentUser("/var/run/docker.sock") {
			addFinding(p, "DOCKER", "/var/run/docker.sock",
				"Writable docker socket — container breakout to root",
				RiskHigh, true)
		}
	}
}

// --- Containers ---
// containerSocketPaths lists the unix sockets of the non-docker container
// runtimes. The docker socket is intentionally absent: scanDocker already
// owns it (group membership + writability) and a second reporter would
// duplicate every docker finding.
func containerSocketPaths() []string {
	return []string{
		"/var/run/podman/podman.sock",
		"/run/podman/podman.sock",
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
	}
}

// runtimeForSocket names the runtime behind a socket path for finding text.
func runtimeForSocket(sock string) string {
	switch {
	case strings.Contains(sock, "podman"):
		return "podman"
	case strings.Contains(sock, "containerd"):
		return "containerd"
	default:
		return "container runtime"
	}
}

// containerCgroupEvidence extracts runtime hints from cgroup data. Kept pure
// (string in, hints out) so the heuristic is testable without a container.
func containerCgroupEvidence(cgroup string) []string {
	var found []string
	lower := strings.ToLower(cgroup)
	for _, hint := range []string{"docker", "containerd", "kubepods", "libpod", "podman", "lxc"} {
		if strings.Contains(lower, hint) {
			found = append(found, hint)
		}
	}
	return found
}

// pidNamespaceFromStatus classifies this process' PID-namespace visibility
// from the raw /proc/<pid>/status text. The NSpid line carries one value per
// nested namespace: a single value means the process shares the host PID
// namespace (it sees the host init as PID 1), two or more mean the process
// sits inside a PID namespace, and a missing line means the kernel is too
// old to tell — "unknown" is the only honest answer there.
func pidNamespaceFromStatus(status string) string {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		switch len(strings.Fields(strings.TrimPrefix(line, "NSpid:"))) {
		case 0:
			return "unknown"
		case 1:
			return "host"
		default:
			return "own"
		}
	}
	return "unknown"
}

// containerPrivilegeFromStatus reports "privileged" when the CapEff mask in
// the given status text includes CAP_SYS_ADMIN — the capability that unlocks
// the classic breakouts (host mounts, cgroup tricks). Anything else (no CapEff
// line, unparsable mask, mask without sys_admin) is "" — never a guess.
func containerPrivilegeFromStatus(status string) string {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		eff := parseCapHex(strings.TrimPrefix(line, "CapEff:"))
		if eff&capSysAdmin != 0 {
			return "privileged"
		}
		return ""
	}
	return ""
}

// canonicalSocketPaths collapses paths that alias the same file (systemd
// distros symlink /var/run → /run, so a podman/containerd socket appears
// under both prefixes and the naive list would report every socket twice —
// R26). Unresolvable paths (socket absent on this host) keep their identity:
// existence is decided later by Lstat, here only aliasing is collapsed.
func canonicalSocketPaths(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		key := p
		if real, err := filepath.EvalSymlinks(p); err == nil {
			key = real
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

// scanContainers reports the container context the tool itself runs in and
// the container-runtime breakout surfaces around it. Honesty rules: the
// "inside a container" indicator never claims escalation by itself (the
// breakout technique must come from a reachable runtime), and the daemon CLI
// check notes that rootless runtimes contain the classic breakout.
func scanContainers(p *AutoPrivilege) {
	var evidence []string
	privileged := false
	if _, err := os.Stat("/.dockerenv"); err == nil {
		evidence = append(evidence, "/.dockerenv present")
	}
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, hint := range containerCgroupEvidence(string(data)) {
			evidence = append(evidence, "cgroup hint "+hint)
		}
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		evidence = append(evidence, "kubernetes service env")
	}
	// Isolation hardening (R24): a container that shares the host PID
	// namespace changes how EVERY other finding must be read (host init,
	// host processes and their /proc data are in reach), and a privileged
	// container (cap_sys_admin in CapEff) makes the classic breakouts
	// trivial instead of "needs a reachable runtime". The parser of
	// capabilities already exists (parseCapHex) — reused, not duplicated.
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		if ns := pidNamespaceFromStatus(string(data)); ns == "host" {
			evidence = append(evidence, "host PID namespace visible (PID 1 is the host init)")
		}
		if containerPrivilegeFromStatus(string(data)) == "privileged" {
			evidence = append(evidence, "privileged caps (cap_sys_admin in CapEff)")
			privileged = true
		}
	}
	if len(evidence) > 0 {
		// Host init environment (R35): in a shared PID namespace,
		// /proc/1 is the host init and its environ is a credential
		// prize when readable. Only probed when other container
		// evidence exists — on bare metal the host init's environ is
		// readable to root and would fabricate a false container
		// signal. The CONTENT is never printed: only the readability
		// is declared. Permission-denied is the common case and
		// stays silent.
		if _, err := os.ReadFile("/proc/1/environ"); err == nil {
			evidence = append(evidence, "host init environment readable (/proc/1/environ)")
		}
		risk := RiskMedium
		if privileged {
			// Honest escalation ladder: privileged = breakout is
			// trivial, but it still needs a technique — the tool
			// reports context, it does not pretend to escape.
			risk = RiskHigh
		}
		addFinding(p, "CONTAINER", "self",
			fmt.Sprintf("Running inside a container (%s) — breakout needs a reachable runtime socket or a privileged runtime",
				strings.Join(evidence, ", ")),
			risk, false)
	}

	for _, sock := range canonicalSocketPaths(containerSocketPaths()) {
		info, err := os.Lstat(sock)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			continue
		}
		if isWritableByCurrentUser(sock) {
			addFinding(p, "CONTAINER", sock,
				fmt.Sprintf("Writable %s socket — host breakout via privileged container", runtimeForSocket(sock)),
				RiskHigh, true)
		} else {
			addFinding(p, "CONTAINER", sock,
				fmt.Sprintf("%s socket present (not writable by current user)", runtimeForSocket(sock)),
				RiskLow, false)
		}
	}

	// A docker CLI that actually reaches a daemon is a breakout vector on
	// its own: it can start a privileged container mounting the host root.
	// scanDocker covers group membership and the raw socket; this also
	// covers DOCKER_HOST / oddly-permissioned setups.
	// Half the scan timeout (R28): on docker-less hosts this probe eats
	// the full budget on every run for an answer that is always "no".
	if out, err := runCmdOut(p.Opts.scanCmdTimeout()/2, "docker", "ps"); err == nil {
		_ = out
		addFinding(p, "CONTAINER", "docker-daemon",
			"docker CLI reaches a live daemon — container breakout available (verify rootful vs rootless)",
			RiskHigh, true)
	}
}

// --- Capabilities ---
// capSetuid / capSysPtrace bit positions in the 64-bit capability mask.
const (
	capSetuid    = 1 << 7
	capSysPtrace = 1 << 19
	capSysAdmin  = 1 << 21
)

// parseCapHex decodes a /proc/<pid>/status capability hex word.
func parseCapHex(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 16, 64)
	return v
}

func scanCapabilities(p *AutoPrivilege) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", os.Getpid()))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		eff := parseCapHex(strings.TrimPrefix(line, "CapEff:"))
		if eff == 0 {
			return
		}
		switch {
		case eff&capSetuid != 0:
			addFinding(p, "CAPS", "cap_setuid",
				"Process holds CAP_SETUID — can become root in-process",
				RiskMedium, true)
		case eff&capSysAdmin != 0:
			addFinding(p, "CAPS", "cap_sys_admin",
				"Process holds CAP_SYS_ADMIN — container escape territory",
				RiskMedium, false)
		case eff&capSysPtrace != 0:
			addFinding(p, "CAPS", "cap_sys_ptrace",
				"Process holds CAP_SYS_PTRACE — can inject into other processes",
				RiskMedium, false)
		default:
			addFinding(p, "CAPS", fmt.Sprintf("0x%x", eff),
				"Process has non-default capabilities (review manually)",
				RiskLow, false)
		}
		return
	}
}

// --- File capabilities ---
// scanFileCaps looks for binaries with file capabilities (e.g. cap_setuid+ep
// on an interpreter) using getcap when available.
func scanFileCaps(p *AutoPrivilege) {
	// getcap -r walks the whole filesystem: it is the slowest external call
	// of the scan, so it gets 4x the configured timeout.
	out, err := runCmdOut(4*p.Opts.scanCmdTimeout(), "getcap", "-r", "/usr", "/bin", "/sbin", "/opt")
	if err != nil {
		return // getcap missing or unreadable paths — skip silently
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "cap_setuid") {
			continue
		}
		fields := strings.SplitN(line, " =", 2)
		if len(fields) != 2 {
			continue
		}
		binPath := fields[0]
		if _, err := os.Lstat(binPath); err != nil {
			continue
		}
		addFinding(p, "CAPS", "cap_setuid:"+binPath,
			fmt.Sprintf("cap_setuid on %s — interpreter can setuid(0)", binPath),
			RiskMedium, true)
	}
}

// --- NFS ---
func scanNFS(p *AutoPrivilege) {
	data, err := os.ReadFile("/etc/exports")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.Contains(line, "no_root_squash") {
			addFinding(p, "NFS", line,
				"NFS export with no_root_squash — mount and own files as root",
				RiskHigh, true)
			continue
		}
		// no_root_squash is the worst case, but an rw export with an
		// unrestricted client list is its quieter sibling: every host
		// that can reach the port can mount and (with a matching uid)
		// write. Config weakness, not a direct path for the current
		// user — MEDIUM, informational.
		if nfsExportHostless(line) {
			addFinding(p, "NFS", line,
				"NFS export rw without host restriction — any client may mount",
				RiskMedium, false)
		}
	}
}

// nfsExportHostless reports whether an /etc/exports line grants rw to an
// unrestricted client list: `*(rw,...)` (the wildcard host) or a bare
// `(rw,...)` group (empty host = world). Options-only lines without rw,
// host-qualified exports and the literal "ro" case all stay silent.
// Pure function — table-testable without an NFS server.
func nfsExportHostless(line string) bool {
	// /etc/exports grammar: path client(options) client(options)…
	// The export path is field 0; every other field is a client spec.
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	for _, client := range fields[1:] {
		if client == "" {
			continue
		}
		unrestricted := strings.HasPrefix(client, "*(") || strings.HasPrefix(client, "(")
		if !unrestricted {
			continue
		}
		// rw present and not ro: scanning the option group only —
		// a substring search over the whole line would false-positive
		// on a host named "rw-host".
		opts := strings.TrimPrefix(strings.TrimPrefix(client, "*"), "(")
		opts = strings.TrimSuffix(opts, ")")
		hasRW, hasRO := false, false
		for _, opt := range strings.Split(opts, ",") {
			switch strings.TrimSpace(opt) {
			case "rw":
				hasRW = true
			case "ro":
				hasRO = true
			}
		}
		if hasRW && !hasRO {
			return true
		}
	}
	return false
}

// --- Writable PATH entries ---
// scanWritablePath flags PATH directories the CURRENT USER can really write
// to. The old version tested the OWNER's write bit (`perm&0200`), which
// flagged root-owned 755 directories as "writable binary planting" — a false
// positive the Director reproduced live (honest results demand real access).
func scanWritablePath(p *AutoPrivilege) {
	// Running as root, nothing in PATH can escalate further: every
	// directory is "writable" and every finding would be noise.
	if os.Geteuid() == 0 {
		return
	}

	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			dir = "."
		}
		if planting, owner := isPathPlantingDir(dir); planting {
			addFinding(p, "PATH", dir,
				"Writable directory in PATH (owner uid "+owner+") — binary planting",
				RiskHigh, true)
		}
	}
}

// isPathPlantingDir reports whether dir is a binary-planting bait: a
// directory in PATH the current user can write but does NOT own (group- or
// world-writable). Your own directories are your terrain, not bait. The
// second return value is the owner uid for the finding text.
func isPathPlantingDir(dir string) (bool, string) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return false, ""
	}
	if !isWritableByCurrentUser(dir) {
		return false, ""
	}
	// Platform layer: uid lookup is a Stat_t question on Linux and has no
	// answer on Windows (ok=false → honestly not bait rather than guessed).
	uid, _, ok := fileOwnerIDs(info)
	if !ok {
		return false, ""
	}
	if uid == uint32(os.Getuid()) {
		return false, ""
	}
	return true, fmt.Sprintf("%d", uid)
}

// isWritableByCurrentUser checks if the current user/group can write to a file
func isWritableByCurrentUser(path string) bool {
	// Root (euid 0) bypasses the permission bits entirely — the old code
	// returned false for root-owned 0444 files, which root can obviously
	// still write.
	if os.Geteuid() == 0 {
		return true
	}
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	uid := uint32(os.Getuid())
	perm := info.Mode().Perm()
	fuid, fgid, ok := fileOwnerIDs(info)
	if !ok {
		return perm&0002 != 0
	}
	if fuid == uid && perm&0200 != 0 {
		return true
	}
	if perm&0002 != 0 {
		return true
	}
	if fgid == uint32(os.Getgid()) && perm&0020 != 0 {
		return true
	}
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if uint32(g) == fgid && perm&0020 != 0 {
			return true
		}
	}
	return false
}

// --- Writable services ---
// servicePaths exists so tests can point the scanner at synthetic trees;
// production code always sees the real /etc locations.
var servicePaths = struct {
	systemd string
	initd   string
}{
	systemd: "/etc/systemd/system",
	initd:   "/etc/init.d",
}

// scanServices covers the two service-execution families the current user
// must never be able to rewrite: systemd units (systemd) and SysV init
// scripts (init.d). Both run as root — at boot, on restart, on timer fire.
func scanServices(p *AutoPrivilege) {
	scanServicesWithPaths(p, servicePaths.systemd, servicePaths.initd)
}

func scanServicesWithPaths(p *AutoPrivilege, systemdDir, initdDir string) {
	dirs := []struct {
		path   string
		suffix string // "" matches every regular file (init.d scripts carry no extension)
		desc   string
	}{
		{systemdDir, ".service", "Writable systemd service — hijack execution"},
		{initdDir, "", "Writable init.d script — hijack boot/service execution"},
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir.path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if dir.suffix != "" && !strings.HasSuffix(e.Name(), dir.suffix) {
				continue
			}
			full := filepath.Join(dir.path, e.Name())
			info, _ := os.Lstat(full)
			if info == nil || !info.Mode().IsRegular() {
				continue
			}
			if isWritableByCurrentUser(full) {
				addFinding(p, "SERVICE", full, dir.desc, RiskHigh, true)
			}
		}
	}
}

// --- Kernel CVE detection ---
// kernelVersion parses "6.8.0-42-generic" into [6, 8, 0].
func kernelVersion(s string) []int {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil
	}
	core := strings.Split(strings.Split(fields[0], "-")[0], ".")
	nums := []int{}
	for _, part := range core {
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		nums = append(nums, n)
	}
	for len(nums) < 3 {
		nums = append(nums, 0)
	}
	return nums
}

// kernelInRange reports whether v is inside [min, max] (version heuristic —
// distros backport fixes, so this is an indicator, not a certainty).
func kernelInRange(v, minV, maxV []int) bool {
	if len(v) < 3 || len(minV) != 3 || len(maxV) != 3 {
		return false
	}
	cmp := func(a, b []int) int {
		for i := 0; i < 3; i++ {
			if a[i] != b[i] {
				if a[i] < b[i] {
					return -1
				}
				return 1
			}
		}
		return 0
	}
	return cmp(v, minV) >= 0 && cmp(v, maxV) <= 0
}

func scanKernelCVE(p *AutoPrivilege) {
	out, err := runCmdOut(p.Opts.scanCmdTimeout(), "uname", "-r")
	if err != nil {
		return
	}
	kernel := strings.TrimSpace(string(out))
	kv := kernelVersion(kernel)

	cves := []struct {
		cve  string
		name string
		desc string
		minV []int
		maxV []int
		risk RiskLevel
	}{
		{
			cve:  "CVE-2022-0847",
			name: "Dirty Pipe",
			desc: "kernel pipe buffer flag overwrite — read/write any file as root",
			minV: []int{5, 8, 0},
			maxV: []int{5, 16, 10},
			risk: RiskHigh,
		},
		{
			// The canonical legacy/CTF vector: the fix landed in
			// 4.8.3 (also backported to 4.7.9 and 4.4.26), so the
			// conservative window is 2.6.22 through 4.8.3 — on
			// any modern kernel this never fires, which keeps it
			// free of noise (R29).
			cve:  "CVE-2016-5195",
			name: "Dirty Cow",
			desc: "mm/gup race in copy-on-write — write to read-only mappings, root any legacy host",
			minV: []int{2, 6, 22},
			maxV: []int{4, 8, 3},
			risk: RiskHigh,
		},
		{
			cve:  "CVE-2023-0386",
			name: "OverlayFS",
			desc: "overlayfs copy-up permission bypass — file ownership escalation",
			minV: []int{5, 11, 0},
			maxV: []int{6, 2, 0},
			risk: RiskHigh,
		},
		{
			cve:  "CVE-2023-32629",
			name: "StackRot",
			desc: "kernel 6.1 VMA stack expansion race — local privilege escalation",
			minV: []int{6, 1, 0},
			maxV: []int{6, 1, 13},
			risk: RiskMedium,
		},
		{
			cve:  "CVE-2024-1086",
			name: "nf_tables UAF",
			desc: "netfilter use-after-free — local privilege escalation",
			minV: []int{5, 14, 0},
			maxV: []int{6, 6, 13},
			risk: RiskHigh,
		},
	}

	for _, cve := range cves {
		if kernelInRange(kv, cve.minV, cve.maxV) {
			addFinding(p, "KERNEL", cve.cve,
				fmt.Sprintf("Kernel %s in affected range for %s (%s) — verify before use (heuristic, backports may patch it)",
					kernel, cve.name, cve.cve),
				cve.risk, true)
		}
	}
}

// --- PwnKit ---
// scanPwnKit checks for a SUID pkexec binary (CVE-2021-4034 affects polkit,
// not the kernel — the old code matched it against kernel versions).
func scanPwnKit(p *AutoPrivilege) {
	info, err := os.Lstat("/usr/bin/pkexec")
	if err != nil || info.Mode()&os.ModeSetuid == 0 {
		return
	}
	version := ""
	if out, err := runCmdOut(p.Opts.scanCmdTimeout(), "/usr/bin/pkexec", "--version"); err == nil {
		version = strings.TrimSpace(string(out))
	}
	addFinding(p, "KERNEL", "CVE-2021-4034",
		fmt.Sprintf("SUID pkexec present (%s) — PwnKit polkit LPE candidate (patched pkexec may still match)",
			version),
		RiskHigh, true)
}

// --- sudo version ---
// scanSudoVersion flags old sudo builds vulnerable to Baron Samedit
// (CVE-2021-3156, fixed in 1.9.5p2) — a sudo bug, not a kernel one.
func scanSudoVersion(p *AutoPrivilege) {
	out, err := runCmdOut(p.Opts.scanCmdTimeout(), "sudo", "--version")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Sudo version ") {
			continue
		}
		ver := strings.TrimSpace(strings.TrimPrefix(line, "Sudo version "))
		if sudoVersionOlder(ver, "1.9.5p2") {
			addFinding(p, "KERNEL", "CVE-2021-3156",
				fmt.Sprintf("sudo %s older than 1.9.5p2 — Baron Samedit heap overflow candidate", ver),
				RiskHigh, true)
		}
		break
	}
}

// sudoVersionOlder compares dotted sudo versions with an optional p-suffix.
func sudoVersionOlder(ver, ref string) bool {
	parse := func(s string) []int {
		suffix := 0
		if i := strings.Index(s, "p"); i >= 0 {
			_, _ = fmt.Sscanf(s[i+1:], "%d", &suffix)
			s = s[:i]
		}
		nums := []int{}
		for _, part := range strings.Split(s, ".") {
			n := 0
			_, _ = fmt.Sscanf(part, "%d", &n)
			nums = append(nums, n)
		}
		nums = append(nums, suffix)
		return nums
	}
	a, b := parse(ver), parse(ref)
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// --- Preload + sudoers (persistence-critical configs) ---
// preloadPaths exists so tests can point the scanner at synthetic files;
// production code always sees the real /etc locations. confD/conf are the
// dynamic-loader SEARCH path (a different mechanism than ld.so.preload but
// the same family: library loading under root privilege).
var preloadPaths = struct {
	preload    string
	sudoers    string
	sudoersDir string
	conf       string
	confD      string
}{
	preload:    "/etc/ld.so.preload",
	sudoers:    "/etc/sudoers",
	sudoersDir: "/etc/sudoers.d",
	conf:       "/etc/ld.so.conf",
	confD:      "/etc/ld.so.conf.d",
}

// scanPreload checks the two config surfaces whose compromise equals root:
// /etc/ld.so.preload (every entry is loaded with euid 0 into EVERY SUID
// binary on the host — escalation and persistence in one file) and the
// sudoers tree (a writable /etc/sudoers or sudoers.d is a one-line route to
// uid 0). Content is never printed — presence and entry count only —
// mirroring the credential scanners' "presence, not contents" rule.
func scanPreload(p *AutoPrivilege) {
	scanPreloadPaths(p, preloadPaths.preload, preloadPaths.sudoers, preloadPaths.sudoersDir)
	scanLoaderPath(p, preloadPaths.conf, preloadPaths.confD)
}

// scanLoaderPath flags a writable ld.so.conf or ld.so.conf.d: entries there
// add library search paths absorbed by the system's next ldconfig run
// (package installs, boot), and SUID binaries resolve through that cache —
// a planted directory with a trojan .so becomes a root-loaded object. Same
// HIGH/exploitable class as a writable cron file: user action now, system
// trigger later, root on arrival.
func scanLoaderPath(p *AutoPrivilege, confPath, confDir string) {
	if info, err := os.Lstat(confPath); err == nil && info.Mode().IsRegular() && isWritableByCurrentUser(confPath) {
		addFinding(p, "PRELOAD", confPath,
			"Writable /etc/ld.so.conf — inject library search paths into the system loader cache",
			RiskHigh, true)
	}
	if info, err := os.Lstat(confDir); err == nil && info.IsDir() && isWritableByCurrentUser(confDir) {
		addFinding(p, "PRELOAD", confDir,
			"Writable /etc/ld.so.conf.d — drop a .conf adding an attacker library dir (absorbed by the next ldconfig)",
			RiskHigh, true)
	}
}

func scanPreloadPaths(p *AutoPrivilege, preloadPath, sudoersPath, sudoersDir string) {
	if data, err := os.ReadFile(preloadPath); err == nil {
		if n := countPreloadEntries(string(data)); n > 0 {
			writable := isWritableByCurrentUser(preloadPath)
			desc := fmt.Sprintf("%d ld.so.preload entries loaded with euid 0 into every SUID binary", n)
			risk, exploitable := RiskLow, false
			if writable {
				desc += " — file writable, entries injectable"
				risk, exploitable = RiskHigh, true
			}
			addFinding(p, "PRELOAD", preloadPath, desc, risk, exploitable)
		}
	}
	// missing or permission-denied: silent (honest absence of evidence)

	if isWritableByCurrentUser(sudoersPath) {
		addFinding(p, "SUDOERS", sudoersPath,
			"Writable /etc/sudoers — append a NOPASSWD ALL rule",
			RiskHigh, true)
	}
	if info, err := os.Lstat(sudoersDir); err == nil && info.IsDir() {
		if isWritableByCurrentUser(sudoersDir) {
			addFinding(p, "SUDOERS", sudoersDir,
				"Writable /etc/sudoers.d — drop-in rule possible (sudo requires root-owned files)",
				RiskHigh, true)
		} else {
			// Directory locked down, but the drop-ins themselves can
			// still be abnormal: sudo only honors root-owned, non-
			// group/world-writable files, so a root-owned file the
			// current user can nevertheless write (ACLs, freak perms)
			// is the ONE per-file case worth surfacing. User-owned
			// files are ignored by sudo by design — flagging them
			// would be noise, so the uid check gates the finding.
			scanSudoersDropins(p, sudoersDir)
		}
	}
}

// scanSudoersDropins inspects the individual files of a non-writable
// /etc/sudoers.d for the root-owned-and-user-writable combination. Honest
// risk level: HIGH would overstate it (sudo's visudo check still validates
// the file — an abnormal-perms file may be rejected outright), so this is
// MEDIUM informational with the verification step named. Runs only when the
// parent directory itself is NOT writable: the dir finding already covers
// the write-anywhere case and duplication would double-report every drop-in.
func scanSudoersDropins(p *AutoPrivilege, sudoersDir string) {
	entries, err := os.ReadDir(sudoersDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(sudoersDir, e.Name())
		fi, err := os.Lstat(full)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if !isWritableByCurrentUser(full) {
			continue
		}
		// Platform layer: uid 0 is a Linux notion; on Windows ok=false
		// stays silent instead of guessing ownership.
		ownerUID, _, ok := fileOwnerIDs(fi)
		if !ok || ownerUID != 0 {
			// Not root-owned: sudo ignores it entirely — honest silence.
			continue
		}
		addFinding(p, "SUDOERS", full,
			"Root-owned writable sudoers.d drop-in (ACL/abnormal perms) — verify with visudo -c whether sudo still honors it",
			RiskMedium, false)
	}
}

// countPreloadEntries counts meaningful ld.so.preload entries: non-blank
// lines after trimming whitespace. glibc ignores blank lines, so they are
// not entries; any other non-blank line is a path glibc WILL attempt to load.
func countPreloadEntries(content string) int {
	n := 0
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// --- Group database + login hooks (session-time root surfaces) ---
// groupPath/loginHookPaths exist so tests can point the scanners at
// synthetic files; production code always sees the real /etc locations.
var groupPath = "/etc/group"

var loginHookPaths = struct {
	environment string
	profileD    string
	profile     string
	bashrc      string
}{
	environment: "/etc/environment",
	profileD:    "/etc/profile.d",
	profile:     "/etc/profile",
	bashrc:      "/etc/bash.bashrc",
}

// scanGroup flags a writable /etc/group. The group database governs
// membership in sudo/wheel/docker — a user who can append a line can grant
// himself any of those groups, and the grant takes effect on the next login
// session. Running as root the check is meaningless (root needs no group
// help), so it short-circuits like scanWritablePath — without the guard
// every check would trip and the finding would be pure noise.
func scanGroup(p *AutoPrivilege) {
	if os.Geteuid() == 0 {
		return
	}
	if !isWritableByCurrentUser(groupPath) {
		return
	}
	addFinding(p, "GROUP", groupPath,
		"Writable /etc/group — append yourself to sudo/wheel/docker (effective on next login)",
		RiskHigh, true)
}

// scanLoginHooks flags writable login-time execution surfaces: files and
// directories whose contents run inside every future login shell — root's
// included. /etc/environment is the sharpest of the set (its variables are
// process-wide, so LD_PRELOAD there injects a shared object into every
// login session, not just shells). All are HIGH exploitable when writable:
// the payload is a plain append, no compilation, no schedule, no waiting
// for a misconfiguration — only for the next login.
func scanLoginHooks(p *AutoPrivilege) {
	if info, err := os.Lstat(loginHookPaths.environment); err == nil && info.Mode().IsRegular() {
		if isWritableByCurrentUser(loginHookPaths.environment) {
			addFinding(p, "HOOKS", loginHookPaths.environment,
				"Writable /etc/environment — LD_PRELOAD injected into every login session (root included)",
				RiskHigh, true)
		}
	}
	scanLoginHookPath(p, loginHookPaths.profileD, true,
		"Writable /etc/profile.d — code runs in every login shell (root included)")
	scanLoginHookPath(p, loginHookPaths.profile, false,
		"Writable /etc/profile — code runs in every login shell (root included)")
	scanLoginHookPath(p, loginHookPaths.bashrc, false,
		"Writable /etc/bash.bashrc — code runs in every interactive bash (root included)")
}

// scanLoginHookPath reports one login hook location: a directory (like
// /etc/profile.d, where any dropped .sh becomes login code) or a single
// script file. Missing or permission-denied locations stay silent.
func scanLoginHookPath(p *AutoPrivilege, path string, isDir bool, desc string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	if isDir != info.IsDir() {
		// Shape mismatch (e.g. profile.d replaced by a plain file):
		// the honest answer for the directory-shaped probe is silence;
		// the file case is covered by its own entry.
		return
	}
	if isWritableByCurrentUser(path) {
		addFinding(p, "HOOKS", path, desc, RiskHigh, true)
	}
}

// --- Credential scanning ---
func scanCredentials(p *AutoPrivilege) {
	scanSSHKeys(p)
	scanConfigPasswords(p)
	scanHistoryFiles(p)
	scanCloudMetadata(p)
}

func scanSSHKeys(p *AutoPrivilege) {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}

	sshDirs := []string{
		filepath.Join(home, ".ssh"),
		"/root/.ssh",
	}

	for _, dir := range sshDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			full := filepath.Join(dir, e.Name())
			if strings.HasSuffix(e.Name(), "_rsa") || strings.HasSuffix(e.Name(), "_ed25519") ||
				strings.HasSuffix(e.Name(), "_ecdsa") || strings.HasSuffix(e.Name(), "_dsa") {
				addFinding(p, "CRED", full,
					"SSH private key found — use for lateral movement",
					RiskHigh, true)
			}
			if e.Name() == "authorized_keys" {
				data, err := os.ReadFile(full)
				if err == nil && len(data) > 0 {
					lines := strings.Split(strings.TrimSpace(string(data)), "\n")
					addFinding(p, "CRED", full,
						fmt.Sprintf("SSH authorized_keys with %d entries", len(lines)),
						RiskMedium, false)
				}
			}
			if e.Name() == "known_hosts" {
				data, err := os.ReadFile(full)
				if err == nil && len(data) > 0 {
					hosts := 0
					for _, line := range strings.Split(string(data), "\n") {
						line = strings.TrimSpace(line)
						if line != "" && !strings.HasPrefix(line, "#") {
							hosts++
						}
					}
					if hosts > 0 {
						addFinding(p, "CRED", full,
							fmt.Sprintf("SSH known_hosts with %d hosts — lateral movement targets", hosts),
							RiskLow, false)
					}
				}
			}
		}
	}
}

func scanConfigPasswords(p *AutoPrivilege) {
	configPaths := []struct {
		path    string
		pattern string
		desc    string
	}{
		{"/etc/mysql/my.cnf", "password", "MySQL config with credentials"},
		{"/etc/postgresql", "password", "PostgreSQL config with credentials"},
		{"/etc/redis/redis.conf", "requirepass", "Redis password configuration"},
		{filepath.Join(os.Getenv("HOME"), ".mysql_history"), "", "MySQL command history"},
		{filepath.Join(os.Getenv("HOME"), ".psql_history"), "", "PostgreSQL command history"},
		{"/etc/NetworkManager/system-connections", "psk=", "WiFi passwords in NetworkManager"},
	}

	for _, cfg := range configPaths {
		for _, file := range configCandidateFiles(cfg.path) {
			scanConfigFile(p, file, cfg.pattern, cfg.desc)
		}
	}
}

// configCandidateFiles resolves one configured location into the concrete
// files to audit: the file itself, or — when the location is a directory —
// its regular top-level files (sorted for a deterministic order). The old
// code skipped every directory, which silently killed the NetworkManager
// psk= check (system-connections is ALWAYS a directory where NetworkManager
// exists — the finding was structurally unreachable) and left the
// /etc/postgresql entry dead despite its comment promising per-file checks.
// Scope stays bounded: top-level files only, subdirectories and symlinks are
// not descended into (per-version trees like /etc/postgresql/15/main are
// deliberately out — /etc walks belong to a dedicated feature, not a
// credential sweep).
func configCandidateFiles(path string) []string {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if !info.IsDir() {
		return []string{path}
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(path, e.Name())
		fi, err := os.Lstat(full)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, full)
	}
	sort.Strings(out)
	return out
}

// scanConfigFile reports one credential-bearing config file. History files
// (empty pattern) report on presence alone; patterned entries only report
// when the credential pattern is really inside the file. Permission-denied
// (the common non-root case) stays silent — honest absence of evidence.
func scanConfigFile(p *AutoPrivilege, path, pattern, desc string) {
	if !isReadable(path) {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if pattern != "" && !strings.Contains(string(data), pattern) {
		return
	}
	addFinding(p, "CRED", path, desc, RiskMedium, true)
}

func scanHistoryFiles(p *AutoPrivilege) {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}

	histFiles := []string{
		filepath.Join(home, ".bash_history"),
		filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".sh_history"),
		"/root/.bash_history",
		"/root/.zsh_history",
	}

	seen := map[string]bool{}
	for _, hf := range histFiles {
		if seen[hf] {
			continue // HOME=/root duplicates the explicit /root paths
		}
		seen[hf] = true
		data, err := os.ReadFile(hf)
		if err != nil || len(data) == 0 {
			continue
		}
		content := string(data)
		secrets := []string{"password", "passwd", "secret", "token", "api_key", "aws_", "AKIA", "private"}
		found := []string{}
		for _, s := range secrets {
			if strings.Contains(strings.ToLower(content), s) {
				found = append(found, s)
			}
		}
		if len(found) > 0 {
			addFinding(p, "CRED", hf,
				fmt.Sprintf("History file with potential secrets: %s", strings.Join(found, ", ")),
				RiskHigh, true)
		}
	}
}

func scanCloudMetadata(p *AutoPrivilege) {
	metadataURLs := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/user-data/",
	}
	client := &http.Client{Timeout: 800 * time.Millisecond}
	for _, url := range metadataURLs {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && len(body) > 0 {
			addFinding(p, "CRED", url,
				"Cloud metadata endpoint accessible — may contain IAM credentials",
				RiskHigh, true)
			break
		}
	}
}

func isReadable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

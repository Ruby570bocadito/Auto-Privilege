package autopriv

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// currentEUID is the effective-uid source for every root guard in the
// scanner suite (audit FP-1). It is a package var rather than a direct
// os.Geteuid call so the test suite can simulate an unprivileged scan on
// elevated CI runners — the guards themselves are what keep a root run
// from reporting "writable /etc/passwd" on a pristine host.
var currentEUID = os.Geteuid

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
		p.Findings = dedupFindings(p.Findings)
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
	// Same-access dedup (audit FP-9) runs on the merged result so both
	// engines — sequential and parallel — hand identical findings to every
	// downstream consumer (terminal, JSON, reports, gates, score).
	p.Findings = dedupFindings(p.Findings)
}

// dedupFindings collapses findings that describe the same underlying
// access (audit FP-9). Docker group membership, a writable docker socket
// and a CLI-reachable daemon are ONE breakout path, not three findings;
// a full sudo grant subsumes every per-binary rule below it. Rules:
//
//   - any DOCKER finding present  → drop CONTAINER/docker-daemon (same access)
//   - writable docker socket      → drop the DOCKER group-membership note
//   - SUDO "ALL" (full grant)     → drop per-binary SUDO findings
//
// Pure function over the slice — table-tested in audit_fixes_test.go.
func dedupFindings(fs []Finding) []Finding {
	hasDockerSocket, hasDockerAny, hasSudoAll := false, false, false
	for _, f := range fs {
		switch {
		case f.Source == "DOCKER" && f.Target == "/var/run/docker.sock":
			hasDockerSocket, hasDockerAny = true, true
		case f.Source == "DOCKER":
			hasDockerAny = true
		case f.Source == "SUDO" && f.Target == "ALL":
			hasSudoAll = true
		}
	}
	if !hasDockerAny && !hasSudoAll {
		return fs
	}
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if f.Source == "CONTAINER" && f.Target == "docker-daemon" && hasDockerAny {
			continue
		}
		if f.Source == "DOCKER" && hasDockerSocket && f.Target != "/var/run/docker.sock" {
			continue
		}
		if f.Source == "SUDO" && hasSudoAll && f.Target != "ALL" {
			continue
		}
		out = append(out, f)
	}
	return out
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

// standardSUIDBins / standardSGIDBins are the distribution-baseline setuid
// files (audit INC-2): su, sudo, passwd, mount and friends ship setuid on
// every stock Ubuntu/Debian host. The old scanner reported all seventeen
// as findings, a clean container bled 34 score points and the real signals
// drowned in inventory noise. Baseline binaries are skipped entirely —
// only deviations from the baseline surface. The skip is bounded to the
// system locations (isStandardBinLocation) so a setuid "passwd" planted in
// /opt still shows up.
var standardSUIDBins = map[string]bool{
	"at": true, "bwrap": true, "chage": true, "chfn": true, "chsh": true,
	"crontab": true, "dbus-daemon-launch-helper": true, "expiry": true,
	"fusermount": true, "fusermount3": true, "gpasswd": true, "mount": true,
	"mtr-packet": true, "newgrp": true, "passwd": true, "pkexec": true,
	"pppd": true, "sg": true, "snap-confine": true, "ssh-keysign": true,
	"su": true, "sudo": true, "umount": true, "unix_chkpwd": true,
	"pam_extrausers_chkpwd": true,
}

var standardSGIDBins = map[string]bool{
	"chage": true, "crontab": true, "expiry": true, "locate": true,
	"mail": true, "mlocate": true, "netreport": true, "plocate": true,
	"ssh-agent": true, "utempter": true, "wall": true, "write": true,
	"unix_chkpwd": true,
}

// standardBinLocationPrefixes are the trees where a baseline setuid binary
// is expected to live. /opt and /usr/local are deliberately absent: a
// setuid file there is a deviation worth reporting even under a familiar
// name.
var standardBinLocationPrefixes = []string{
	"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/",
	"/usr/lib64/", "/lib64/", "/lib/", "/snap/bin/", "/usr/lib/openssh/",
}

// isStandardBinLocation reports whether full sits inside one of the
// baseline trees. Pure function — table-tested.
func isStandardBinLocation(full string) bool {
	for _, pref := range standardBinLocationPrefixes {
		if strings.HasPrefix(full, pref) {
			return true
		}
	}
	return false
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
	// Second pass (audit FN-2): a renamed copy of a GTFOBins binary
	// (cp /usr/bin/find /opt/secure/bin/custom-find; chmod u+s) survives
	// the name-based lookup above as an unknown — content hashing against
	// the pristine copies on this host unmasks it.
	detectRenamedSUID(p)
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
		// Distribution baseline (INC-2): su, sudo, passwd… are inventory,
		// not findings — but only in the trees where they are expected.
		if standardSUIDBins[e.Name()] && isStandardBinLocation(full) {
			return
		}
		risk, expl := classifySUID(e.Name(), uid)
		if currentEUID() == 0 && expl {
			// FP-1: running as root, a setuid file grants this process
			// nothing it lacks — honest inventory, no escalation claim.
			risk, expl = RiskLow, false
		}
		reportSetBit(p, "SUID", e.Name(), full, uid, risk, expl)
	}
	if info.Mode()&os.ModeSetgid != 0 {
		if standardSGIDBins[e.Name()] && isStandardBinLocation(full) {
			return
		}
		risk, expl := classifySGID(e.Name(), gid)
		if currentEUID() == 0 && expl {
			risk, expl = RiskMedium, false
		}
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

// --- Renamed SUID detection (content hashing, audit FN-2) ---
// referenceBinDirs is where rename detection looks for the pristine copies
// of GTFOBins binaries to hash against.
var referenceBinDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"}

// maxHashBytes caps hashing so a pathological file can never stall the
// scan: anything bigger than this is not a "renamed copy" scenario.
const maxHashBytes = 100 << 20

// hashFile returns the hex SHA-256 of a regular file, or "" when the path
// is unreadable, not regular, or over the size cap. Symlinks are rejected
// (Lstat): only real bytes are compared.
func hashFile(path string) string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxHashBytes {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxHashBytes+1)); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// detectRenamedSUID upgrades the "unknown SUID" findings of this scanner's
// own pass: every root-owned non-GTFOBins-named setuid file is hashed and
// compared against the pristine GTFOBins binaries present on this host.
// Identical bytes under a different name is the renamed-SUID trick
// (`cp /usr/bin/find /opt/secure/bin/custom-find; chmod u+s`), and the
// finding is rewritten in place to say exactly what the file is. The order
// of p.Findings is preserved (the parallel-merge contract depends on it).
func detectRenamedSUID(p *AutoPrivilege) {
	var candidates []int
	for i, f := range p.Findings {
		// Only this scanner's own output: SUID, non-exploitable, and the
		// "GTFOBins: false" reason marks a root-owned unknown. Non-root
		// owners say "not a root vector" and are not copies of interest.
		if f.Source == "SUID" && !f.Exploitable && strings.Contains(f.Description, "GTFOBins: false") {
			candidates = append(candidates, i)
		}
	}
	if len(candidates) == 0 {
		return
	}
	// Reference index: hash → canonical GTFOBins name. First pristine copy
	// of each hash wins (vi/vim dups collapse harmlessly).
	refs := map[string]string{}
	for name := range gtfoLookup {
		for _, dir := range referenceBinDirs {
			if h := hashFile(filepath.Join(dir, name)); h != "" {
				refs[h] = name
				break
			}
		}
	}
	if len(refs) == 0 {
		return
	}
	for _, i := range candidates {
		orig, ok := refs[hashFile(p.Findings[i].Target)]
		if !ok {
			continue
		}
		f := &p.Findings[i]
		f.Description = fmt.Sprintf("SUID binary: %s is a byte-identical copy of %s — renamed GTFOBins binary", filepath.Base(f.Target), orig)
		f.Risk, f.Exploitable = RiskHigh, true
		if currentEUID() == 0 {
			// FP-1: root cannot escalate past root — inventory only.
			f.Risk, f.Exploitable = RiskLow, false
		}
	}
}

// --- Sudo ---
// sudoRule is one parsed command spec from `sudo -n -l` output: the binary,
// its fixed arguments (empty for a FREE rule) and whether a tag made it
// passwordless.
type sudoRule struct {
	Bin          string
	Args         string
	Passwordless bool
}

// parseSudoRules parses the command section of `sudo -l` output into
// rules. Grammar handled (audit FP-8 — the old parser grabbed every
// slash-token in sight, so `/usr/bin/find /var/www` reported a free
// "NOPASSWD sudo: find" while the rule was actually path-restricted):
//
//	(root) /usr/bin/awk                           — free rule, password required
//	(ALL) NOPASSWD: /usr/bin/find                 — free rule, passwordless
//	(root) NOPASSWD: /usr/bin/tar -cf /dev/null * — restricted rule
//	(ALL) ALL                                     — full access
//
// Comma-separated spec lists and repeated (runas) segments are handled;
// header lines, Defaults and prose never start with "(" and are skipped.
// Pure function — table-tested against real sudo -l transcripts.
func parseSudoRules(output string) []sudoRule {
	var rules []sudoRule
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "(") {
			continue
		}
		passwordless := false
		for _, spec := range strings.Split(line, ", ") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			// optional runas segment at spec start: "(root) /usr/bin/awk"
			if strings.HasPrefix(spec, "(") {
				i := strings.Index(spec, ")")
				if i < 0 {
					continue
				}
				spec = strings.TrimSpace(spec[i+1:])
			}
			if strings.HasPrefix(spec, "NOPASSWD:") {
				passwordless = true
				spec = strings.TrimSpace(spec[len("NOPASSWD:"):])
			} else if strings.HasPrefix(spec, "PASSWD:") {
				passwordless = false
				spec = strings.TrimSpace(spec[len("PASSWD:"):])
			}
			fields := strings.Fields(spec)
			if len(fields) == 0 {
				continue
			}
			rules = append(rules, sudoRule{
				Bin:          fields[0],
				Args:         strings.Join(fields[1:], " "),
				Passwordless: passwordless,
			})
		}
	}
	return rules
}

func scanSudo(p *AutoPrivilege) {
	// Root guard (audit FP-1): a root run of `sudo -n -l` lists (ALL) ALL
	// on literally any host — root already holds every power sudo grants.
	if currentEUID() == 0 {
		return
	}
	user := currentUsername()

	// sudo -n fails fast instead of prompting for a password (the old
	// `sudo -l` fallback hung forever in labs without a password).
	out, err := runCmdOut(p.Opts.scanCmdTimeout(), "sudo", "-n", "-l")
	if err != nil {
		// `sudo -n -l` fails for two very different reasons. No rules at
		// all → honest silence. Rules that need a password → "sudo: a
		// password is required" in the combined output. The second case is
		// a real escalation path for the account owner (audit FN-4: a
		// `k ALL=(ALL) ALL` user was invisible — "no exploitable findings"
		// — while their own password turns sudo into root). It surfaces as
		// a visible, non-gate-tripping lead: passworded sudo is the
		// standard admin setup, not a misconfiguration.
		if strings.Contains(string(out), "a password is required") {
			addFinding(p, "SUDO", user,
				"Passworded sudo rules exist — the account's own password may unlock root (run `sudo -l` to review; standard admin setup on desktops)",
				RiskMedium, false)
			return
		}
		// Group fallback: no rules readable and no prompt seen, but
		// sudo/wheel membership is itself the classic grant.
		if isInGroup(p.Opts, user, "sudo") || isInGroup(p.Opts, user, "wheel") {
			addFinding(p, "SUDO", user,
				"User in sudo/wheel group — passworded sudo likely (own password unlocks root); verify with `sudo -l`",
				RiskMedium, false)
		}
		return
	}

	rules := parseSudoRules(string(out))
	full, fullPasswordless := false, false
	for _, r := range rules {
		if r.Bin == "ALL" {
			full = true
			if r.Passwordless {
				fullPasswordless = true
			}
		}
	}
	if full {
		if fullPasswordless {
			addFinding(p, "SUDO", "ALL",
				"Full passwordless sudo — instant root",
				RiskHigh, true)
		} else {
			addFinding(p, "SUDO", "ALL",
				"Full sudo access (password required) — the account's own password unlocks root",
				RiskMedium, false)
		}
		// FP-9: a full grant subsumes every per-binary rule — reporting
		// both double-counts the same access in gates and score.
		return
	}

	seen := map[string]bool{}
	for _, r := range rules {
		if !strings.HasPrefix(r.Bin, "/") {
			continue // non-absolute specs are not command rules
		}
		key := r.Bin + "|" + strconv.FormatBool(r.Passwordless)
		if seen[key] {
			continue
		}
		seen[key] = true
		bin := filepath.Base(r.Bin)
		_, isGTFO := getCommand(bin)
		switch {
		case r.Args != "" && r.Passwordless:
			// FP-8: arguments restrict the invocation. The textbook
			// "sudo find → root" technique does not apply verbatim when
			// sudo itself pins the argument list; an escape may still
			// exist (wildcards, subcommands) but that is manual review,
			// not a confirmed vector.
			addFinding(p, "SUDO", r.Bin,
				fmt.Sprintf("Restricted NOPASSWD sudo: %s %s — args pin the invocation; review whether they still permit a technique escape", r.Bin, r.Args),
				RiskMedium, false)
		case r.Args != "":
			addFinding(p, "SUDO", r.Bin,
				fmt.Sprintf("Restricted sudo (password required): %s %s — review the args before use", r.Bin, r.Args),
				RiskLow, false)
		case r.Passwordless && isGTFO:
			if cmd, ok := getCommand(bin); ok {
				addFinding(p, "SUDO", r.Bin,
					fmt.Sprintf("NOPASSWD sudo: %s → %s", r.Bin, strings.SplitN(cmd, " ", 2)[0]),
					RiskHigh, true)
			}
		case r.Passwordless:
			addFinding(p, "SUDO", r.Bin,
				fmt.Sprintf("NOPASSWD sudo on %s — runs as root; check whether the binary is escapable", r.Bin),
				RiskLow, false)
		default:
			// Free rule, password required (FN-4): a real vector for the
			// account owner, authorized-by-design on admin machines —
			// visible, never gate-tripping.
			if isGTFO {
				addFinding(p, "SUDO", r.Bin,
					fmt.Sprintf("sudo (password required): %s — the account's own password turns this into root", r.Bin),
					RiskMedium, false)
			}
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
// cronSystemDirs hold schedules whose jobs execute as root: any writable
// file here is injectable, and any script they reference is load-bearing.
var cronSystemDirs = []string{
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.hourly",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
}

// cronSpoolDirs hold per-user crontabs; the FILE NAME is the owning user,
// and each user's jobs run as that user — never as root.
var cronSpoolDirs = []string{
	"/var/spool/cron/crontabs",
	"/var/spool/cron",
}

func scanCron(p *AutoPrivilege) {
	// Root guard (audit FP-1): as root every cron file is writable and the
	// scanner degrades into a wall of noise on a pristine host.
	if currentEUID() == 0 {
		return
	}
	user := currentUsername()

	// System schedules run as root.
	for _, dir := range cronSystemDirs {
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
			if e.IsDir() {
				continue
			}
			full := filepath.Join(dir, name)
			info, err := os.Lstat(full)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if isWritableByCurrentUser(full) {
				addFinding(p, "CRON", full,
					"Writable root cron file — inject command (runs as root)",
					RiskHigh, true)
				continue
			}
			// Not writable: the root-run schedule can still be abused
			// through wildcard-absorption (heuristic below) or through a
			// referenced script this user can swap (FN-3) — read-only
			// content analysis, nothing executed.
			if isReadable(full) {
				scanCronWildcards(p, full)
				scanCronReferencedScripts(p, full)
			}
		}
	}
	// The legacy /etc/crontab gets the same two-pass treatment.
	scanCrontabFile(p, "/etc/crontab")

	// Per-user spool crontabs. Audit FP-5: your OWN crontab runs as YOU —
	// writing it or its scripts is not an escalation and must stay silent.
	// Another user's crontab (root's above all) is a real target.
	seenSpool := map[string]bool{}
	for _, dir := range cronSpoolDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if name == ".placeholder" || strings.HasPrefix(name, ".") || e.IsDir() {
				continue
			}
			if name == user {
				continue
			}
			full := filepath.Join(dir, name)
			resolved, err := filepath.EvalSymlinks(full)
			if err != nil {
				resolved = full
			}
			if seenSpool[resolved] {
				continue
			}
			seenSpool[resolved] = true
			info, err := os.Lstat(full)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if isWritableByCurrentUser(full) {
				if name == "root" {
					addFinding(p, "CRON", full,
						"Writable root crontab — inject a root command",
						RiskHigh, true)
				} else {
					addFinding(p, "CRON", full,
						fmt.Sprintf("Writable crontab of user %s — jobs run as that user (lateral, not root)", name),
						RiskMedium, false)
				}
				continue
			}
			// Readable root spool crontab: referenced scripts matter too.
			if name == "root" && isReadable(full) {
				scanCronReferencedScripts(p, full)
			}
		}
	}
}

// scanCrontabFile applies the writable-check + referenced-scripts pass to a
// single schedule file (/etc/crontab).
func scanCrontabFile(p *AutoPrivilege, path string) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	if isWritableByCurrentUser(path) {
		addFinding(p, "CRON", path,
			"Writable /etc/crontab — inject a root command",
			RiskHigh, true)
		return
	}
	if isReadable(path) {
		scanCronReferencedScripts(p, path)
	}
}

// cronReferencedPaths extracts candidate file paths from one cron command
// line: the binary, its file arguments and redirect targets (">log",
// "2>/dev/null" — the target follows the last ">"). Env assignments
// ("PATH=/usr/bin") never look like paths because they carry no ">" and do
// not start with "/". Pure function — table-tested.
func cronReferencedPaths(line string) []string {
	var out []string
	for _, f := range strings.Fields(line) {
		if i := strings.LastIndex(f, ">"); i >= 0 {
			f = f[i+1:]
		}
		f = strings.Trim(f, "\"'")
		if strings.HasPrefix(f, "/") {
			out = append(out, f)
		}
	}
	return out
}

// scanCronReferencedScripts reads a root-run schedule file and flags any
// referenced script the current user can write: the schedule itself can be
// fully locked down while its payload is swappable. Audit FN-3 — the old
// check only ever ran over the user's OWN `crontab -l` output (pure FP-5
// territory) and never looked at /etc/cron.d references. Device nodes
// (/dev/null in a redirect) are excluded by the regular-file check.
func scanCronReferencedScripts(p *AutoPrivilege, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	self, _ := filepath.EvalSymlinks(path)
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, ref := range cronReferencedPaths(line) {
			info, err := os.Lstat(ref)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			resolved, _ := filepath.EvalSymlinks(ref)
			if resolved == self || seen[resolved] {
				continue
			}
			seen[resolved] = true
			if isWritableByCurrentUser(ref) {
				addFinding(p, "CRON", ref,
					fmt.Sprintf("Root cron %s references user-writable script — replace the payload, wait for the schedule", filepath.Base(path)),
					RiskHigh, true)
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
// --- /etc/passwd writable ---
func scanPasswd(p *AutoPrivilege) {
	// Root guard (audit FP-1): root can write anything by definition — the
	// old check fired "Writable /etc/passwd" on every pristine host scanned
	// as root. The only honest root-run signal is a permission-bit
	// MISCONFIGURATION (group/world-writable), which is exactly what other
	// local users would abuse.
	if currentEUID() == 0 {
		if info, err := os.Lstat("/etc/passwd"); err == nil && info.Mode().Perm()&0022 != 0 {
			addFinding(p, "FILE", "/etc/passwd",
				"Group/world-writable /etc/passwd (misconfiguration) — any local user can inject a root account",
				RiskHigh, false)
		}
		return
	}
	if isWritableByCurrentUser("/etc/passwd") {
		addFinding(p, "FILE", "/etc/passwd",
			"Writable /etc/passwd — inject root user",
			RiskHigh, true)
	}
}

// --- /etc/shadow readable/writable ---
// --- /etc/shadow readable/writable ---
func scanShadow(p *AutoPrivilege) {
	// Root guard (audit FP-1), same contract as scanPasswd: as root the
	// readable/writable questions are meaningless (the answer is always
	// yes), but the permission bits still tell the truth about what OTHER
	// users can do. Ubuntu's 0640 root:shadow stays silent; 0644 or 0666 are
	// real misconfigurations worth surfacing from any uid.
	if currentEUID() == 0 {
		if info, err := os.Lstat("/etc/shadow"); err == nil {
			perm := info.Mode().Perm()
			if perm&0004 != 0 {
				addFinding(p, "FILE", "/etc/shadow",
					"World-readable /etc/shadow (misconfiguration) — hashes crackable by any local user",
					RiskHigh, false)
			}
			if perm&0022 != 0 {
				addFinding(p, "FILE", "/etc/shadow",
					"Group/world-writable /etc/shadow (misconfiguration)",
					RiskDanger, false)
			}
		}
		return
	}
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
// --- Docker ---
func scanDocker(p *AutoPrivilege) {
	// Root guard (audit FP-1): root owns the socket — membership and
	// writability tell it nothing it does not already have.
	if currentEUID() == 0 {
		return
	}
	// Audit FP-9: group membership, a writable socket and a reachable
	// daemon are ONE breakout path. The socket is the most direct evidence,
	// so it owns the exploitable finding; the group note only appears when
	// the socket is NOT directly writable (rootless daemon, DOCKER_HOST).
	socketWritable := false
	if info, err := os.Lstat("/var/run/docker.sock"); err == nil && info.Mode()&os.ModeSocket != 0 {
		if isWritableByCurrentUser("/var/run/docker.sock") {
			socketWritable = true
			addFinding(p, "DOCKER", "/var/run/docker.sock",
				"Writable docker socket — container breakout to root",
				RiskHigh, true)
		}
	}
	if !socketWritable && isInGroup(p.Opts, currentUsername(), "docker") {
		addFinding(p, "DOCKER", currentUsername(),
			"User in docker group but socket not writable here — rootless or remote daemon? verify with `docker ps`",
			RiskMedium, false)
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
// scanContainers reports the container context the tool itself runs in and
// the container-runtime breakout surfaces around it. Honesty rules: the
// "inside a container" indicator never claims escalation by itself (the
// breakout technique must come from a reachable runtime), the daemon CLI
// check notes that rootless runtimes contain the classic breakout, and —
// audit FP-2 — a SINGLE NSpid value is the bare-metal default, never
// container evidence. The old logic counted "host PID namespace visible"
// as proof of being in a container and fired on every laptop and WSL host
// with a self-contradictory message; only an OWN PID namespace (NSpid
// listing two or more ids) is a container signal now.
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
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		// FP-2: see the comment above — "own" is the only namespace verdict
		// that belongs in container evidence.
		if ns := pidNamespaceFromStatus(string(data)); ns == "own" {
			evidence = append(evidence, "own PID namespace (NSpid lists multiple ids)")
		}
		if containerPrivilegeFromStatus(string(data)) == "privileged" {
			evidence = append(evidence, "privileged caps (cap_sys_admin in CapEff)")
			privileged = true
		}
	}
	if len(evidence) > 0 {
		// Host init environment: in a shared PID namespace /proc/1 is the
		// host init and its environ is a credential prize when readable.
		// Only probed when other container evidence exists — on bare metal
		// the host init's environ is readable to root and would fabricate a
		// false container signal. The CONTENT is never printed: only the
		// readability is declared. Permission-denied is the common case and
		// stays silent.
		if _, err := os.ReadFile("/proc/1/environ"); err == nil {
			evidence = append(evidence, "host init environment readable (/proc/1/environ)")
		}
		// Context note, not a posture hit (audit INC-2): being in a normal
		// container is the deployment's shape, not a misconfiguration —
		// RiskSafe keeps a clean container's score at 100. A PRIVILEGED
		// container is genuinely bad posture and stays HIGH informational.
		risk := RiskSafe
		if privileged {
			risk = RiskHigh
		}
		addFinding(p, "CONTAINER", "self",
			fmt.Sprintf("Running inside a container (%s) — context note, not an escalation by itself; breakout needs a reachable runtime socket or privileged caps",
				strings.Join(evidence, ", ")),
			risk, false)
	}

	// The socket and daemon surfaces below are escalation paths — for root
	// they are meaningless (audit FP-1).
	if currentEUID() == 0 {
		return
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
	// covers DOCKER_HOST / oddly-permissioned setups. dedupFindings drops
	// this finding again when a DOCKER finding already covers the access
	// (audit FP-9: one breakout path, one finding).
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
	// Root guard (audit FP-1): "Process holds CAP_SETUID — can become root
	// in-process" said to a root user is absurd; root starts with every
	// capability the mask can hold.
	if currentEUID() == 0 {
		return
	}
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
// scanFileCaps looks for binaries with file capabilities (e.g. cap_setuid+ep
// on an interpreter) using getcap when available.
func scanFileCaps(p *AutoPrivilege) {
	// Root guard (audit FP-1): file capabilities grant nothing root lacks.
	if currentEUID() == 0 {
		return
	}
	// getcap -r walks the whole filesystem: it is the slowest external call
	// of the scan, so it gets 4x the configured timeout. /usr/local joins
	// the roots — custom interpreters live there more often than in /usr.
	out, err := runCmdOut(4*p.Opts.scanCmdTimeout(), "getcap", "-r", "/usr", "/bin", "/sbin", "/opt", "/usr/local")
	if err != nil && len(out) == 0 {
		return // getcap missing entirely — skip silently
	}
	// err != nil WITH output: getcap exits nonzero when parts of the tree
	// are unreadable but still prints every capability it found — the
	// findings stand (audit FN-1: the old code threw them all away).
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		binPath, caps, ok := parseGetcapLine(line)
		if !ok {
			continue
		}
		if _, err := os.Lstat(binPath); err != nil {
			continue
		}
		switch {
		case strings.Contains(caps, "cap_setuid"):
			addFinding(p, "CAPS", "cap_setuid:"+binPath,
				fmt.Sprintf("cap_setuid on %s — interpreter can setuid(0) in-process", binPath),
				RiskMedium, true)
		case strings.Contains(caps, "cap_dac_read_search"):
			addFinding(p, "CAPS", "cap_dac_read_search:"+binPath,
				fmt.Sprintf("cap_dac_read_search on %s — reads any file (/etc/shadow included)", binPath),
				RiskMedium, true)
		case strings.Contains(caps, "cap_sys_admin"):
			addFinding(p, "CAPS", "cap_sys_admin:"+binPath,
				fmt.Sprintf("cap_sys_admin on %s — mount/namespace escape territory (verify)", binPath),
				RiskMedium, false)
		}
	}
}

// parseGetcapLine tolerates BOTH getcap output formats (audit FN-1 — the
// old SplitN(line, " =", 2) silently discarded every modern-format line):
//
//	modern libcap (>= 2.60):  /usr/bin/python3.10 cap_setuid=ep
//	legacy:                   /usr/bin/foo = cap_setuid+ep
//
// A line without any cap_ token (stderr warnings that CombinedOutput mixed
// in) is rejected. Paths containing spaces survive via the legacy branch.
// Pure function — table-tested.
func parseGetcapLine(line string) (path, caps string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", false
	}
	for i := 0; i < len(fields); i++ {
		tok := fields[i]
		if tok == "=" && i >= 1 && i+1 < len(fields) {
			return strings.Join(fields[:i], " "), fields[i+1], true
		}
		if strings.Contains(tok, "cap_") && i >= 1 {
			return strings.Join(fields[:i], " "), tok, true
		}
	}
	return "", "", false
}

// --- NFS ---
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
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		reported := false
		for _, client := range fields[1:] {
			// FP-7: no_root_squash only matters on a WRITABLE export. The old
			// substring match flagged read-only exports as "mount and own
			// files as root" — on ro the attacker gets root-owned READS at
			// best. exports(5) default is rw when neither rw nor ro is set,
			// so "not ro" is the honest writability test.
			_, ro, nrs := nfsClientOptions(client)
			if !nrs || reported {
				continue
			}
			if !ro {
				addFinding(p, "NFS", line,
					"NFS export rw + no_root_squash — mount remotely and own files as root",
					RiskHigh, true)
			} else {
				addFinding(p, "NFS", line,
					"NFS export ro + no_root_squash — root-owned reads over NFS only, no file takeover",
					RiskLow, false)
			}
			reported = true // one finding per export line keeps the report honest
		}
		if !reported && nfsExportHostless(line) {
			addFinding(p, "NFS", line,
				"NFS export rw without host restriction — any client may mount",
				RiskMedium, false)
		}
	}
}

// nfsClientOptions parses one client spec — "(rw,no_root_squash)",
// "*(ro,no_root_squash)", "192.168.1.0/24(rw)" — into its security-relevant
// flags. The option group is the LAST parenthesized chunk, so both the
// bare "(rw,...)" form and any host-qualified "host(rw,...)" form parse.
// Pure function — table-tested.
func nfsClientOptions(client string) (rw, ro, noRootSquash bool) {
	i := strings.LastIndex(client, "(")
	if i < 0 || !strings.HasSuffix(client, ")") {
		return false, false, false
	}
	s := client[i+1 : len(client)-1]
	for _, opt := range strings.Split(s, ",") {
		switch strings.TrimSpace(opt) {
		case "rw":
			rw = true
		case "ro":
			ro = true
		case "no_root_squash":
			noRootSquash = true
		}
	}
	return
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
// --- Writable PATH entries ---
// scanWritablePath flags PATH directories the CURRENT USER can really write
// to. The old version tested the OWNER's write bit (`perm&0200`), which
// flagged root-owned 755 directories as "writable binary planting" — a false
// positive the Director reproduced live (honest results demand real access).
func scanWritablePath(p *AutoPrivilege) {
	// Running as root, nothing in PATH can escalate further: every
	// directory is "writable" and every finding would be noise.
	if currentEUID() == 0 {
		return
	}
	dirs := strings.Split(os.Getenv("PATH"), ":")
	// Audit FN-5: /etc/environment carries the PAM-level PATH that LOGIN
	// sessions use — docker exec and cron never source it, so the process
	// env alone misses exactly the directory a future login will trust.
	if data, err := os.ReadFile("/etc/environment"); err == nil {
		dirs = append(dirs, envPathDirs(string(data))...)
	}
	seen := map[string]bool{}
	for _, dir := range dirs {
		if dir == "" {
			dir = "."
		}
		if seen[dir] {
			continue
		}
		seen[dir] = true
		if planting, owner := isPathPlantingDir(dir); planting {
			addFinding(p, "PATH", dir,
				"Writable directory in PATH (owner uid "+owner+") — binary planting",
				RiskHigh, true)
		}
	}
}

// envPathDirs parses PATH assignments out of /etc/environment content
// (PATH="..." or PATH=...). Pure function — table-tested.
func envPathDirs(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PATH=") {
			continue
		}
		v := strings.Trim(strings.TrimPrefix(line, "PATH="), "\"'")
		for _, dir := range strings.Split(v, ":") {
			if dir != "" {
				out = append(out, dir)
			}
		}
	}
	return out
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
// scanServices covers the two service-execution families the current user
// must never be able to rewrite: systemd units (systemd) and SysV init
// scripts (init.d). Both run as root — at boot, on restart, on timer fire.
func scanServices(p *AutoPrivilege) {
	// Root guard (audit FP-1): as root every unit file is writable and the
	// scanner reports a pristine host as 21 HIGH/DANGER findings.
	if currentEUID() == 0 {
		return
	}
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

// kernelCVEEntry is one version-range heuristic. ranges is a list of
// [min,max] pairs (inclusive, OR-ed) so multi-range CVEs fit — INC-1:
// StackRot (CVE-2023-3269, never 32629) affects 6.1.0-6.1.36 AND
// 6.2.0-6.3.10; the old single range 6.1.0-6.1.13 hid 6.1.14+ and all of
// 6.2/6.3 behind a wrong CVE id.
type kernelCVEEntry struct {
	cve    string
	name   string
	desc   string
	ranges [][]int
	risk   RiskLevel
}

// kernelCVEDB returns the heuristic table. Every entry is exploitable=false
// by policy (audit FP-4): version ranges cannot see distro backports, so a
// match is a VERIFY lead, never confirmed surface — it must not trip
// --fail-on, --min-score or the auto-exploit pipeline.
func kernelCVEDB() []kernelCVEEntry {
	return []kernelCVEEntry{
		{
			cve:  "CVE-2022-0847",
			name: "Dirty Pipe",
			desc: "kernel pipe buffer flag overwrite — read/write any file as root",
			ranges: [][]int{
				{5, 8, 0, 5, 16, 10},
			},
			risk: RiskHigh,
		},
		{
			// The canonical legacy/CTF vector: the fix landed in 4.8.3
			// (also backported to 4.7.9 and 4.4.26), so the conservative
			// window is 2.6.22 through 4.8.3 — on any modern kernel this
			// never fires, which keeps it free of noise (R29).
			cve:  "CVE-2016-5195",
			name: "Dirty Cow",
			desc: "mm/gup race in copy-on-write — write to read-only mappings, root any legacy host",
			ranges: [][]int{
				{2, 6, 22, 4, 8, 3},
			},
			risk: RiskHigh,
		},
		{
			cve:  "CVE-2023-0386",
			name: "OverlayFS",
			desc: "overlayfs copy-up permission bypass — file ownership escalation",
			ranges: [][]int{
				{5, 11, 0, 6, 2, 0},
			},
			risk: RiskHigh,
		},
		{
			// INC-1: correct id (3269, StackRot) and BOTH affected windows:
			// fixed upstream in 6.1.37 and 6.3.11.
			cve:  "CVE-2023-3269",
			name: "StackRot",
			desc: "kernel 6.1-6.3 VMA stack expansion race — local privilege escalation",
			ranges: [][]int{
				{6, 1, 0, 6, 1, 36},
				{6, 2, 0, 6, 3, 10},
			},
			risk: RiskMedium,
		},
		{
			cve:  "CVE-2024-1086",
			name: "nf_tables UAF",
			desc: "netfilter use-after-free — local privilege escalation",
			ranges: [][]int{
				{5, 14, 0, 6, 6, 13},
			},
			risk: RiskHigh,
		},
	}
}

// versionInAnyRange reports whether v falls inside any [min,max] pair of
// the ranges list. Each pair is a flat 6-int slice (major,minor,patch twice).
func versionInAnyRange(v []int, ranges [][]int) bool {
	for _, r := range ranges {
		if len(r) != 6 {
			continue
		}
		if kernelInRange(v, r[0:3], r[3:6]) {
			return true
		}
	}
	return false
}

func scanKernelCVE(p *AutoPrivilege) {
	out, err := runCmdOut(p.Opts.scanCmdTimeout(), "uname", "-r")
	if err != nil {
		return
	}
	kernel := strings.TrimSpace(string(out))
	kv := kernelVersion(kernel)
	for _, cve := range kernelCVEDB() {
		if !versionInAnyRange(kv, cve.ranges) {
			continue
		}
		// FP-4: heuristic findings are informational, always. The text says
		// exactly how to verify before burning time on an exploit that a
		// distro backport already defused.
		addFinding(p, "KERNEL", cve.cve,
			fmt.Sprintf("Kernel %s in affected range for %s (%s) — %s. Version heuristic only: distro backports may already patch it; verify (e.g. `ubuntu.com/security/CVEs`, `apt changelog linux`) before use",
				kernel, cve.name, cve.cve, cve.desc),
			cve.risk, false)
	}
}

// --- PwnKit ---
// scanPwnKit checks for a SUID pkexec binary (CVE-2021-4034 affects polkit,
// not the kernel — the old code matched it against kernel versions).
// --- PwnKit ---
// scanPwnKit checks for a SUID pkexec binary (CVE-2021-4034 affects polkit,
// not the kernel — the old code matched it against kernel versions).
// Audit FP-3: every SUID pkexec on earth matched "HIGH exploitable" even
// though every current distro has shipped the 2022 patch years ago. The
// honest classification is an informational lead: verify the package patch
// level before treating it as a vector.
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
		fmt.Sprintf("SUID pkexec present (%s) — PwnKit candidate; all current distros ship the 2022 patch, verify the package level (e.g. `dpkg -l policykit-1`) before use",
			version),
		RiskLow, false)
}

// --- sudo version ---
// scanSudoVersion flags old sudo builds vulnerable to Baron Samedit
// (CVE-2021-3156, fixed in 1.9.5p2) — a sudo bug, not a kernel one.
// --- sudo version ---
// scanSudoVersion flags old sudo builds vulnerable to Baron Samedit
// (CVE-2021-3156, fixed in 1.9.5p2) — a sudo bug, not a kernel one.
// Version comparison alone cannot see distro backports (Ubuntu 20.04's
// 1.8.31-1ubuntu1.2 is patched but "older"), so the finding is an
// informational lead with the verification step spelled out.
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
				fmt.Sprintf("sudo %s older than 1.9.5p2 — Baron Samedit heap overflow candidate; distros backported the fix, verify the package version (`dpkg -l sudo`) before use", ver),
				RiskMedium, false)
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
	// Root guard (audit FP-1): the preload/sudoers surfaces are root's own
	// configuration — a root run would flag them all "writable".
	if currentEUID() == 0 {
		return
	}
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
	if currentEUID() == 0 {
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
	// Root guard (audit FP-1): every login hook is writable for root on a
	// pristine host — pure noise from a privileged scan.
	if currentEUID() == 0 {
		return
	}
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
	scanCustomConfigs(p)
	scanHistoryFiles(p)
	scanCloudMetadata(p)
}

// customConfigRoots are walked (depth-bounded) for credential-bearing
// config files in locations that are neither /etc services nor the classic
// dotfile set — audit FN-5: /opt/custom/db.conf and .env-style secrets
// were invisible because /opt was not on any scan list.
var customConfigRoots = []string{"/opt", "/srv", "/var/www"}

// customConfigSuffixes select which files get content-checked.
var customConfigSuffixes = []string{".env", ".conf", ".ini", ".cfg", ".cnf", ".yaml", ".yml"}

// customConfigSkipDirs are noise trees never descended into.
var customConfigSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, ".cache": true, ".npm": true,
	".local": true, ".config": true, "site-packages": true, "vendor": true,
	"__pycache__": true, ".venv": true, "venv": true,
}

// credPlaceholderValues are obvious non-secrets that still match the
// assignment patterns (documentation examples, templates).
var credPlaceholderValues = map[string]bool{
	"changeme": true, "change_me": true, "example": true, "placeholder": true,
	"xxx": true, "xxxx": true, "xxxxx": true, "dummy": true, "sample": true,
	"your_password": true, "<password>": true, "password": true, "test": true,
	"secret": true, "none": true, "null": true, "true": true, "false": true,
	"notset": true, "redacted": true, "todo": true, "fixme": true,
}

const (
	maxCustomConfigDepth = 3
	maxCustomConfigBytes = 1 << 20
)

// scanCustomConfigs sweeps the custom roots (plus $HOME, shallow) for
// readable config files containing credential assignments.
func scanCustomConfigs(p *AutoPrivilege) {
	roots := append([]string{}, customConfigRoots...)
	if home := os.Getenv("HOME"); home != "" && home != "/root" {
		roots = append(roots, home)
	}
	for _, root := range roots {
		walkCustomConfigs(p, root, 0)
	}
}

func walkCustomConfigs(p *AutoPrivilege, dir string, depth int) {
	if depth > maxCustomConfigDepth {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if !customConfigSkipDirs[e.Name()] {
				walkCustomConfigs(p, full, depth+1)
			}
			continue
		}
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := strings.ToLower(e.Name())
		match := name == ".env" || strings.HasPrefix(name, ".env.")
		if !match {
			for _, suf := range customConfigSuffixes {
				if strings.HasSuffix(name, suf) {
					match = true
					break
				}
			}
		}
		if !match {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxCustomConfigBytes {
			continue
		}
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		if label := credentialAssignmentMatch(string(data)); label != "" {
			addFinding(p, "CRED", full,
				fmt.Sprintf("Credential assignment in %s (%s) — readable secret, verify scope and rotate", full, label),
				RiskMedium, true)
		}
	}
}

// credAssignRes are line-anchored assignment patterns for config files.
var credAssignRes = []struct {
	label string
	re    *regexp.Regexp
}{
	{"password", regexp.MustCompile(`(?im)^\s*[a-z0-9_]*(?:password|passwd|pwd)[\t ]*[=:][\t ]*["']?([^\s"']{3,})`)},
	{"redis requirepass", regexp.MustCompile(`(?im)^\s*requirepass[\t ]+([^\s]{3,})`)},
	{"secret/key", regexp.MustCompile(`(?im)^\s*(?:api_?key|secret|secret_?key|client_?secret|private_?key)[\t ]*[=:][\t ]*["']?([^\s"']{3,})`)},
	{"token", regexp.MustCompile(`(?im)^\s*(?:token|access_?token|auth_?token)[\t ]*[=:][\t ]*["']?([^\s"']{3,})`)},
	{"aws key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
}

// credentialAssignmentMatch returns the label of the first real (non-
// placeholder, non-template) credential assignment found. Pure function.
func credentialAssignmentMatch(content string) string {
	for _, pat := range credAssignRes {
		for _, m := range pat.re.FindAllStringSubmatch(content, -1) {
			v := strings.ToLower(strings.Trim(m[1], "\"'"))
			if strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$(") {
				continue // template reference, not a literal secret
			}
			if !credPlaceholderValues[v] {
				return pat.label
			}
		}
	}
	return ""
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

// historySecretRes are the context-aware secret patterns for shell history
// (audit FP-6). Substring fishing over "password|secret|token|private"
// flagged benign prose like `echo rotate password quarterly` or
// `grep -rn token ./src` as HIGH exploitable; every pattern below demands
// assignment or usage context instead. Findings are MEDIUM informational:
// a lead to review and purge, never confirmed credentials.
var historySecretRes = []struct {
	label string
	re    *regexp.Regexp
}{
	{"password assignment", regexp.MustCompile(`(?i)(?:^|[^a-z0-9])[a-z0-9_]*(?:password|passwd|pwd)[\t ]*[=:][\t ]*["']?[^\s"']{3,}`)},
	{"redis requirepass", regexp.MustCompile(`(?im)^\s*requirepass[\t ]+\S{3,}`)},
	{"secret/token/api-key assignment", regexp.MustCompile(`(?i)\b(?:secret|api_?key|access_?key|client_?secret|secret_?key)\s*[=:]\s*["']?[^\s"']{3,}`)},
	{"token assignment", regexp.MustCompile(`(?i)\btoken\s*[=:]\s*["']?[^\s"']{3,}`)},
	{"password flag with value", regexp.MustCompile(`(?i)(?:--password(?:=|\s+)\S+|-p\s*["'][^"']{3,}["'])`)},
	{"aws access key id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"aws secret key assignment", regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*\S+`)},
	{"private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

// historySecretMatches returns the labels of every pattern that hits the
// content. Pure function — table-tested with benign and malicious lines.
func historySecretMatches(content string) []string {
	var found []string
	for _, pat := range historySecretRes {
		if pat.re.MatchString(content) {
			found = append(found, pat.label)
		}
	}
	return found
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
		found := historySecretMatches(content)
		if len(found) > 0 {
			addFinding(p, "CRED", hf,
				fmt.Sprintf("History file with potential secrets (%s) — review and purge; leads, not confirmed credentials",
					strings.Join(found, ", ")),
				RiskMedium, false)
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

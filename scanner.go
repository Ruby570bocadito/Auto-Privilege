package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ================================================================
// FASE 1 — Scanner: passivo, no modifica nada
// ================================================================

var scannerOrder = []func(*AutoPrivilege){
	scanSUID, scanSudo, scanCron, scanPasswd, scanShadow, scanDocker,
	scanCapabilities, scanFileCaps, scanNFS, scanWritablePath, scanServices,
	scanKernelCVE, scanPwnKit, scanSudoVersion, scanCredentials,
}

func scanAll(p *AutoPrivilege) {
	logScanStart(p.Opts)
	for _, scanner := range scannerOrder {
		scanner(p)
		if p.Opts.Stealth {
			time.Sleep(time.Duration(100+rand.Intn(300)) * time.Millisecond)
		}
	}
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

// --- SUID ---
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

func scanSUID(p *AutoPrivilege) {
	// Common SUID paths
	paths := []string{
		"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin",
		"/usr/local/sbin", "/snap/bin", "/opt", "/usr/lib",
	}
	seen := map[string]bool{}

	for _, dir := range paths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || seen[e.Name()] {
				continue
			}
			full := filepath.Join(dir, e.Name())
			info, err := os.Lstat(full)
			if err != nil {
				continue
			}
			// SUID bit set
			if info.Mode()&os.ModeSetuid != 0 && !info.Mode().IsDir() && info.Mode().IsRegular() {
				seen[e.Name()] = true
				bin := e.Name()

				var ownerUID uint32
				if stat, ok := info.Sys().(*syscall.Stat_t); ok {
					ownerUID = stat.Uid
				}
				risk, exploitable := classifySUID(bin, ownerUID)
				if !exploitable {
					// Kept as informational intel (never printed, counted in
					// JSON) with the reason spelled out instead of a bare
					// "GTFOBins: false" — non-root-owned bins are not root
					// vectors at all.
					desc := fmt.Sprintf("SUID binary: %s (GTFOBins: false)", bin)
					if ownerUID != 0 {
						desc = fmt.Sprintf("SUID binary: %s (owner uid %d — not a root vector)", bin, ownerUID)
					}
					addFinding(p, "SUID", full, desc, RiskLow, false)
					continue
				}
				addFinding(p, "SUID", full,
					fmt.Sprintf("SUID binary: %s (GTFOBins: true)", bin),
					risk, true)
			}
		}
	}
}

// --- Sudo ---
func scanSudo(p *AutoPrivilege) {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("LOGNAME")
	}

	// sudo -n fails fast instead of prompting for a password (the old
	// `sudo -l` fallback hung forever in labs without a password).
	out, err := runCmdOut(5*time.Second, "sudo", "-n", "-l")
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
	if isInGroup(user, "sudo") || isInGroup(user, "wheel") {
		// Try passwordless sudo (timeout guard)
		out3, err3 := runCmdOut(5*time.Second, "sudo", "-n", "true")
		_ = out3
		if err3 == nil {
			addFinding(p, "SUDO", user,
				"User has passwordless sudo",
				RiskHigh, true)
		}
	}
}

func isInGroup(user, group string) bool {
	cmd := exec.Command("groups", user)
	out, err := cmd.Output()
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
			if !isWritableByCurrentUser(full) {
				continue
			}
			addFinding(p, "CRON", full,
				"Writable cron job — inject command",
				RiskHigh, true)
		}
	}

	// Check crontab -l for writable scripts referenced
	cmd := exec.Command("crontab", "-l")
	out, err := cmd.Output()
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
	if isInGroup(currentUsername(), "docker") {
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
	out, err := runCmdOut(20*time.Second, "getcap", "-r", "/usr", "/bin", "/sbin", "/opt")
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
		}
	}
}

// --- Writable PATH entries ---
func scanWritablePath(p *AutoPrivilege) {
	path := os.Getenv("PATH")
	uid := uint32(os.Getuid())

	// Standard system directories — skip unless we own them
	systemDirs := map[string]bool{
		"/usr/local/sbin": true,
		"/usr/local/bin":  true,
		"/usr/sbin":       true,
		"/usr/bin":        true,
		"/sbin":           true,
		"/bin":            true,
	}

	for _, dir := range strings.Split(path, ":") {
		if dir == "" {
			dir = "."
		}
		info, err := os.Lstat(dir)
		if err != nil {
			continue
		}
		// Skip standard system dirs unless we own them
		if systemDirs[dir] {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != uid {
				continue
			}
		}
		if info.Mode().Perm()&0200 != 0 {
			// Only flag if we don't own it
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok && stat.Uid != uid {
				addFinding(p, "PATH", dir,
					"Writable directory in PATH (owned by UID "+fmt.Sprintf("%d", stat.Uid)+") — binary planting",
					RiskHigh, true)
			}
		}
	}
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
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return perm&0002 != 0
	}
	if stat.Uid == uid && perm&0200 != 0 {
		return true
	}
	if perm&0002 != 0 {
		return true
	}
	gid := uint32(os.Getgid())
	if stat.Gid == gid && perm&0020 != 0 {
		return true
	}
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if uint32(g) == stat.Gid && perm&0020 != 0 {
			return true
		}
	}
	return false
}

// --- Writable services ---
func scanServices(p *AutoPrivilege) {
	dirs := []string{
		"/etc/systemd/system",
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			full := filepath.Join(dir, e.Name())
			info, _ := os.Lstat(full)
			if info == nil {
				continue
			}
			if isWritableByCurrentUser(full) {
				addFinding(p, "SERVICE", full,
					"Writable systemd service — hijack execution",
					RiskHigh, true)
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
	out, err := runCmdOut(5*time.Second, "uname", "-r")
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
	if out, err := runCmdOut(3*time.Second, "/usr/bin/pkexec", "--version"); err == nil {
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
	out, err := runCmdOut(3*time.Second, "sudo", "--version")
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
		info, err := os.Stat(cfg.path)
		if err != nil || info.IsDir() {
			// Directories like /etc/postgresql only matter file-by-file;
			// flagging their existence was pure noise.
			continue
		}
		if !isReadable(cfg.path) {
			continue
		}
		data, err := os.ReadFile(cfg.path)
		if err != nil {
			continue
		}
		if cfg.pattern != "" && !strings.Contains(string(data), cfg.pattern) {
			continue // only report when the credential pattern is really there
		}
		addFinding(p, "CRED", cfg.path, cfg.desc, RiskMedium, true)
	}
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

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// ================================================================
// FASE 1 — Scanner: passivo, no modifica nada
// ================================================================

func scanAll(p *AutoPrivilege) {
	scanSUID(p)
	scanSudo(p)
	scanCron(p)
	scanPasswd(p)
	scanShadow(p)
	scanDocker(p)
	scanCapabilities(p)
	scanNFS(p)
	scanWritablePath(p)
	scanServices(p)
	scanKernelCVE(p)
	scanCredentials(p)
}

func addFinding(p *AutoPrivilege, source, target, desc string, risk RiskLevel, exploitable bool) {
	p.Findings = append(p.Findings, Finding{
		Source:      source,
		Target:      target,
		Description: desc,
		Risk:        risk,
		Exploitable: exploitable,
	})
	if !p.Opts.JSON && !p.Opts.Quiet && exploitable {
		p.Print(p.Findings[len(p.Findings)-1])
	}
}

// --- SUID ---
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
				risk := RiskMedium

				_, isGTFO := getCommand(bin)
				isShell := isSuidShellBin(bin)

				if isShell {
					risk = RiskHigh
				} else if isGTFO {
					risk = RiskLow
				}

				addFinding(p, "SUID", full,
					fmt.Sprintf("SUID binary: %s (GTFOBins: %v)", bin, isGTFO || isShell),
					risk, isGTFO || isShell)
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

	// Check sudo -l
	cmd := exec.Command("sudo", "-n", "-l")
	out, err := cmd.CombinedOutput()
	if err != nil {
		cmd2 := exec.Command("sudo", "-l")
		out2, _ := cmd2.CombinedOutput()
		out = out2
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
		// Try passwordless sudo
		cmd3 := exec.Command("sudo", "-n", "true")
		if cmd3.Run() == nil {
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
	info, err := os.Lstat("/etc/passwd")
	if err != nil {
		return
	}
	if info.Mode().Perm()&0200 != 0 {
		addFinding(p, "FILE", "/etc/passwd",
			"Writable /etc/passwd — inject root user",
			RiskHigh, true)
	}
}

// --- /etc/shadow readable/writable ---
func scanShadow(p *AutoPrivilege) {
	info, err := os.Lstat("/etc/shadow")
	if err != nil {
		return
	}
	if info.Mode().Perm()&0400 != 0 {
		addFinding(p, "FILE", "/etc/shadow",
			"Readable /etc/shadow — crack root hash",
			RiskHigh, true)
	}
	if info.Mode().Perm()&0200 != 0 {
		addFinding(p, "FILE", "/etc/shadow",
			"Writable /etc/shadow — set root password",
			RiskDanger, true)
	}
}

// --- Docker ---
func scanDocker(p *AutoPrivilege) {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("LOGNAME")
	}

	// Check if current user is in docker group
	cmd := exec.Command("groups", user)
	out, err := cmd.Output()
	if err != nil {
		return
	}

	if strings.Contains(string(out), "docker") {
		addFinding(p, "DOCKER", user,
			"User in docker group — container breakout to root",
			RiskHigh, true)
	}

	// Check if docker socket is accessible
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		info, _ := os.Lstat("/var/run/docker.sock")
		if info != nil && info.Mode().Perm()&0060 != 0 {
			// Socket is readable by non-root
		}
	}
}

// --- Capabilities ---
func scanCapabilities(p *AutoPrivilege) {
	pid := os.Getpid()
	capFile := fmt.Sprintf("/proc/%d/status", pid)

	data, err := os.ReadFile(capFile)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "CapEff:") {
			eff := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			if eff != "0000000000000000" && eff != "0" {
				// Has some effective capabilities
				addFinding(p, "CAPS", eff,
					"Process has non-default capabilities",
					RiskLow, true)
			}
		}
	}

	// Check cap_sys_ptrace specifically via /proc/self/status
	if strings.Contains(string(data), "CapEff:") {
		for _, line := range lines {
			if strings.HasPrefix(line, "CapPrm:") {
				prm := strings.TrimSpace(strings.TrimPrefix(line, "CapPrm:"))
				if strings.Contains(prm, "0000001") || strings.Contains(prm, "0000002") ||
					strings.Contains(prm, "0000004") {
					addFinding(p, "CAPS", "cap_sys_ptrace",
						"SYS_PTRACE capability — can inject into other processes",
						RiskMedium, true)
				}
			}
		}
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
func scanKernelCVE(p *AutoPrivilege) {
	cmd := exec.Command("uname", "-r")
	out, err := cmd.Output()
	if err != nil {
		return
	}
	kernel := strings.TrimSpace(string(out))

	cves := []struct {
		cve       string
		pattern   string
		desc      string
		risk      RiskLevel
		exploitFn func() *ExploitResult
	}{
		{
			cve:     "CVE-2021-4034",
			pattern: "5.10.",
			desc:    "PwnKit (polkit pkexec) — local privilege escalation",
			risk:    RiskHigh,
			exploitFn: func() *ExploitResult {
				return exploitKernelCVE("CVE-2021-4034", "polkit pkexec LPE")
			},
		},
		{
			cve:     "CVE-2021-3156",
			pattern: "5.11.",
			desc:    "Baron Samedit (sudo heap overflow) — local root",
			risk:    RiskHigh,
			exploitFn: func() *ExploitResult {
				return exploitKernelCVE("CVE-2021-3156", "sudo heap overflow LPE")
			},
		},
		{
			cve:     "CVE-2022-0847",
			pattern: "5.16.",
			desc:    "PolaKit — polkit pkexec race condition",
			risk:    RiskHigh,
			exploitFn: func() *ExploitResult {
				return exploitKernelCVE("CVE-2022-0847", "polkit race condition LPE")
			},
		},
		{
			cve:     "CVE-2023-32629",
			pattern: "6.1.",
			desc:    "StackRot (glibc) — stack clash privilege escalation",
			risk:    RiskMedium,
			exploitFn: func() *ExploitResult {
				return exploitKernelCVE("CVE-2023-32629", "StackRot LPE")
			},
		},
		{
			cve:     "CVE-2024-1086",
			pattern: "6.6.",
			desc:    "Netfilter nf_tables UAF — local privilege escalation",
			risk:    RiskHigh,
			exploitFn: func() *ExploitResult {
				return exploitKernelCVE("CVE-2024-1086", "nf_tables UAF LPE")
			},
		},
		{
			cve:     "CVE-2023-2235",
			pattern: "6.2.",
			desc:    "Packet socket UAF — local privilege escalation",
			risk:    RiskHigh,
			exploitFn: func() *ExploitResult {
				return exploitKernelCVE("CVE-2023-2235", "packet socket UAF LPE")
			},
		},
	}

	for _, cve := range cves {
		if strings.Contains(kernel, cve.pattern) {
			addFinding(p, "KERNEL", cve.cve,
				fmt.Sprintf("Kernel %s vulnerable to %s — %s", kernel, cve.cve, cve.desc),
				cve.risk, true)
		}
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
		{"/etc/shadow", ":", "Shadow file readable"},
		{filepath.Join(os.Getenv("HOME"), ".mysql_history"), "", "MySQL command history"},
		{filepath.Join(os.Getenv("HOME"), ".psql_history"), "", "PostgreSQL command history"},
		{"/etc/NetworkManager/system-connections", "psk=", "WiFi passwords in NetworkManager"},
	}

	for _, cfg := range configPaths {
		if _, err := os.Stat(cfg.path); err != nil {
			continue
		}
		if isWritableByCurrentUser(cfg.path) || isReadable(cfg.path) {
			desc := cfg.desc
			if cfg.pattern != "" {
				data, err := os.ReadFile(cfg.path)
				if err == nil && strings.Contains(string(data), cfg.pattern) {
					desc += " (contains " + cfg.pattern + ")"
				}
			}
			addFinding(p, "CRED", cfg.path, desc, RiskMedium, true)
		}
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

	for _, hf := range histFiles {
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

	for _, url := range metadataURLs {
		cmd := exec.Command("curl", "-s", "-m", "3", url)
		out, err := cmd.Output()
		if err == nil && len(out) > 0 {
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
	f.Close()
	return true
}

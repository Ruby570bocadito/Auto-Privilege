package autopriv

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ================================================================
// Hardening playbook (--explain + "## Hardening plan" in markdown)
// ================================================================

// explainEntry is the remediation knowledge attached to each finding
// source. The tool already measures (scan), quantifies (score) and tracks
// (baseline diff) — this is the missing half of the loop: WHAT the finding
// means and HOW to close it. Entries are honest to the same standard as
// everything else: steps name exact commands or exact file paths, never
// vague advice, and the list covers EVERY source the tool can emit
// (guarded by TestExplainDBCoversAllSources, so a new source cannot ship
// without its playbook).
type explainEntry struct {
	What   string   // what the finding source means, one sentence
	Harden []string // concrete remediation steps, safest first
}

var explainDB = map[string]explainEntry{
	"SUID": {
		What: "Binaries with the setuid bit owned by root that GTFOBins knows how to turn into a root shell.",
		Harden: []string{
			"Remove the bit from binaries you do not need: chmod u-s /path/to/bin",
			"Audit the survivors periodically: find / -xdev -perm -4000 -type f",
			"Mount removable/multi-user trees nosuid in /etc/fstab",
		},
	},
	"SGID": {
		What: "Binaries with the setgid bit owned by the root group — grants group-level privileges, never uid 0 directly.",
		Harden: []string{
			"Drop the bit where the group privilege is not required: chmod g-s /path/to/bin",
			"Review which users belong to the owning group: getent group <gid>",
		},
	},
	"SUDO": {
		What: "sudo rules hand this user privileged commands, some without a password.",
		Harden: []string{
			"Scope the rules: replace ALL with exact binaries and arguments in visudo",
			"Remove NOPASSWD: from rules that do not strictly need it",
			"Prefer command allowlists per group instead of per-user catch-alls",
		},
	},
	"CRON": {
		What: "Root-run cron surface the current user can influence, from writable job files to wildcard-absorption candidates.",
		Harden: []string{
			"Restore ownership/permissions: chown root:root <file> && chmod 644 <file> (dirs 755)",
			"Never invoke archivers with bare * in root jobs — spell the file list",
			"Pin PATH= at the top of /etc/crontab and in the job files",
		},
	},
	"FILE": {
		What: "Critical account files (/etc/passwd, /etc/shadow) are readable or writable beyond what the system needs.",
		Harden: []string{
			"passwd must be 644 root:root; shadow 640 or 600 root:shadow (Debian) / root:root",
			"Restore in place: chown root:root /etc/passwd /etc/shadow && chmod 644 /etc/passwd && chmod 640 /etc/shadow",
			"Check what leaked while it was open: rotate any hash visible in a readable shadow",
		},
	},
	"DOCKER": {
		What: "The docker group or a writable docker socket equals root on the host by design.",
		Harden: []string{
			"Leave the docker group only to real administrators: gpasswd -d <user> docker",
			"chmod 660 /var/run/docker.sock with a dedicated group — never 666/world-writable",
			"Consider rootless Docker/Podman for non-admin workloads",
		},
	},
	"CONTAINER": {
		What: "This process runs inside a container, with breakout surfaces around it (sockets, privilege, shared namespaces).",
		Harden: []string{
			"Drop --privileged and cap_sys_admin unless a workload truly needs them",
			"Never mount the runtime socket (docker.sock, containerd.sock) into untrusted containers",
			"Use dedicated user namespaces/seccomp profiles for workloads that parse untrusted input",
		},
	},
	"CAPS": {
		What: "Process or file capabilities (cap_setuid and friends) grant privilege fragments that compose into root.",
		Harden: []string{
			"Remove file caps you did not deliberately set: setcap -r /path/to/bin",
			"Prefer targeted caps (cap_net_bind_service) over broad ones (cap_sys_admin)",
			"Hunt the sources: getcap -r / 2>/dev/null",
		},
	},
	"NFS": {
		What: "NFS exports configured in a way that hands ownership or write access to untrusted clients.",
		Harden: []string{
			"Remove no_root_squash unless a specific host genuinely needs it",
			"Pin every export to explicit hosts or networks: /srv 10.0.0.0/24(rw,sync) — never *",
			"Re-export after changes: exportfs -ra",
		},
	},
	"PATH": {
		What: "A directory in the executable search path is writable by the current user — binary planting bait.",
		Harden: []string{
			"Restore the directory owner and mode: chown root:root <dir> && chmod 755 <dir>",
			"Never leave writable directories ahead of system paths in PATH",
			"Audit planted files before cleaning: ls -la <dir>",
		},
	},
	"SERVICE": {
		What: "Service definitions the current user can modify — code executes at boot, restart or timer fire.",
		Harden: []string{
			"Restore ownership/mode: chown root:root <unit> && chmod 644 <unit> (init.d scripts 755)",
			"Review the unit's ExecStart for planted payloads BEFORE trusting the service again",
			"systemctl daemon-reload after any edit; audit for unexpected timers",
		},
	},
	"KERNEL": {
		What: "Kernel/sudo/pkexec version heuristics matched a known-exploitation window.",
		Harden: []string{
			"Patch first: the heuristics say verify, the vendor advisory decides",
			"until patched: restrict local shell access — these are local privilege escalations",
			"Re-scan after update; matches disappear when the version leaves the window",
		},
	},
	"CRED": {
		What: "Credentials or secret traces reachable by the current user: history lines, config passwords, cloud metadata, private keys.",
		Harden: []string{
			"Rotate anything found — treat every hit as already-compromised",
			"Purge secrets from history: history -c && rm ~/.bash_history (and stop storing them)",
			"Move config credentials into a secrets manager or root-readable-only files (600)",
			"On cloud hosts, enforce IMDSv2 / metadata token requirements",
		},
	},
	"PRELOAD": {
		What: "Dynamic-loader surfaces: ld.so.preload entries execute with euid 0 in every SUID binary; a writable ld.so.conf(.d) redirects the library search path for the whole system.",
		Harden: []string{
			"Restore the preload file: chown root:root /etc/ld.so.preload && chmod 644 /etc/ld.so.preload (empty file is valid)",
			"Review every entry before deleting — a legit acceleration lib can hide next to a rootkit",
			"ld.so.conf(.d): chown root:root && chmod 644 (dir 755), then rebuild the cache: ldconfig",
		},
	},
	"SUDOERS": {
		What: "The sudoers configuration is writable beyond visudo's own path — a one-line rule away from passwordless root.",
		Harden: []string{
			"Restore: chown root:root /etc/sudoers /etc/sudoers.d && chmod 440 /etc/sudoers && chmod 755 /etc/sudoers.d",
			"Drop-ins inside must be root:root 0440 — anything else is ignored or dangerous",
			"Validate after any change: visudo -c",
		},
	},
	"GROUP": {
		What: "The group database is writable by the current user — self-service membership in sudo/wheel/docker.",
		Harden: []string{
			"Restore: chown root:root /etc/group && chmod 644 /etc/group",
			"Audit memberships for lines you did not create: getent group sudo wheel docker",
			"Prefer gpasswd/usermod for group changes — never hand-edit with world-writable files",
		},
	},
	"HOOKS": {
		What: "Login-time execution surfaces are writable: code inside them runs in every future shell — root's included.",
		Harden: []string{
			"Restore each surface: chown root:root <path> && chmod 644 <file> (profile.d dir 755)",
			"/etc/environment: review line by line before cleaning — LD_PRELOAD there is a classic rootkit door",
			"Audit /etc/profile.d for scripts you cannot attribute; delete orphans after inspection",
		},
	},
	"POLKIT": {
		What: "polkit policy surfaces are writable: a rule granting this user org.freedesktop.policykit.exec turns every pkexec into a passwordless root shell.",
		Harden: []string{
			"Restore: chown root:root /etc/polkit-1/rules.d && chmod 755 /etc/polkit-1/rules.d (rule files 644)",
			"Review every .rules file line by line before cleaning — a legit accessibility rule can hide next to a grant",
			"Audit who can write localauthority dirs: chown root:root && chmod 755 /etc/polkit-1/localauthority/*",
			"Monitor polkitd logs after cleanup — reloads of rules you did not make are incident signals",
		},
	},
	"WINOS": {
		What: "the Windows build banner the scan started from — informational context for every other WIN* finding.",
		Harden: []string{
			"Track patch level: the build number maps to a cumulative update — hosts behind on CU carry public exploits",
			"Compare against the EOL list: unsupported builds have no patches, only mitigations",
		},
	},
	"WINPRIV": {
		What: "the process token holds privileges that are direct escalation primitives (SeImpersonate → potato family, SeBackup → hash dumping, SeDebug → lsass access).",
		Harden: []string{
			"Remove the privilege from the account: secpol.msc → Local Policies → User Rights Assignment",
			"Service accounts must never hold SeImpersonate without a documented need — it is the potato prerequisite",
			"gpo / secedit export the current assignment so the fix survives a group policy refresh",
		},
	},
	"WINREG": {
		What: "registry misconfigurations that hand out SYSTEM (AlwaysInstallElevated) or plaintext credentials (AutoLogon).",
		Harden: []string{
			"AlwaysInstallElevated: delete the policy value in BOTH hives (HKLM+HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer)",
			"AutoLogon: remove DefaultPassword and switch to autologon via credential guard or drop autologon entirely",
			"EnableLUA must stay 1 — UAC off turns every admin click into a silent elevation",
		},
	},
	"WINSVC": {
		What: "Windows services expose binary-planting surfaces: unquoted paths with spaces, binaries in user-writable directories, SYSTEM services running user-profile binaries.",
		Harden: []string{
			"Quote every service PathName: sc qc <name> to review, sc config <name> binPath= \"…\" to fix",
			"ACL the writable directories: icacls <dir> /inheritance:r /grant:r Administrators:F SYSTEM:F — user-writable system dirs are the bug",
			"Move misplaced service binaries out of user profiles into Program Files",
		},
	},
	"WINAUTO": {
		What: "autorun keys (Run/RunOnce) point at binaries the current user can rewrite — the payload executes at every logon, admins included.",
		Harden: []string{
			"Delete the orphaned autorun entries you cannot attribute",
			"Point the survivors at binaries under Program Files with SYSTEM/Administrator-only write ACLs",
			"Autoruns (Sysinternals) shows the full picture including Wow6432Node variants — audit with it periodically",
		},
	},
	"WINTASK": {
		What: "scheduled tasks execute user-writable commands (or run privileged binaries from user profiles) — the schedule IS the persistence trigger.",
		Harden: []string{
			"Move task scripts to SYSTEM-only directories and quote paths in the action",
			"Audit task principals: a SYSTEM task whose script a standard user can edit is an open door",
			"Export the task list for diffing: schtasks /query /fo csv > tasks-baseline.csv",
		},
	},
	"WINCRED": {
		What: "credential artifacts reachable by the current user: unattend/sysprep passwords, GPP cpassword, PowerShell history, cloud and SSH key material.",
		Harden: []string{
			"Delete the answer files from deployed images (unattend.xml/sysprep.xml are install-time only, not run-time)",
			"GPP passwords: MS14-025 — remove the cpassword entries; the encryption key is public and forever",
			"Rotate every credential the history/keys touched before deleting the artifacts — exposure is already done",
		},
	},
	"WINPATH": {
		What: "a writable directory sits in PATH — the next binary/DLL a privileged process resolves from it is hijackable.",
		Harden: []string{
			"Strip user-writable entries from the SYSTEM Path (sysdm.cpl → Environment Variables)",
			"ACL the directories that must stay: icacls <dir> /inheritance:r /grant:r Administrators:F SYSTEM:F",
			"User PATH belongs to the user profile — system-wide entries must never resolve there",
		},
	},
}

// validSources is the canonical list of finding sources the tool emits —
// the vocabulary --ignore validates against and --explain must cover.
var validSources = []string{
	"SUID", "SGID", "SUDO", "CRON", "FILE", "DOCKER", "CONTAINER", "CAPS",
	"NFS", "PATH", "SERVICE", "KERNEL", "CRED", "PRELOAD", "SUDOERS",
	"GROUP", "HOOKS", "POLKIT",
	// Windows sources (v1.9) — emitted by windows_scan.go on Windows.
	"WINOS", "WINPRIV", "WINREG", "WINSVC", "WINAUTO", "WINTASK", "WINCRED", "WINPATH",
}

func isValidSource(s string) bool {
	for _, v := range validSources {
		if v == s {
			return true
		}
	}
	return false
}

// printExplain renders the playbook for ONE source or every source
// (argument "all"). Unknown sources are a usage error (fail-fast, exit 2
// at the caller) — the playbook never invents advice for a source it does
// not know.
func printExplain(source string) error {
	if strings.EqualFold(source, "all") {
		sources := append([]string{}, validSources...)
		sort.Strings(sources)
		for _, s := range sources {
			printOneExplain(s)
		}
		return nil
	}
	src := strings.ToUpper(strings.TrimSpace(source))
	if !isValidSource(src) {
		return fmt.Errorf("unknown source %q (valid: %s,all)", source, strings.Join(validSources, ","))
	}
	printOneExplain(src)
	return nil
}

func printOneExplain(source string) {
	e, ok := explainDB[source]
	if !ok {
		// Defensive: validation upstream guarantees presence, but the
		// printer must stay honest if the DB and the source list diverge.
		fmt.Printf("  %s → no playbook entry yet (report it)\n", source)
		return
	}
	fmt.Printf("\n  %s — %s\n", colorize(source, AnsiBold), e.What)
	for _, step := range e.Harden {
		fmt.Printf("    %s %s\n", colorize("→", AnsiGrey), step)
	}
}

// hardeningPlan renders the "## Hardening plan" markdown section from the
// sources ACTUALLY present in the findings, in first-appearance order —
// deterministic by construction, never map iteration, and empty-safe (no
// findings → no section). This is the same knowledge printExplain serves,
// embedded in the evidence report so the engagement appendix carries its
// own remediation checklist.
func hardeningPlan(findings []Finding) string {
	seen := map[string]bool{}
	var order []string
	for _, f := range findings {
		if seen[f.Source] {
			continue
		}
		if _, ok := explainDB[f.Source]; !ok {
			continue
		}
		seen[f.Source] = true
		order = append(order, f.Source)
	}
	if len(order) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n## Hardening plan\n\n")
	b.WriteString("One playbook per detected source, steps safest first. Rotate any secret surfaced by CRED findings before anything else.\n")
	for _, s := range order {
		e := explainDB[s]
		fmt.Fprintf(&b, "\n### %s\n\n%s\n\n", s, e.What)
		for _, step := range e.Harden {
			fmt.Fprintf(&b, "- %s\n", step)
		}
	}
	return b.String()
}

// parseIgnore validates a --ignore list: comma-separated source names,
// case-insensitive, deduplicated, order-preserving. Unknown names are a
// usage error (fail-fast before any scan) — silently ignoring a typo'd
// source would silently ignore nothing.
func parseIgnore(s string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(s, ",") {
		name := strings.ToUpper(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		if !isValidSource(name) {
			return nil, fmt.Errorf("unknown --ignore source %q (valid: %s)", name, strings.Join(validSources, ","))
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, errors.New("empty --ignore list (valid: " + strings.Join(validSources, ",") + ")")
	}
	return out, nil
}

// filterIgnored drops findings whose Source was explicitly excluded. The
// filter runs ONCE, right after the scan, so every downstream consumer
// (terminal, JSON, markdown, SARIF, score, policy gate, baseline diff,
// enumeration) sees the exact same filtered reality — no per-consumer
// special cases to drift apart.
func filterIgnored(findings []Finding, ignored []string) []Finding {
	if len(ignored) == 0 {
		return findings
	}
	drop := map[string]bool{}
	for _, s := range ignored {
		drop[s] = true
	}
	out := findings[:0:0]
	for _, f := range findings {
		if !drop[f.Source] {
			out = append(out, f)
		}
	}
	return out
}

// parseMinRisk validates the --min-risk value: the risk floor below which
// findings stop existing for the rest of the run. "safe" is rejected on
// purpose — a safe floor would show everything (the default), so accepting
// it would only give operators a flag that silently does nothing. Same
// fail-fast contract as parseFailOn: a typo costs an exit 2 before the
// scan, never a wasted run that hides nothing.
func parseMinRisk(s string) (RiskLevel, error) {
	switch strings.ToLower(s) {
	case "low":
		return RiskLow, nil
	case "medium":
		return RiskMedium, nil
	case "high":
		return RiskHigh, nil
	case "danger":
		return RiskDanger, nil
	case "safe":
		return RiskSafe, errors.New(`invalid --min-risk "safe": the default already shows every finding — use low as the floor`)
	}
	return RiskSafe, fmt.Errorf("invalid --min-risk %q (valid: low, medium, high, danger)", s)
}

// filterMinRisk drops findings strictly BELOW the risk floor (the floor is
// inclusive: --min-risk medium keeps MEDIUM and above). It runs ONCE, right
// after filterIgnored, under the same filtered-reality contract: every
// downstream consumer — terminal, JSON, markdown, SARIF, hardening score,
// all three CI gates, baseline diff, enumeration — sees the identical
// filtered set. Order-preserving and empty-safe: the survivors keep the
// scannerOrder sequence the parallel merge guarantees.
func filterMinRisk(findings []Finding, floor RiskLevel) []Finding {
	if floor <= RiskSafe {
		return findings
	}
	out := findings[:0:0]
	for _, f := range findings {
		if f.Risk >= floor {
			out = append(out, f)
		}
	}
	return out
}

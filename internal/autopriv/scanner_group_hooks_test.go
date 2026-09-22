package autopriv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ================================================================
// Scanners GROUP + HOOKS, sudoers.d per-file, NFS
// hostless exports, cron wildcard candidates, and their wiring.
// ================================================================

// --- scanGroup ---

func TestScanGroupWritable(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	group := filepath.Join(dir, "group")
	if err := os.WriteFile(group, []byte("root:x:0:\n"), 0666); err != nil {
		t.Fatal(err)
	}

	orig := groupPath
	defer func() { groupPath = orig }()
	groupPath = group

	p := &AutoPrivilege{Opts: Options{}}
	scanGroup(p)

	if len(p.Findings) != 1 {
		t.Fatalf("writable /etc/group must yield exactly one finding, got %v", p.Findings)
	}
	f := p.Findings[0]
	if f.Source != "GROUP" || f.Risk != RiskHigh || !f.Exploitable {
		t.Errorf("writable group must be GROUP/HIGH/exploitable, got %+v", f)
	}
	if !strings.Contains(f.Description, "sudo") {
		t.Errorf("description must name the privilege groups, got %q", f.Description)
	}
}

func TestScanGroupHonestSilence(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	group := filepath.Join(dir, "group")
	if err := os.WriteFile(group, []byte("root:x:0:\n"), 0444); err != nil {
		t.Fatal(err)
	}

	orig := groupPath
	defer func() { groupPath = orig }()
	groupPath = group

	p := &AutoPrivilege{Opts: Options{}}
	scanGroup(p)
	if len(p.Findings) != 0 {
		t.Errorf("read-only group must stay silent, got %v", p.Findings)
	}

	// Missing file: silence too.
	groupPath = filepath.Join(dir, "missing")
	p2 := &AutoPrivilege{Opts: Options{}}
	scanGroup(p2)
	if len(p2.Findings) != 0 {
		t.Errorf("missing group must stay silent, got %v", p2.Findings)
	}
}

// --- scanLoginHooks ---

func TestScanLoginHooksWritable(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	environment := filepath.Join(dir, "environment")
	profileD := filepath.Join(dir, "profile.d")
	profile := filepath.Join(dir, "profile")
	bashrc := filepath.Join(dir, "bash.bashrc")

	if err := os.WriteFile(environment, []byte("LANG=en_US.UTF-8\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(profileD, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, []byte("#!/bin/sh\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bashrc, []byte("# rc\n"), 0444); err != nil { // read-only: silent
		t.Fatal(err)
	}

	orig := loginHookPaths
	defer func() { loginHookPaths = orig }()
	loginHookPaths = struct {
		environment string
		profileD    string
		profile     string
		bashrc      string
	}{environment: environment, profileD: profileD, profile: profile, bashrc: bashrc}

	p := &AutoPrivilege{Opts: Options{}}
	scanLoginHooks(p)

	if len(p.Findings) != 3 {
		t.Fatalf("writable environment+profile.d+profile must yield 3 findings, got %v", p.Findings)
	}
	for _, f := range p.Findings {
		if f.Source != "HOOKS" || f.Risk != RiskHigh || !f.Exploitable {
			t.Errorf("writable hooks must be HOOKS/HIGH/exploitable, got %+v", f)
		}
	}
	// The environment target names LD_PRELOAD — the technique that makes it
	// sharper than a shell rc (process-wide, non-shell logins included).
	env := p.Findings[0]
	if env.Target != environment || !strings.Contains(env.Description, "LD_PRELOAD") {
		t.Errorf("environment finding must name LD_PRELOAD, got %+v", env)
	}
}

func TestScanLoginHooksHonestSilence(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	orig := loginHookPaths
	defer func() { loginHookPaths = orig }()
	// All four locations missing → zero findings (honest absence).
	loginHookPaths = struct {
		environment string
		profileD    string
		profile     string
		bashrc      string
	}{
		environment: filepath.Join(dir, "missing-env"),
		profileD:    filepath.Join(dir, "missing-profiled"),
		profile:     filepath.Join(dir, "missing-profile"),
		bashrc:      filepath.Join(dir, "missing-bashrc"),
	}
	p := &AutoPrivilege{Opts: Options{}}
	scanLoginHooks(p)
	if len(p.Findings) != 0 {
		t.Errorf("missing hooks must produce zero findings, got %v", p.Findings)
	}

	// Shape mismatch: a profile.d that is a FILE, not a directory, is not
	// reported by the directory probe (honesty over guessing).
	mismatch := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(mismatch, []byte("x"), 0666); err != nil {
		t.Fatal(err)
	}
	loginHookPaths.profileD = mismatch
	p2 := &AutoPrivilege{Opts: Options{}}
	scanLoginHooks(p2)
	for _, f := range p2.Findings {
		if f.Target == mismatch {
			t.Errorf("directory probe must stay silent on a shape-mismatched target, got %v", f)
		}
	}
}

// --- scanSudoersDropins (per-file pass when the directory is locked) ---

func TestScanSudoersDropinsSilentOnUserOwnedFiles(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	sudoersDir := filepath.Join(dir, "sudoers.d")
	if err := os.Mkdir(sudoersDir, 0755); err != nil {
		t.Fatal(err)
	}
	// A file WE own that sudo would ignore (uid != 0): world-writable, but
	// the scanner must stay silent — flagging user-owned drop-ins is noise.
	mine := filepath.Join(sudoersDir, "mine.conf")
	if err := os.WriteFile(mine, []byte("junk\n"), 0666); err != nil {
		t.Fatal(err)
	}

	p := &AutoPrivilege{Opts: Options{}}
	scanSudoersDropins(p, sudoersDir)
	for _, f := range p.Findings {
		if f.Target == mine {
			t.Errorf("user-owned drop-in must stay silent (sudo ignores it), got %v", f)
		}
	}

	// Root-owned files are the honest positive branch — only testable where
	// chown to root is permitted (euid 0).
	if os.Geteuid() == 0 {
		rootOwned := filepath.Join(sudoersDir, "rooted.conf")
		if err := os.WriteFile(rootOwned, []byte("junk\n"), 0666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(rootOwned, 0, 0); err != nil {
			t.Fatal(err)
		}
		p2 := &AutoPrivilege{Opts: Options{}}
		scanSudoersDropins(p2, sudoersDir)
		found := false
		for _, f := range p2.Findings {
			if f.Target == rootOwned {
				found = true
				if f.Risk != RiskMedium || f.Exploitable {
					t.Errorf("root-owned writable drop-in must be MEDIUM/informational, got %+v", f)
				}
				if !strings.Contains(f.Description, "visudo") {
					t.Errorf("description must name the verification step, got %q", f.Description)
				}
			}
		}
		if !found {
			t.Errorf("root-owned writable drop-in must be reported, got %v", p2.Findings)
		}
	}
}

// --- scanPreloadPaths: the drop-in pass only runs when the DIR is locked ---

func TestScanPreloadPathsDropinPassGatedOnDirLock(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	sudoersDir := filepath.Join(dir, "sudoers.d")
	if err := os.Mkdir(sudoersDir, 0777); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(sudoersDir, "mine.conf")
	if err := os.WriteFile(mine, []byte("junk\n"), 0666); err != nil {
		t.Fatal(err)
	}

	// Writable DIRECTORY: the dir finding covers it — no per-file duplication.
	p := &AutoPrivilege{Opts: Options{}}
	scanPreloadPaths(p, filepath.Join(dir, "missing-preload"), filepath.Join(dir, "missing-sudoers"), sudoersDir)
	perFile := 0
	for _, f := range p.Findings {
		if f.Target == mine {
			perFile++
		}
	}
	if perFile != 0 {
		t.Errorf("writable dir must suppress the per-file pass (no duplicate findings), got %d", perFile)
	}
	if len(p.Findings) != 1 {
		t.Errorf("writable dir must yield exactly the dir finding, got %v", p.Findings)
	}
}

// --- nfsExportHostless ---

func TestNFSExportHostless(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"/srv *(rw,sync,no_subtree_check)", true},         // wildcard host + rw
		{"/data (rw,sync)", true},                          // empty host = world
		{"/exports *(ro,all_squash)", false},               // ro is not rw
		{"/exports host1(rw,sync)", false},                 // host-qualified
		{"/exports *.corp.example.com(rw,sync)", false},    // domain-qualified
		{"/exports 10.0.0.0/24(rw,no_root_squash)", false}, // network-qualified
		{"/srv *(sync)", false},                            // no rw at all
		{"/onlypath", false},                               // clientless line
	}
	for _, c := range cases {
		if got := nfsExportHostless(c.line); got != c.want {
			t.Errorf("nfsExportHostless(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestScanNFSReportsBothFindings(t *testing.T) {
	// no_root_squash wins (HIGH exploitable); the hostless-rw line below it
	// is the informational sibling (MEDIUM, not exploitable).
	p := &AutoPrivilege{Opts: Options{}}
	high := "/exports 10.0.0.0/24(rw,no_root_squash)"
	if got := nfsExportHostless(high); got {
		t.Errorf("no_root_squash line must not double-report as hostless: %v", got)
	}
	addFinding(p, "NFS", high, "NFS export with no_root_squash — mount and own files as root", RiskHigh, true)
	if p.Findings[0].Risk != RiskHigh || !p.Findings[0].Exploitable {
		t.Errorf("no_root_squash stays HIGH/exploitable, got %+v", p.Findings[0])
	}
}

// --- cronWildcardLine ---

func TestCronWildcardLine(t *testing.T) {
	cases := []struct {
		line string
		bin  string
		want bool
	}{
		// /etc/cron.d shape (5 schedule fields + command)
		{"0 3 * * * tar -czf /backup.tgz /var/www/*", "tar", true},
		{"0 2 * * * rsync -a /srv/* backup@host:/srv/", "rsync", true},
		{"30 1 * * * cd /var/www && zip -r /tmp/site.zip *", "zip", true},
		// cron.daily shape (bare command)
		{"7z a /tmp/archive.7z /data/*", "7z", true},
		// Negative: wildcards but no prone binary
		{"0 3 * * * find /var/www -name '*.log' -delete", "", false},
		{"tar -cf /tmp/x.tar /etc", "", false}, // tar WITHOUT wildcard args
		{"ls -la *", "", false},                // not a prone binary
		{"", "", false},
		// NOTE: comment lines are NOT part of this contract — the caller
		// (scanCronWildcards) strips comments/blanks before calling.
	}
	for _, c := range cases {
		bin, ok := cronWildcardLine(c.line)
		if ok != c.want || bin != c.bin {
			t.Errorf("cronWildcardLine(%q) = (%q,%v), want (%q,%v)", c.line, bin, ok, c.bin, c.want)
		}
	}
}

// --- wiring: group + hooks enumerations ---

func TestEnumerateGroupManualVector(t *testing.T) {
	p := &AutoPrivilege{Opts: Options{}}
	p.Findings = []Finding{{Source: "GROUP", Target: "/etc/group", Risk: RiskHigh, Exploitable: true}}
	enumerateAll(p)
	if len(p.Vectors) != 1 {
		t.Fatalf("writable GROUP must yield exactly one vector, got %+v", p.Vectors)
	}
	v := p.Vectors[0]
	if v.Category != "group" || v.Exploit != nil {
		t.Errorf("group vector must be manual with category group, got %+v", v)
	}
	if !strings.Contains(v.Command, currentUsername()) {
		t.Errorf("command must append the CURRENT user, got %q", v.Command)
	}
	if !strings.Contains(v.Command, "log out") {
		t.Errorf("command must state the re-login requirement, got %q", v.Command)
	}
}

func TestEnumerateHooksVectors(t *testing.T) {
	orig := loginHookPaths
	defer func() { loginHookPaths = orig }()
	dir := t.TempDir()
	profileD := filepath.Join(dir, "profile.d")
	if err := os.Mkdir(profileD, 0755); err != nil {
		t.Fatal(err)
	}
	loginHookPaths = struct {
		environment string
		profileD    string
		profile     string
		bashrc      string
	}{environment: filepath.Join(dir, "environment"), profileD: profileD,
		profile: filepath.Join(dir, "profile"), bashrc: filepath.Join(dir, "bash.bashrc")}

	p := &AutoPrivilege{Opts: Options{}}
	p.Findings = []Finding{
		{Source: "HOOKS", Target: loginHookPaths.environment, Risk: RiskHigh, Exploitable: true},
		{Source: "HOOKS", Target: profileD, Risk: RiskHigh, Exploitable: true},
	}
	enumerateAll(p)
	if len(p.Vectors) != 2 {
		t.Fatalf("both HOOKS findings must yield vectors, got %+v", p.Vectors)
	}
	for _, v := range p.Vectors {
		if v.Category != "hooks" || v.Exploit != nil {
			t.Errorf("hooks vectors must be manual with category hooks, got %+v", v)
		}
	}
	if !strings.Contains(p.Vectors[0].Command, "LD_PRELOAD") {
		t.Errorf("environment vector must use LD_PRELOAD, got %q", p.Vectors[0].Command)
	}
	// The directory target gets a concrete file path in its command —
	// ">> /dir" would be a broken paste; ">> /dir/autopriv.sh" is real.
	if !strings.Contains(p.Vectors[1].Command, filepath.Join(profileD, "autopriv.sh")) {
		t.Errorf("directory hook vector must name the concrete file, got %q", p.Vectors[1].Command)
	}
}

// --- --vector accepts the new names (parseVectorList contract) ---

func TestParseVectorListAcceptsGroupAndHooks(t *testing.T) {
	names, err := parseVectorList("group,hooks")
	if err != nil {
		t.Fatalf("group,hooks must be valid --vector values: %v", err)
	}
	if len(names) != 2 || names[0] != "group" || names[1] != "hooks" {
		t.Errorf("parseVectorList order wrong: %v", names)
	}
	// "all" must expand to include both.
	all, err := parseVectorList("all")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, n := range all {
		seen[n] = true
	}
	if !seen["group"] || !seen["hooks"] {
		t.Errorf("--vector all must include group and hooks: %v", all)
	}
}

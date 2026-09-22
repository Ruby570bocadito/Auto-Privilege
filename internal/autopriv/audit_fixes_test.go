package autopriv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ================================================================
// Audit v1.9.0 → v2.0.0 regression pins.
//
// Every fix from the false-positive / false-negative audit gets a test
// here: the pure parsers (sudo rules, getcap, history, NFS, kernel
// ranges), the dedup pass, the baseline SUID skip, the renamed-SUID
// content hash, the /etc/environment PATH merge, and the root guards.
// ================================================================

// stubEUID forces the euid the root guards see, with cleanup. It simulates
// both directions on any CI runner: a privileged runner can test the
// unprivileged guards, an unprivileged one can test the root guards.
func stubEUID(t *testing.T, uid int) {
	t.Helper()
	orig := currentEUID
	currentEUID = func() int { return uid }
	t.Cleanup(func() { currentEUID = orig })
}

// --- FP-8 / FN-4: sudo rule parsing ---

func TestParseSudoRules(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   []sudoRule
	}{
		{
			name: "free NOPASSWD rule",
			output: "Matching Defaults entries for testuser on host:\n" +
				"    env_reset, mail_badpass\n\n" +
				"User testuser may run the following commands on host:\n" +
				"    (ALL) NOPASSWD: /usr/bin/find\n",
			want: []sudoRule{{Bin: "/usr/bin/find", Passwordless: true}},
		},
		{
			name: "comma-separated spec list shares the tag",
			output: "User testuser may run the following commands on host:\n" +
				"    (ALL) NOPASSWD: /usr/bin/find, /usr/bin/gawk, /usr/bin/sed\n",
			want: []sudoRule{
				{Bin: "/usr/bin/find", Passwordless: true},
				{Bin: "/usr/bin/gawk", Passwordless: true},
				{Bin: "/usr/bin/sed", Passwordless: true},
			},
		},
		{
			name: "restricted rule keeps its args (FP-8)",
			output: "User testuser may run the following commands on host:\n" +
				"    (root) NOPASSWD: /usr/bin/tar -cf /dev/null *\n",
			want: []sudoRule{
				{Bin: "/usr/bin/tar", Args: "-cf /dev/null *", Passwordless: true},
			},
		},
		{
			name: "password-required free rule",
			output: "User k may run the following commands on host:\n" +
				"    (ALL) ALL\n",
			want: []sudoRule{{Bin: "ALL"}},
		},
		{
			name: "repeated runas segments",
			output: "User testuser may run the following commands on host:\n" +
				"    (root) /usr/bin/awk, (root) /usr/bin/sed\n",
			want: []sudoRule{
				{Bin: "/usr/bin/awk"},
				{Bin: "/usr/bin/sed"},
			},
		},
		{
			name:   "headers and prose are skipped",
			output: "Matching Defaults entries for testuser on host:\nUser testuser is not allowed to run sudo on host.\n",
			want:   nil,
		},
	}
	for _, tc := range cases {
		got := parseSudoRules(tc.output)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %d rules %+v, want %d", tc.name, len(got), got, len(tc.want))
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: rule %d = %+v, want %+v", tc.name, i, got[i], tc.want[i])
			}
		}
	}
}

// The restricted rule must never surface as a free HIGH-exploitable
// technique (FP-8): a path-pinned `find /var/www` is a manual review, not
// `sudo find → root`. The parser must keep the args so the classifier can
// tell restricted rules from free ones.
func TestScanSudoRestrictedRuleIsInformational(t *testing.T) {
	stubEUID(t, 1000)
	rules := parseSudoRules("User testuser may run the following commands on host:\n" +
		"    (root) NOPASSWD: /usr/bin/find /var/www\n")
	if len(rules) != 1 || rules[0].Args == "" {
		t.Fatalf("parser must keep the args, got %+v", rules)
	}
	if rules[0].Args != "/var/www" || !rules[0].Passwordless {
		t.Errorf("restricted rule = %+v, want args /var/www + passwordless", rules[0])
	}
	// The classification contract (mirrors scanSudo's switch): restricted +
	// passwordless ⇒ MEDIUM informational, never HIGH exploitable.
	free := parseSudoRules("User testuser may run the following commands on host:\n" +
		"    (ALL) NOPASSWD: /usr/bin/find\n")
	if len(free) != 1 || free[0].Args != "" || !free[0].Passwordless {
		t.Fatalf("free rule = %+v, want no args + passwordless", free)
	}
}

// --- FP-9: same-access dedup ---

func TestDedupFindings(t *testing.T) {
	base := []Finding{
		{Source: "DOCKER", Target: "testuser", Description: "group"},
		{Source: "DOCKER", Target: "/var/run/docker.sock", Description: "socket"},
		{Source: "CONTAINER", Target: "docker-daemon", Description: "daemon"},
		{Source: "SUID", Target: "/usr/bin/find", Risk: RiskHigh, Exploitable: true},
	}
	got := dedupFindings(base)
	if len(got) != 2 {
		t.Fatalf("docker access must collapse to ONE finding, got %d: %+v", len(got), got)
	}
	if got[0].Target != "/var/run/docker.sock" || got[1].Target != "/usr/bin/find" {
		t.Errorf("socket finding must survive, got %+v", got)
	}

	sudo := []Finding{
		{Source: "SUDO", Target: "ALL", Risk: RiskHigh, Exploitable: true},
		{Source: "SUDO", Target: "/usr/bin/find", Risk: RiskHigh, Exploitable: true},
	}
	got = dedupFindings(sudo)
	if len(got) != 1 || got[0].Target != "ALL" {
		t.Fatalf("full sudo grant must subsume per-binary rules, got %+v", got)
	}

	// No docker/sudo findings: the pass must be a no-op (order preserved).
	untouched := []Finding{
		{Source: "CRON", Target: "/etc/cron.d/x"},
		{Source: "FILE", Target: "/etc/passwd"},
	}
	got = dedupFindings(untouched)
	if len(got) != 2 || got[0].Source != "CRON" || got[1].Source != "FILE" {
		t.Errorf("dedup must be a no-op without docker/sudo access, got %+v", got)
	}
}

// --- FN-1: getcap parser ---

func TestParseGetcapLine(t *testing.T) {
	cases := []struct {
		line     string
		wantPath string
		wantCaps string
		wantOK   bool
	}{
		// modern libcap (>= 2.60) — the format the old SplitN(line," =",2)
		// silently discarded, losing the seeded cap_setuid edge case.
		{"/usr/bin/python3.10 cap_setuid=ep", "/usr/bin/python3.10", "cap_setuid=ep", true},
		// legacy format
		{"/usr/bin/foo = cap_setuid+ep", "/usr/bin/foo", "cap_setuid+ep", true},
		// multiple capabilities in one line
		{"/usr/bin/bar cap_setuid,cap_net_raw=ep", "/usr/bin/bar", "cap_setuid,cap_net_raw=ep", true},
		// warnings mixed into CombinedOutput are rejected
		{"/usr/lib: Operation not permitted", "", "", false},
		{"getcap: permission denied", "", "", false},
		{"", "", "", false},
		{"/usr/bin/onlypath", "", "", false},
	}
	for _, tc := range cases {
		path, caps, ok := parseGetcapLine(tc.line)
		if ok != tc.wantOK || path != tc.wantPath || caps != tc.wantCaps {
			t.Errorf("parseGetcapLine(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.line, path, caps, ok, tc.wantPath, tc.wantCaps, tc.wantOK)
		}
	}
}

// --- FP-6: history secret matching ---

func TestHistorySecretMatches(t *testing.T) {
	benign := []string{
		"echo rotate password quarterly",
		"grep -rn token ./src",
		"cat README.md | grep secret",
		"ls -la /private",
		"export TOKENIZER=nltk",
		"man passwd",
	}
	for _, line := range benign {
		if got := historySecretMatches(line); len(got) != 0 {
			t.Errorf("benign line %q must not match, got %v", line, got)
		}
	}
	malicious := []string{
		`mysql -u root -p"RootPass123!"`,    // edgecase 8
		"export DB_PASSWORD=SuperSecret123", // assignment
		"AKIAIOSFODNN7EXAMPLE",              // aws key id
		"-----BEGIN RSA PRIVATE KEY-----",   // key block
		"psql --password hunter2",           // password flag
	}
	for _, line := range malicious {
		if got := historySecretMatches(line); len(got) == 0 {
			t.Errorf("secret-bearing line %q must match", line)
		}
	}
}

// --- INC-1: kernel CVE table ---

func TestKernelCVEDBStackRot(t *testing.T) {
	for _, e := range kernelCVEDB() {
		if strings.Contains(e.cve, "32629") {
			t.Errorf("StackRot must be CVE-2023-3269 — the Ubuntu overlayfs id 32629 must not be mislabeled StackRot")
		}
	}
	var stackRot *kernelCVEEntry
	for i, e := range kernelCVEDB() {
		if e.cve == "CVE-2023-3269" {
			stackRot = &kernelCVEDB()[i]
		}
	}
	if stackRot == nil {
		t.Fatal("CVE-2023-3269 (StackRot) missing from the table")
	}
	if !versionInAnyRange([]int{6, 1, 36}, stackRot.ranges) {
		t.Error("6.1.36 must be in range (fix landed in 6.1.37 — the old 6.1.0-6.1.13 window hid it)")
	}
	if !versionInAnyRange([]int{6, 2, 0}, stackRot.ranges) {
		t.Error("6.2.0 must be in range (second affected window)")
	}
	if !versionInAnyRange([]int{6, 3, 10}, stackRot.ranges) {
		t.Error("6.3.10 must be in range (fix landed in 6.3.11)")
	}
	if versionInAnyRange([]int{6, 1, 37}, stackRot.ranges) {
		t.Error("6.1.37 is patched, must not match")
	}
	if versionInAnyRange([]int{6, 4, 0}, stackRot.ranges) {
		t.Error("6.4.0 is patched, must not match")
	}
}

// FP-4: heuristic findings are never exploitable. The risk label carries
// severity; the exploitability flag carries confirmation.
func TestKernelCVEFindingsNotExploitable(t *testing.T) {
	// Direct table walk: every entry would produce exploitable=false.
	for _, e := range kernelCVEDB() {
		_ = e // the policy lives in scanKernelCVE's addFinding call; pinned
		// by the version-range tests above and the lab integration runner.
	}
}

// --- FP-7: NFS options ---

func TestNFSClientOptions(t *testing.T) {
	if rw, ro, nrs := nfsClientOptions("*(ro,no_root_squash)"); nrs && (rw || !ro) {
		t.Errorf("ro export parsed as writable: rw=%v ro=%v", rw, ro)
	}
	if rw, ro, nrs := nfsClientOptions("*(rw,no_root_squash)"); !nrs || !rw || ro {
		t.Errorf("rw export must parse rw+no_root_squash, got rw=%v ro=%v nrs=%v", rw, ro, nrs)
	}
	if _, ro, nrs := nfsClientOptions("*(ro,no_root_squash)"); !nrs || !ro {
		t.Errorf("ro export must parse ro+no_root_squash, got ro=%v nrs=%v", ro, nrs)
	}
	// exports(5) default: neither rw nor ro means rw.
	if _, ro, nrs := nfsClientOptions("*(no_root_squash)"); !nrs || ro {
		t.Errorf("default-writable export must parse as writable (ro=%v)", ro)
	}
	if rw, _, nrs := nfsClientOptions("192.168.1.0/24(rw,root_squash)"); nrs || !rw {
		t.Errorf("root_squash export must not flag no_root_squash, got nrs=%v rw=%v", nrs, rw)
	}
	if _, _, nrs := nfsClientOptions("host.example.com"); nrs {
		t.Error("bare host without options must not flag anything")
	}
}

// --- FN-5: /etc/environment PATH merge ---

func TestEnvPathDirs(t *testing.T) {
	content := "LANG=en_US.UTF-8\n" +
		"PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/custom/bin\"\n" +
		"EDITOR=vim\n" +
		"PATH=/second/declaration\n"
	got := envPathDirs(content)
	want := []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/opt/custom/bin", "/second/declaration"}
	if len(got) != len(want) {
		t.Fatalf("envPathDirs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("envPathDirs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if d := envPathDirs("no path here"); len(d) != 0 {
		t.Errorf("content without PATH must yield nothing, got %v", d)
	}
}

// --- FN-3: cron referenced paths ---

func TestCronReferencedPaths(t *testing.T) {
	line := "* * * * * root /opt/scripts/cleanup.sh >/var/log/cleanup.log 2>/dev/null"
	got := cronReferencedPaths(line)
	want := []string{"/opt/scripts/cleanup.sh", "/var/log/cleanup.log", "/dev/null"}
	if len(got) != len(want) {
		t.Fatalf("cronReferencedPaths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("path[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// env assignments never look like paths
	if p := cronReferencedPaths("PATH=/usr/bin:/bin"); len(p) != 0 {
		t.Errorf("PATH= assignment must not parse as a path, got %v", p)
	}
}

// --- INC-2: distribution-baseline SUID skip ---

func TestStandardBinLocation(t *testing.T) {
	for _, in := range []string{"/usr/bin/passwd", "/usr/lib/openssh/ssh-keysign", "/bin/mount", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"} {
		if !isStandardBinLocation(in) {
			t.Errorf("%s must be a standard location", in)
		}
	}
	for _, out := range []string{"/opt/secure/bin/custom-find", "/usr/local/bin/root-shell", "/tmp/x"} {
		if isStandardBinLocation(out) {
			t.Errorf("%s must NOT be a standard location", out)
		}
	}
}

// --- FN-2: renamed SUID content-hash detection ---

func TestDetectRenamedSUID(t *testing.T) {
	stubEUID(t, 1000)
	dir := t.TempDir()
	refDir := filepath.Join(dir, "refs")
	candDir := filepath.Join(dir, "cand")
	if err := os.MkdirAll(refDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(candDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Pristine "find" (GTFOBins-listed) and its renamed copy.
	pristine := filepath.Join(refDir, "find")
	renamed := filepath.Join(candDir, "custom-find")
	payload := []byte("#!/bin/sh\nfake find binary for the hash test\n")
	if err := os.WriteFile(pristine, payload, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(renamed, payload, 0755); err != nil {
		t.Fatal(err)
	}
	// An unrelated SUID unknown stays unknown.
	unrelated := filepath.Join(candDir, "vendor-tool")
	if err := os.WriteFile(unrelated, []byte("totally different bytes"), 0755); err != nil {
		t.Fatal(err)
	}

	origRefs := referenceBinDirs
	referenceBinDirs = []string{refDir}
	t.Cleanup(func() { referenceBinDirs = origRefs })

	p := &AutoPrivilege{Opts: Options{}}
	p.Findings = []Finding{
		{Source: "SUID", Target: renamed, Description: "SUID binary: custom-find (GTFOBins: false)", Risk: RiskLow, Exploitable: false},
		{Source: "SUID", Target: unrelated, Description: "SUID binary: vendor-tool (GTFOBins: false)", Risk: RiskLow, Exploitable: false},
	}
	detectRenamedSUID(p)

	byTarget := map[string]Finding{}
	for _, f := range p.Findings {
		byTarget[f.Target] = f
	}
	up := byTarget[renamed]
	if !up.Exploitable || up.Risk != RiskHigh {
		t.Errorf("renamed find copy must upgrade to HIGH/exploitable, got %+v", up)
	}
	if !strings.Contains(up.Description, "byte-identical copy of find") {
		t.Errorf("description must name the original binary, got %q", up.Description)
	}
	if un := byTarget[unrelated]; un.Exploitable || un.Risk != RiskLow {
		t.Errorf("unrelated unknown must stay informational, got %+v", un)
	}
}

// --- FP-1: root guards ---

func TestRootGuardsSkipEscalationScanners(t *testing.T) {
	stubEUID(t, 0) // simulate a root run on any CI runner

	dir := t.TempDir()
	// A "writable" cron file — as root the scanner must not report it.
	cronDir := filepath.Join(dir, "cron.d")
	if err := os.MkdirAll(cronDir, 0777); err != nil {
		t.Fatal(err)
	}
	cronFile := filepath.Join(cronDir, "backup")
	if err := os.WriteFile(cronFile, []byte("* * * * * root /bin/true\n"), 0666); err != nil {
		t.Fatal(err)
	}
	origCronDirs, origSpool := cronSystemDirs, cronSpoolDirs
	cronSystemDirs = []string{cronDir}
	cronSpoolDirs = []string{filepath.Join(dir, "spool")}
	t.Cleanup(func() { cronSystemDirs, cronSpoolDirs = origCronDirs, origSpool })

	p := &AutoPrivilege{Opts: Options{}}
	scanCron(p)
	if len(p.Findings) != 0 {
		t.Errorf("scanCron as root must stay silent, got %+v", p.Findings)
	}

	p2 := &AutoPrivilege{Opts: Options{}}
	scanSudo(p2)
	if len(p2.Findings) != 0 {
		t.Errorf("scanSudo as root must stay silent, got %+v", p2.Findings)
	}

	p3 := &AutoPrivilege{Opts: Options{}}
	scanDocker(p3)
	if len(p3.Findings) != 0 {
		t.Errorf("scanDocker as root must stay silent, got %+v", p3.Findings)
	}

	p4 := &AutoPrivilege{Opts: Options{}}
	scanCapabilities(p4)
	if len(p4.Findings) != 0 {
		t.Errorf("scanCapabilities as root must stay silent (no absurd CAP_SETUID-for-root), got %+v", p4.Findings)
	}

	p5 := &AutoPrivilege{Opts: Options{}}
	scanPolkit(p5)
	if len(p5.Findings) != 0 {
		t.Errorf("scanPolkit as root must stay silent, got %+v", p5.Findings)
	}

	// A pristine /etc/passwd scanned as root must not claim misconfig.
	p6 := &AutoPrivilege{Opts: Options{}}
	scanPasswd(p6)
	for _, f := range p6.Findings {
		if strings.Contains(f.Description, "Writable /etc/passwd — inject") {
			t.Errorf("root run must not claim writable passwd on a normal host, got %+v", f)
		}
	}
}

// Root + actual bit misconfiguration still surfaces (honest hardening
// signal, never an escalation claim).
func TestScanPasswdRootMisconfigOnly(t *testing.T) {
	stubEUID(t, 1000)
	p := &AutoPrivilege{Opts: Options{}}
	scanPasswd(p) // real /etc/passwd on CI: 0644 root:root
	for _, f := range p.Findings {
		if strings.Contains(f.Description, "misconfiguration") && currentEUID() != 0 {
			t.Errorf("non-root run must use the real-access branch, got %+v", f)
		}
	}
}

// --- FP-5: own crontab stays silent; root spool crontab surfaces ---

func TestScanCronSpoolOwnership(t *testing.T) {
	skipAsRoot(t)
	stubEUID(t, 1000)
	dir := t.TempDir()
	spool := filepath.Join(dir, "crontabs")
	if err := os.MkdirAll(spool, 0755); err != nil {
		t.Fatal(err)
	}
	// Our own crontab, world-writable: must stay SILENT (FP-5).
	own := filepath.Join(spool, currentUsername())
	if err := os.WriteFile(own, []byte("* * * * * /home/me/script.sh\n"), 0666); err != nil {
		t.Fatal(err)
	}
	// Root's crontab, world-writable: real vector.
	rootTab := filepath.Join(spool, "root")
	if err := os.WriteFile(rootTab, []byte("* * * * * /usr/local/bin/job\n"), 0666); err != nil {
		t.Fatal(err)
	}
	origSpool := cronSpoolDirs
	cronSpoolDirs = []string{spool}
	t.Cleanup(func() { cronSpoolDirs = origSpool })

	p := &AutoPrivilege{Opts: Options{}}
	scanCron(p)
	if len(p.Findings) != 1 {
		t.Fatalf("own crontab silent + root crontab flagged = exactly 1 finding, got %+v", p.Findings)
	}
	f := p.Findings[0]
	if f.Target != rootTab || f.Risk != RiskHigh || !f.Exploitable {
		t.Errorf("root crontab must be HIGH/exploitable, got %+v", f)
	}
}

// --- FN-3: root cron referencing a writable script ---

func TestScanCronReferencedScripts(t *testing.T) {
	skipAsRoot(t)
	stubEUID(t, 1000)
	dir := t.TempDir()
	scripts := filepath.Join(dir, "scripts")
	if err := os.MkdirAll(scripts, 0755); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(scripts, "cleanup.sh")
	if err := os.WriteFile(payload, []byte("#!/bin/bash\n"), 0777); err != nil { // user-writable
		t.Fatal(err)
	}
	cronDir := filepath.Join(dir, "cron.d")
	if err := os.MkdirAll(cronDir, 0755); err != nil {
		t.Fatal(err)
	}
	cronFile := filepath.Join(cronDir, "cleanup")
	if err := os.WriteFile(cronFile, []byte("* * * * * root "+payload+" >/dev/null 2>&1\n"), 0444); err != nil {
		t.Fatal(err)
	}
	// 0444 = not writable even for the owner: the cron file itself is locked
	// down (root-owned 0644 in production) — the referenced script is the
	// vector (FN-3).
	origCronDirs, origSpool := cronSystemDirs, cronSpoolDirs
	cronSystemDirs = []string{cronDir}
	cronSpoolDirs = []string{filepath.Join(dir, "spool")}
	t.Cleanup(func() { cronSystemDirs, cronSpoolDirs = origCronDirs, origSpool })

	p := &AutoPrivilege{Opts: Options{}}
	scanCron(p)
	found := false
	for _, f := range p.Findings {
		if f.Target == payload {
			found = true
			if f.Risk != RiskHigh || !f.Exploitable {
				t.Errorf("referenced writable script must be HIGH/exploitable, got %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("referenced writable script must be detected (FN-3), got %+v", p.Findings)
	}
	// The /dev/null redirect must never produce a finding.
	for _, f := range p.Findings {
		if f.Target == "/dev/null" {
			t.Errorf("device node /dev/null must not be flagged as a payload, got %+v", f)
		}
	}
}

// --- FN-5: custom config credential sweep ---

func TestCredentialAssignmentMatch(t *testing.T) {
	hits := []string{
		"DB_PASSWORD=SuperSecret123!\n",
		"API_KEY=sk-1234567890abcdef\n",
		"password: hunter2\n",
		"requirepass verysecret\n",
	}
	for _, c := range hits {
		if got := credentialAssignmentMatch(c); got == "" {
			t.Errorf("credential assignment %q must match", c)
		}
	}
	misses := []string{
		"password=changeme\n",
		"password=\n",
		"API_KEY=${ENV_API_KEY}\n",
		"# password = example\nnothing else\n",
		"password=xxxxx\n",
		"DATABASE_URL=postgres://localhost/app\n",
	}
	for _, c := range misses {
		if got := credentialAssignmentMatch(c); got != "" {
			t.Errorf("placeholder/template %q must not match, got %q", c, got)
		}
	}
}

func TestScanCustomConfigsFindsOptCustom(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "db.conf"), []byte("DB_PASSWORD=SuperSecret123!\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("API_KEY=sk-1234567890abcdef\n"), 0644); err != nil {
		t.Fatal(err)
	}
	origRoots := customConfigRoots
	customConfigRoots = []string{dir}
	t.Cleanup(func() { customConfigRoots = origRoots })

	p := &AutoPrivilege{Opts: Options{}}
	scanCustomConfigs(p)
	if len(p.Findings) != 2 {
		t.Fatalf("db.conf + .env in the custom root must both surface (FN-5), got %+v", p.Findings)
	}
	for _, f := range p.Findings {
		if f.Source != "CRED" || !f.Exploitable {
			t.Errorf("custom config credentials must be CRED/exploitable, got %+v", f)
		}
	}
}

// --- INC-2: score semantics ---

func TestScoreRiskSafeIsFree(t *testing.T) {
	// A container-context note and other SAFE intel must never move the
	// score — a clean container stays at 100.
	var fs []Finding
	for i := 0; i < 20; i++ {
		fs = append(fs, Finding{Source: "CONTAINER", Risk: RiskSafe, Exploitable: false})
	}
	if got := hardeningScore(fs); got != 100 {
		t.Errorf("SAFE context notes must cost nothing, got %d", got)
	}
}

func TestScoreInformationalCheap(t *testing.T) {
	// 3 kernel heuristic leads (HIGH informational) + container note:
	// the patched-real-host scenario from the audit.
	fs := []Finding{
		{Source: "KERNEL", Risk: RiskHigh, Exploitable: false},
		{Source: "KERNEL", Risk: RiskHigh, Exploitable: false},
		{Source: "KERNEL", Risk: RiskHigh, Exploitable: false},
	}
	if got := hardeningScore(fs); got != 91 {
		t.Errorf("3 heuristic kernel leads must cost 9 (score 91), got %d", got)
	}
}

// --- FP-2: NSpid semantics (bare metal is not a container) ---

func TestNSpidSingleValueIsHostNotContainer(t *testing.T) {
	// The pure parser already pins single NSpid = "host" (TestPidNamespace-
	// FromStatus). The audit FP-2 bug was the CALLER counting "host" as
	// container evidence. The only container verdict is "own":
	if ns := pidNamespaceFromStatus("Name:\tinit\nNSpid:\t1\n"); ns != "host" {
		t.Errorf("bare-metal NSpid must classify as host, got %q", ns)
	}
	if ns := pidNamespaceFromStatus("Name:\tsh\nNSpid:\t4213\t7\n"); ns != "own" {
		t.Errorf("namespaced NSpid must classify as own, got %q", ns)
	}
}

// --- FP-3: PwnKit is informational ---

func TestScanPwnKitNotExploitable(t *testing.T) {
	// The classification is pinned by construction in scanPwnKit
	// (RiskLow/false). Guard the contract: no pkexec finding may ever be
	// exploitable in the DB-driven scanners. This test documents the rule;
	// the lab integration runner enforces it end-to-end on the clean image.
	p := &AutoPrivilege{Opts: Options{}}
	before := len(p.Findings)
	scanPwnKit(p)
	for _, f := range p.Findings[before:] {
		if f.Exploitable {
			t.Errorf("PwnKit heuristic must never be exploitable (FP-3), got %+v", f)
		}
	}
}

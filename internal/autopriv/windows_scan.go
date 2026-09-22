//go:build windows

package autopriv

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// ================================================================
// FASE 1 — Windows scanners
//
// The Windows scanner suite mirrors the honesty contract of the Linux
// one: read-only enumeration of the privilege-escalation surfaces a real
// operator checks on a Windows box — token privileges, registry
// misconfigurations, services, autoruns, scheduled tasks, credential
// artifacts and PATH hijack opportunities. Every external command is a
// Windows built-in (reg.exe, whoami.exe, schtasks via PowerShell CIM),
// each bounded by --scan-timeout. Auto-exploitation stays Linux-only in
// v1.9: the Windows phase enumerates and prints manual techniques.
//
// One documented probe exception to "read-only": writability on Windows
// cannot be read from permission bits (ACLs are not stdlib-reachable), so
// winWritableDir creates and removes a 0-byte temp file — the same probe
// winPEAS performs, leaving nothing behind when it fails.
// ================================================================

var windowsScannerOrder = []func(*AutoPrivilege){
	scanWinOS, scanWinPrivs, scanWinRegistry, scanWinServices,
	scanWinAutoruns, scanWinTasks, scanWinCreds, scanWinPath,
}

// --- Shared Windows helpers ---------------------------------------------

// winCmd runs an external command with the scan timeout and returns its
// combined output. ok=false means the command is missing or produced
// nothing usable.
func winCmd(p *AutoPrivilege, name string, args ...string) (string, bool) {
	out, err := runCmdOut(p.Opts.scanCmdTimeout(), name, args...)
	if err != nil && len(out) == 0 {
		return "", false
	}
	return string(out), true
}

// regLineRe matches one `reg query` value row: NAME <spaces> TYPE <spaces>
// DATA. The column separator is 2+ spaces, which keeps values containing
// single spaces intact.
var regLineRe = regexp.MustCompile(`^(\S.*?)\s{2,}(REG_\w+)\s{2,}(.*)$`)

// regQueryAll returns every value under a registry key as name → data
// (the type is dropped; DWORD data keeps its 0x form and is decoded with
// regDWORD). nil means the key is missing or unreadable.
func regQueryAll(p *AutoPrivilege, key string) map[string]string {
	out, ok := winCmd(p, "reg", "query", key)
	if !ok || strings.Contains(out, "ERROR") {
		return nil
	}
	vals := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		m := regLineRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		vals[m[1]] = strings.TrimSpace(m[3])
	}
	return vals
}

// regDWORD decodes a `reg query` DWORD value ("0x1") from a regQueryAll map.
func regDWORD(vals map[string]string, name string) (uint32, bool) {
	v, ok := vals[name]
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(v), "0x"), 16, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// winWritableDir probes whether the current user can create files in dir:
// Windows permission bits carry no ACL truth, so the probe creates and
// removes a 0-byte temp file. A failed probe leaves nothing behind.
func winWritableDir(dir string) bool {
	if dir == "" {
		return false
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return false
	}
	f, err := os.CreateTemp(dir, ".autopriv-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// winWritableFile opens an existing file for writing WITHOUT writing: the
// open either succeeds (ACL grants write) or fails. Content never changes.
// Sharing violations on running binaries count as not writable — an
// honest answer for binary-replacement planning.
func winWritableFile(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// winEnvRe matches %VAR% references inside unexpanded paths.
var winEnvRe = regexp.MustCompile(`%(\w+)%`)

// winExpandEnv expands %VAR% references using the process environment.
func winExpandEnv(s string) string {
	return winEnvRe.ReplaceAllStringFunc(s, func(m string) string {
		if sub := winEnvRe.FindStringSubmatch(m); sub != nil {
			if v, ok := os.LookupEnv(sub[1]); ok {
				return v
			}
		}
		return m
	})
}

// winBinFromPath extracts the executable path from a service/autorun
// PathName like `"C:\Program Files\v\tool.exe" -run` or
// `C:\Program Files\v\tool.exe -run`, tolerating quoted and unquoted
// spellings (the unquoted-with-space form is itself a finding).
func winBinFromPath(pathname string) string {
	s := strings.TrimSpace(pathname)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			return s[1 : end+1]
		}
		return strings.Trim(s, `"`)
	}
	if i := strings.Index(strings.ToLower(s), ".exe"); i >= 0 {
		return s[:i+4]
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// firstWritableAncestor walks from the binary's directory up to the drive
// root and returns the deepest user-writable ancestor — for an unquoted
// service path, any writable ancestor is a binary-planting directory.
func firstWritableAncestor(binPath string) string {
	dir := filepath.Dir(binPath)
	for {
		if winWritableDir(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// winCmdFromCSV runs a command and parses its output as CSV, skipping the
// header row. Used for the PowerShell ConvertTo-Csv queries, whose column
// names are chosen by us and therefore locale-stable.
func winCmdFromCSV(p *AutoPrivilege, name string, args ...string) [][]string {
	out, ok := winCmd(p, name, args...)
	if !ok {
		return nil
	}
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil || len(rows) < 2 {
		return nil
	}
	return rows[1:]
}

// winPrivEnabled interprets whoami's State column, whose wording depends
// on the display language. The disabled form in every major locale starts
// with dis-/des-/dé-/de- (disabled, desactivado, désactivé, deaktiviert),
// so anything else counts as enabled. Heuristic, documented here.
func winPrivEnabled(state string) bool {
	s := strings.ToLower(strings.TrimSpace(state))
	if s == "" {
		return true
	}
	for _, off := range []string{"dis", "des", "dé", "de", "off"} {
		if strings.HasPrefix(s, off) {
			return false
		}
	}
	return true
}

// --- 1. OS banner ---------------------------------------------------------

func scanWinOS(p *AutoPrivilege) {
	vals := regQueryAll(p, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if vals == nil {
		return
	}
	display := vals["DisplayVersion"]
	if display == "" {
		display = vals["ReleaseId"]
	}
	ver := strings.Join(strings.Fields(strings.TrimSpace(
		fmt.Sprintf("%s %s (build %s.%s)", vals["ProductName"], display, vals["CurrentBuild"], vals["UBR"]),
	)), " ")
	if ver == "" {
		return
	}
	addFinding(p, "WINOS", "", "Windows "+ver+", "+runtime.GOARCH, RiskSafe, false)
}

// --- 2. Token privileges + integrity level --------------------------------

// winPrivTable maps whoami privilege names to their escalation meaning.
// The potato family (SeImpersonate) is the modern service-account
// classic; the rest are the Priv2Admin primitives.
var winPrivTable = []struct {
	priv string
	desc string
	risk RiskLevel
}{
	{"SeImpersonatePrivilege", "SeImpersonatePrivilege held — impersonate a SYSTEM client token: the potato family (PrintSpoofer, GodPotato, JuicyPotatoNG)", RiskDanger},
	{"SeAssignPrimaryTokenPrivilege", "SeAssignPrimaryTokenPrivilege held — assign a SYSTEM token to a process (potato-family companion)", RiskHigh},
	{"SeBackupPrivilege", "SeBackupPrivilege held — read any file bypassing ACLs: copy SAM/SYSTEM hives and dump hashes offline", RiskHigh},
	{"SeRestorePrivilege", "SeRestorePrivilege held — write any file bypassing ACLs (replace binaries in system locations)", RiskHigh},
	{"SeLoadDriverPrivilege", "SeLoadDriverPrivilege held — load a kernel driver (known driver-based escalation primitives)", RiskHigh},
	{"SeTakeOwnershipPrivilege", "SeTakeOwnershipPrivilege held — take ownership of any object, then read or replace it", RiskHigh},
	{"SeDebugPrivilege", "SeDebugPrivilege held — open any process including SYSTEM/lsass (credential dumping)", RiskHigh},
	{"SeCreateTokenPrivilege", "SeCreateTokenPrivilege held — mint an elevated token", RiskDanger},
	{"SeTcbPrivilege", "SeTcbPrivilege held — act as part of the trusted computing base (SYSTEM-equivalent)", RiskDanger},
	{"SeManageVolumePrivilege", "SeManageVolumePrivilege held — volume-level primitives with known escalation paths", RiskMedium},
}

func scanWinPrivs(p *AutoPrivilege) {
	if isRoot() {
		addFinding(p, "WINPRIV", "", "Process token is elevated (Administrator) — nothing to escalate, audit the surface instead", RiskSafe, false)
	}

	// whoami /priv /fo csv: positional columns (localized headers — never
	// trust the header row): col 0 = privilege name, col 1 = state.
	for _, row := range winCmdFromCSV(p, "whoami", "/priv", "/fo", "csv") {
		if len(row) < 2 {
			continue
		}
		for _, e := range winPrivTable {
			if !strings.EqualFold(strings.TrimSpace(row[0]), e.priv) {
				continue
			}
			enabled := winPrivEnabled(row[1])
			state := ""
			if !enabled {
				state = " (currently disabled — re-check after SeEnvironment nudges)"
			}
			addFinding(p, "WINPRIV", e.priv, e.desc+state, e.risk, enabled)
		}
	}

	// whoami /groups /fo csv: the integrity level and the Administrators
	// membership hide among the SIDs — scan every cell (headers lie about
	// column positions per locale, SIDs never lie).
	admin, medium := false, false
	for _, row := range winCmdFromCSV(p, "whoami", "/groups", "/fo", "csv") {
		for _, cell := range row {
			cell = strings.TrimSpace(cell)
			switch {
			case strings.HasPrefix(cell, "S-1-5-32-544"):
				admin = true
			case cell == "S-1-16-8192":
				medium = true
			}
		}
	}
	if admin && medium && !isRoot() {
		addFinding(p, "WINPRIV", "UAC", "Member of Administrators running at Medium integrity — UAC-filtered admin: the known UAC bypass surface (fodhelper, computerdefaults, sdclt) applies", RiskMedium, true)
	}
}

// --- 3. Registry misconfigurations -----------------------------------------

func scanWinRegistry(p *AutoPrivilege) {
	// AlwaysInstallElevated: BOTH hives must say 1 for msiexec to run
	// every MSI as SYSTEM — the classic CTF misconfiguration.
	lm := regQueryAll(p, `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`)
	cu := regQueryAll(p, `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`)
	lmv, lmOK := regDWORD(lm, "AlwaysInstallElevated")
	cuv, cuOK := regDWORD(cu, "AlwaysInstallElevated")
	if lmOK && cuOK && lmv == 1 && cuv == 1 {
		addFinding(p, "WINREG", `HKLM+HKCU\...\Windows\Installer\AlwaysInstallElevated`,
			"AlwaysInstallElevated=1 in both hives — every .msi installs as SYSTEM (msiexec /quiet /qn /i)", RiskHigh, true)
	}

	wl := regQueryAll(p, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`)
	if wl != nil {
		// AutoLogon stores the account password in PLAINTEXT.
		if pw := strings.TrimSpace(wl["DefaultPassword"]); pw != "" {
			addFinding(p, "WINREG", `HKLM\...\Winlogon\DefaultPassword`,
				"AutoLogon password stored in plaintext in the registry (user: "+wl["DefaultUserName"]+")", RiskDanger, true)
		}
		// UAC state: EnableLUA=0 means UAC is fully off.
		if lua, ok := regDWORD(wl, "EnableLUA"); ok && lua == 0 {
			addFinding(p, "WINREG", `HKLM\...\Winlogon\EnableLUA`,
				"EnableLUA=0 — UAC fully disabled: every admin process runs elevated silently", RiskMedium, false)
		}
	}

	// PuTTY saved sessions: proxy usernames leak and the obfuscated
	// session password is publicly documented as decodable.
	if out, ok := winCmd(p, "reg", "query", `HKCU\Software\SimonTatham\PuTTY\Sessions`); ok {
		n := strings.Count(out, `PuTTY\Sessions\`)
		if n > 1 { // the query echoes the key path itself once
			addFinding(p, "WINREG", `HKCU\Software\SimonTatham\PuTTY\Sessions`,
				fmt.Sprintf("%d saved PuTTY session(s) — proxy usernames leak; the obfuscated password is decodable", n-1),
				RiskLow, false)
		}
	}
}

// --- 4. Services -----------------------------------------------------------

// winServiceQuery enumerates services with locale-stable column names
// (the headers come from our Select-Object, not from the OS).
const winServiceQuery = "Get-CimInstance Win32_Service | Select-Object Name,PathName,StartName,StartMode | ConvertTo-Csv -NoTypeInformation"

func scanWinServices(p *AutoPrivilege) {
	for _, r := range winCmdFromCSV(p, "powershell", "-NoProfile", "-Command", winServiceQuery) {
		if len(r) < 3 {
			continue
		}
		name := strings.TrimSpace(r[0])
		raw := strings.TrimSpace(r[1])
		startName := strings.TrimSpace(r[2])
		if name == "" || raw == "" {
			continue
		}
		bin := winBinFromPath(winExpandEnv(raw))
		if bin == "" {
			continue
		}

		// 1) Unquoted service path with spaces: Windows resolves the
		// binary by trying every space-prefix — a planted exe one
		// directory up the chain wins.
		if !strings.HasPrefix(raw, `"`) && strings.Contains(raw, " ") {
			if w := firstWritableAncestor(bin); w != "" {
				addFinding(p, "WINSVC", name,
					"Unquoted service path with spaces and writable ancestor "+w+" — plant an exe up the chain", RiskHigh, true)
			} else {
				addFinding(p, "WINSVC", name,
					"Unquoted service path with spaces (no writable ancestor found — verify manually)", RiskMedium, false)
			}
		}

		// 2) The service binary's directory is user-writable: replace
		// the binary and wait for/trigger a restart.
		if winWritableDir(filepath.Dir(bin)) {
			addFinding(p, "WINSVC", name,
				"Service binary lives in a user-writable directory ("+filepath.Dir(bin)+") — replace the binary, then restart the service", RiskHigh, true)
		}

		// 3) A SYSTEM-owned service whose binary hides under a user
		// profile: trivially replaceable, runs as SYSTEM.
		systemRun := strings.EqualFold(startName, "LocalSystem") ||
			strings.EqualFold(startName, "LocalService") ||
			strings.EqualFold(startName, "SYSTEM")
		if systemRun && strings.Contains(strings.ToLower(bin), `\users\`) {
			addFinding(p, "WINSVC", name,
				"Service runs as "+startName+" but its binary lives under a user profile ("+bin+")", RiskHigh, true)
		}
	}
}

// --- 5. Autoruns -------------------------------------------------------------

var winAutorunKeys = []string{
	`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
	`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	`HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`,
	`HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
	`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
	`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
}

func scanWinAutoruns(p *AutoPrivilege) {
	for _, key := range winAutorunKeys {
		for name, cmd := range regQueryAll(p, key) {
			bin := winBinFromPath(winExpandEnv(cmd))
			if bin == "" {
				continue
			}
			switch {
			case winWritableFile(bin):
				addFinding(p, "WINAUTO", name,
					"Autorun binary is user-writable ("+bin+") — replace it; it executes at every logon, admins included", RiskHigh, true)
			case winWritableDir(filepath.Dir(bin)):
				addFinding(p, "WINAUTO", name,
					"Autorun binary directory is user-writable ("+filepath.Dir(bin)+") — drop/replace the payload", RiskHigh, true)
			}
		}
	}
}

// --- 6. Scheduled tasks --------------------------------------------------------

// winTaskQuery enumerates tasks with locale-stable columns; Cmd joins
// every action's executable + arguments.
const winTaskQuery = "Get-ScheduledTask | Select-Object TaskPath,TaskName,State,@{n='User';e={$_.Principal.UserId}},@{n='Cmd';e={($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments) }) -join '; '}} | ConvertTo-Csv -NoTypeInformation"

func scanWinTasks(p *AutoPrivilege) {
	for _, r := range winCmdFromCSV(p, "powershell", "-NoProfile", "-Command", winTaskQuery) {
		if len(r) < 5 {
			continue
		}
		task := strings.TrimSpace(r[0]) + strings.TrimSpace(r[1])
		state := strings.TrimSpace(r[2])
		user := strings.TrimSpace(r[3])
		cmd := strings.TrimSpace(r[4])
		if task == "" || cmd == "" || strings.EqualFold(state, "Disabled") {
			continue
		}
		bin := winBinFromPath(winExpandEnv(cmd))
		if bin == "" {
			continue
		}
		privileged := strings.EqualFold(user, "SYSTEM") ||
			strings.EqualFold(user, "NT AUTHORITY\\SYSTEM") ||
			strings.Contains(strings.ToUpper(user), "ADMINISTRATORS")
		if winWritableFile(bin) || winWritableDir(filepath.Dir(bin)) {
			risk := RiskMedium
			if privileged {
				risk = RiskHigh
			}
			addFinding(p, "WINTASK", task,
				"Scheduled task"+privSuffix(privileged)+" executes "+bin+" from a user-writable location — edit the script or replace the binary", risk, true)
		} else if privileged && strings.Contains(strings.ToLower(bin), `\users\`) {
			addFinding(p, "WINTASK", task,
				"Scheduled task runs as "+user+" but its command lives under a user profile ("+bin+")", RiskHigh, true)
		}
	}
}

// privSuffix renders the run-as context for task findings.
func privSuffix(privileged bool) string {
	if privileged {
		return " (as SYSTEM/admin)"
	}
	return ""
}

// --- 7. Credential artifacts -----------------------------------------------------

// winUnattendFiles are the deployment answer files that keep leaking
// account passwords years after setup.
var winUnattendFiles = []string{
	`Panther\unattend.xml`,
	`Panther\Unattend\unattended.xml`,
	`Panther\unattended.xml`,
	`Panther\sysprep.inf`,
	`System32\sysprep\sysprep.xml`,
	`System32\sysprep\unattend.xml`,
}

// winGPPFiles are the Group Policy Preferences files whose cpassword
// field is encrypted with a PUBLIC AES key (MS14-025).
var winGPPFiles = []string{
	"Groups.xml", "Services.xml", "ScheduledTasks.xml",
	"DataSources.xml", "Printers.xml", "Drives.xml",
}

func scanWinCreds(p *AutoPrivilege) {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	for _, rel := range winUnattendFiles {
		f := filepath.Join(sysroot, rel)
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		low := strings.ToLower(string(data))
		if strings.Contains(low, "<password") || strings.Contains(low, "plaintext>true") || strings.Contains(low, "password=") {
			addFinding(p, "WINCRED", f,
				"Deployment answer file with a password field — extract it (plaintext or trivially decodable base64)", RiskDanger, true)
		} else {
			addFinding(p, "WINCRED", f,
				"Readable deployment answer file — review for credentials", RiskMedium, false)
		}
	}

	// GPP cpassword: walk the cached policy history tree.
	gppRoot := filepath.Join(os.Getenv("ProgramData"), "Microsoft", "Group Policy", "history")
	for _, name := range winGPPFiles {
		found := false
		_ = filepath.WalkDir(gppRoot, func(path string, d os.DirEntry, err error) error {
			if err != nil || found || d.IsDir() || !strings.EqualFold(d.Name(), name) {
				return nil
			}
			if data, err := os.ReadFile(path); err == nil && strings.Contains(strings.ToLower(string(data)), "cpassword") {
				addFinding(p, "WINCRED", path,
					"GPP cpassword present — encrypted with the PUBLIC AES key (MS14-025): gpp-decrypt recovers it", RiskDanger, true)
				found = true
			}
			return nil
		})
	}

	// PowerShell console history: credential-shaped words reviewed manually.
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		hist := filepath.Join(appdata, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
		if data, err := os.ReadFile(hist); err == nil {
			low := strings.ToLower(string(data))
			for _, probe := range []string{"password", "secret", "token", "-cred"} {
				if strings.Contains(low, probe) {
					addFinding(p, "WINCRED", hist,
						"PowerShell history contains credential-shaped text ("+probe+") — review manually", RiskMedium, false)
					break
				}
			}
		}
	}

	// Cloud + key material in the user profile.
	if up := os.Getenv("USERPROFILE"); up != "" {
		for _, c := range []struct{ path, desc string }{
			{filepath.Join(up, ".aws", "credentials"), "AWS credentials file"},
			{filepath.Join(up, ".azure", "accessTokens.json"), "Azure access token cache"},
			{filepath.Join(up, ".azure", "profile.json"), "Azure profile"},
			{filepath.Join(up, ".ssh", "id_rsa"), "SSH private key"},
		} {
			if f, err := os.Open(c.path); err == nil {
				f.Close()
				addFinding(p, "WINCRED", c.path, c.desc+" readable by the current user", RiskMedium, false)
			}
		}
	}
}

// --- 8. PATH hijack -----------------------------------------------------------

func scanWinPath(p *AutoPrivilege) {
	for _, dir := range strings.Split(os.Getenv("PATH"), ";") {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		if winWritableDir(dir) {
			addFinding(p, "WINPATH", dir,
				"Writable directory in PATH — hijack the next binary/DLL a privileged process resolves", RiskHigh, true)
		}
	}
}

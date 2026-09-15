package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ================================================================
// SARIF 2.1.0 export (--sarif file)
// ================================================================

// The SARIF (Static Analysis Results Interchange Format) log is the lingua
// franca of code-scanning platforms: GitHub's Security tab, GitLab, Azure
// DevOps and SARIF viewers all ingest it natively. Exporting findings as
// SARIF plugs Auto-Privilege into those dashboards without any external
// converter (zero deps stays intact) — the same report the --json contract
// serves, dressed for the platform.

type sarifContent struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifContent `json:"shortDescription"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifContent    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// sarifLevel maps the Auto-Privilege risk scale onto the three levels SARIF
// defines: error (actionable top risks), warning (medium), note (low and
// informational). DANGER and HIGH both map to error — SARIF has no fifth
// level and both demand the same attention from a scanning dashboard.
func sarifLevel(r RiskLevel) string {
	switch r {
	case RiskDanger, RiskHigh:
		return "error"
	case RiskMedium:
		return "warning"
	default:
		return "note"
	}
}

// sarifRuleText gives each finding source a stable human description for
// the rules block — what the rule means on the dashboard's rule list.
func sarifRuleText(source string) string {
	switch source {
	case "SUID":
		return "SUID binaries that escalate to root"
	case "SGID":
		return "SGID binaries with group-level escalation"
	case "SUDO":
		return "sudo rules granting privileged commands"
	case "CRON":
		return "cron jobs the current user can influence"
	case "FILE":
		return "critical system files with weak permissions"
	case "DOCKER":
		return "docker surfaces that break out to the host"
	case "CONTAINER":
		return "container runtime breakout surfaces"
	case "CAPS":
		return "capabilities enabling privilege changes"
	case "NFS":
		return "NFS exports with unsafe settings"
	case "PATH":
		return "writable directories in the executable search path"
	case "SERVICE":
		return "systemd units the current user can modify"
	case "KERNEL":
		return "kernel/sudo/pkexec known-exploitation candidates"
	case "CRED":
		return "credentials and secrets reachable by the current user"
	case "PRELOAD":
		return "ld.so.preload entries executing with euid 0"
	case "SUDOERS":
		return "writable sudoers configuration"
	case "GROUP":
		return "writable group database"
	case "HOOKS":
		return "writable login-shell hooks"
	default:
		return fmt.Sprintf("Auto-Privilege %s finding", strings.ToLower(source))
	}
}

// sarifTargetURI converts a finding target into a SARIF artifact URI, but
// only when the target IS a filesystem path — targets like "ALL", "self",
// "CVE-2021-4034" or a socket-bearing path that is not absolute have no
// file location, and SARIF allows results without locations. Returning
// false suppresses the location block instead of fabricating one.
func sarifTargetURI(target string) (string, bool) {
	if !strings.HasPrefix(target, "/") {
		return "", false
	}
	u := url.URL{Scheme: "file", Path: target}
	return u.String(), true
}

// buildSARIF renders the findings as a SARIF 2.1.0 log. Rules are deduped
// per source in first-appearance order (never map iteration — the same
// scan always produces byte-identical SARIF) and each result carries a
// location only for path-like targets; everything else embeds the target
// into the message so no context is lost on the dashboard.
func buildSARIF(findings []Finding) sarifLog {
	rules := []sarifRule{}
	ruleSeen := map[string]bool{}
	results := []sarifResult{}

	for _, f := range findings {
		if !ruleSeen[f.Source] {
			ruleSeen[f.Source] = true
			rules = append(rules, sarifRule{
				ID:               f.Source,
				Name:             "AutoPrivilege" + f.Source,
				ShortDescription: sarifContent{Text: sarifRuleText(f.Source)},
			})
		}

		res := sarifResult{
			RuleID:  f.Source,
			Level:   sarifLevel(f.Risk),
			Message: sarifContent{Text: f.Description},
		}
		if uri, ok := sarifTargetURI(f.Target); ok {
			res.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
				},
			}}
		} else if f.Target != "" {
			res.Message = sarifContent{Text: fmt.Sprintf("%s (target: %s)", f.Description, f.Target)}
		}
		results = append(results, res)
	}

	return sarifLog{
		Version: "2.1.0",
		Schema:  sarifSchema,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "Auto-Privilege",
					Version:        Version,
					InformationURI: "https://github.com/Ruby570bocadito/Auto-Privilege",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
}

// WriteSARIFFile persists the SARIF log with 0600 permissions, matching
// the other report artifacts: findings name escalation paths and secrets-
// adjacent targets, so the file must never be group/world readable.
func (p *AutoPrivilege) WriteSARIFFile(path string) error {
	data, err := marshalJSON(buildSARIF(p.Findings))
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

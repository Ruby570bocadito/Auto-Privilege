//go:build !linux && !windows

package autopriv

import (
	"errors"
	"os"
)

// ================================================================
// Platform layer — other Unix (darwin, *BSD)
//
// AUTOPRIV's scanners target Linux surfaces, but the tool still builds,
// runs and reports honestly elsewhere: this stub keeps compilation green on
// the remaining Unixes, where the Linux scanner set runs and simply finds
// nothing (the paths it probes do not exist there).
// ================================================================

// isTerminal uses the portable char-device heuristic. /dev/null matches
// too, which only means "maybe" — good enough for a best-effort color
// decision on platforms AUTOPRIV does not officially target.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// fileOwnerIDs: Stat_t layouts differ per Unix flavor; returning ok=false
// degrades every uid-based classification honestly instead of guessing
// with the wrong struct layout.
func fileOwnerIDs(info os.FileInfo) (uid, gid uint32, ok bool) {
	return 0, 0, false
}

// isRoot: euid 0 exists on every Unix.
func isRoot() bool {
	return os.Geteuid() == 0
}

// escalateInProcess requires the Linux setuid semantics.
func escalateInProcess() error {
	return errors.New("in-process uid escalation is Linux-only on this platform")
}

// platformScanners returns the Linux scanner set — it probes Linux paths
// and stays honestly silent where they do not exist.
func platformScanners() []func(*AutoPrivilege) {
	return scannerOrder
}

// enableANSISupport is a no-op: these terminals speak ANSI natively.
func enableANSISupport() {}

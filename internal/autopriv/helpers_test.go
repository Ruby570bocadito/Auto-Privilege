package autopriv

import (
	"os"
	"runtime"
	"testing"
)

// osLink wraps os.Symlink so tests that exercise symlink-skipping do not
// fail outright in environments (CI sandboxes) that forbid creating links.
func osLink(target, link string) error {
	return os.Symlink(target, link)
}

// skipNonPOSIXPerms bows out on Windows: the Linux scanners' writability
// logic reads POSIX permission bits, and os.Chmod cannot simulate a locked
// directory there (directory chmod is a no-op), so perm-based silence
// expectations are not testable on that platform. The Windows scanners
// have their own writability probe (winWritableDir) validated by their own
// behavior on a real host in CI.
func skipNonPOSIXPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission-bit semantics are not simulable on Windows (directory chmod is a no-op there)")
	}
}

// assertPinned0600 pins the report-artifact permission contract: every
// report the tool writes lands at 0600 regardless of the process umask.
// Windows mode bits cannot express 0600 (only the read-only attribute
// exists), so the assertion bows out there — NTFS ACLs govern instead and
// the write itself is still exercised by the caller.
func assertPinned0600(t *testing.T, path, what string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("%s must be 0600, got %v", what, got)
	}
}

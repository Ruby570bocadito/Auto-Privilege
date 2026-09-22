//go:build linux

package autopriv

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// ================================================================
// Platform layer — Linux
//
// Every syscall that only exists on Linux (Stat_t, TCGETS, Setuid) lives
// behind the three helpers below (isTerminal, fileOwnerIDs,
// escalateInProcess) plus isRoot/platformScanners, each with a matching
// implementation in platform_windows.go and platform_other.go. The scanner
// and exploit engines stay OS-agnostic and never import syscall directly.
// ================================================================

// isTerminal reports whether f is a real terminal (TTY). A plain char-device
// check is not enough — /dev/null also matches — so we ask the kernel with
// TCGETS, which only succeeds on actual ttys.
func isTerminal(f *os.File) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&termios)),
		0, 0, 0,
	)
	return errno == 0
}

// fileOwnerIDs extracts the owning uid and gid from a FileInfo. The bool
// reports whether the platform exposes numeric owners at all — callers
// degrade honestly (skip uid-based classification) when it is false.
func fileOwnerIDs(info os.FileInfo) (uid, gid uint32, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return stat.Uid, stat.Gid, true
}

// isRoot: on Linux the euid is the whole story (setuid binaries included).
func isRoot() bool {
	return os.Geteuid() == 0
}

// escalateInProcess promotes the current process to uid 0 in-process —
// the CAP_SETUID technique (no external shell involved).
func escalateInProcess() error {
	if err := syscall.Setgid(0); err != nil {
		return fmt.Errorf("setgid(0): %w", err)
	}
	if err := syscall.Setuid(0); err != nil {
		return fmt.Errorf("setuid(0): %w", err)
	}
	if os.Getuid() != 0 {
		return errors.New("setuid(0) did not stick")
	}
	return nil
}

// platformScanners returns the Linux scanner set (scanner.go). It is a
// package VAR (not a plain func) so the parallel-merge test can swap in a
// synthetic scanner set on every platform — on Windows the equivalent var
// in platform_windows.go returns windowsScannerOrder.
var platformScanners = func() []func(*AutoPrivilege) {
	return scannerOrder
}

// enableANSISupport is a no-op on Linux: terminals speak ANSI natively.
func enableANSISupport() {}

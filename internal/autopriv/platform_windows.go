//go:build windows

package autopriv

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// ================================================================
// Platform layer — Windows
//
// The Windows twin of platform_linux.go. Numeric uid/gid do not exist here
// (ACLs instead), terminals answer GetConsoleMode, "root" means an elevated
// token, and in-process setuid escalation is not a Windows concept — the
// helpers degrade honestly so the shared engines stay identical.
// ================================================================

// isTerminal reports whether f is attached to a console: GetConsoleMode
// succeeds only for real console handles (CONIN$/CONOUT$), the same trick
// the TCGETS ioctl performs on Linux.
func isTerminal(f *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}

// fileOwnerIDs: Windows files carry ACLs, not numeric uid/gid — there is
// no honest answer to give, so ok=false and every uid-based classification
// (SUID ownership, PATH-planting ownership) is skipped rather than guessed.
func fileOwnerIDs(info os.FileInfo) (uid, gid uint32, ok bool) {
	return 0, 0, false
}

// isRoot: on Windows "root" means the process token is elevated
// (Administrator with UAC consent already given). The stdlib syscall
// package exposes the token handle but not the TokenElevation query, so
// the single GetTokenInformation call goes through LazyDLL — the same
// primitive golang.org/x/sys/windows wraps, without adding a dependency.
func isRoot() bool {
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer tok.Close()
	const tokenElevation = 20
	var elevated uint32 // TOKEN_ELEVATION is a single DWORD
	var returned uint32
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	getTokenInformation := advapi32.NewProc("GetTokenInformation")
	r1, _, _ := getTokenInformation.Call(
		uintptr(tok),
		uintptr(tokenElevation),
		ptr(&elevated),
		uintptr(unsafe.Sizeof(elevated)),
		ptr(&returned),
	)
	return r1 != 0 && elevated != 0
}

// escalateInProcess is not a Windows technique: uid 0 does not exist and
// the CAP_SETUID path has no equivalent. The exploit engine reports the
// error instead of pretending.
func escalateInProcess() error {
	return errors.New("in-process uid escalation is Linux-only; on Windows follow the enumerated manual vectors")
}

// platformScanners returns the Windows scanner set (windows_scan.go).
func platformScanners() []func(*AutoPrivilege) {
	return windowsScannerOrder
}

// enableANSISupport flips ENABLE_VIRTUAL_TERMINAL_PROCESSING on the stdout
// console so ANSI colors render even in legacy conhost sessions (Windows
// Terminal speaks ANSI natively). SetConsoleMode is not in the stdlib
// syscall surface, so it rides LazyDLL — best effort: a failure changes
// nothing, --no-color remains the escape hatch.
func enableANSISupport() {
	const enableVirtualTerminal = 0x0004
	h := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	if syscall.GetConsoleMode(h, &mode) == nil {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		setConsoleMode := kernel32.NewProc("SetConsoleMode")
		_, _, _ = setConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminal))
	}
}

// ptr is a tiny uintptr(unsafe.Pointer) helper that keeps the uintptr
// conversions for LazyDLL.Call in one obvious place.
func ptr[T any](v *T) uintptr { return uintptr(unsafe.Pointer(v)) }

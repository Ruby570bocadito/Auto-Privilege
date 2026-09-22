// Command autoprivilege: the AUTOPRIV binary — an automated local
// privilege-escalation audit suite (scan, enumerate, auto-root) for
// authorized Linux security work, with read-only Windows enumeration since
// v1.9.0.
//
// The entire pipeline (flags, scanners, enumeration, exploitation, exit
// codes) lives in internal/autopriv.Run; this wrapper deliberately stays a
// one-liner so the CLI surface can never diverge from the library.
package main

import "github.com/Ruby570bocadito/Auto-Privilege/internal/autopriv"

func main() {
	autopriv.Run()
}

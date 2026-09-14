package main

import "os"

// osLink wraps os.Symlink so tests that exercise symlink-skipping do not
// fail outright in environments (CI sandboxes) that forbid creating links.
func osLink(target, link string) error {
	return os.Symlink(target, link)
}

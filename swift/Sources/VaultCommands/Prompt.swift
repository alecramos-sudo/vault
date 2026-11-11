import Foundation
import VaultCore

#if canImport(Darwin)
	import Darwin
#elseif canImport(Glibc)
	import Glibc
#elseif canImport(Musl)
	import Musl
#elseif canImport(WinSDK)
	import WinSDK
#endif

// Passphrase input. Sources in priority order:
//   0. --passphrase-file / $VAULT_PASSPHRASE_FILE (unattended boxes; strict file checks).
//   1. stdin protocol (--passphrase-stdin): each call consumes ONE line. Secrets
//      cross the process boundary over stdin, never argv or env.
//   2. $VAULT_PASSPHRASE (tests/CI), unless the caller opts out (`useEnv: false`
//      for secondary prompts such as an item's own password).
//   3. muted TTY prompt.

var passphraseFromStdin: Bool {
	get { CommandContext.current.stdinSecrets }
	set { CommandContext.current.stdinSecrets = newValue }
}

private func readLineBytes() -> Data? {
	guard var line = readLine(strippingNewline: true) else { return nil }
	if line.hasSuffix("\r") { line.removeLast() }
	return Data(line.utf8)
}

func readStdinLine() throws -> String {
	if let s = CommandContext.current.nextSecret() { return s }
	guard passphraseFromStdin else { throw VaultError.invalidArgument("--field-stdin requires --passphrase-stdin") }
	guard let l = readLine(strippingNewline: true) else {
		throw VaultError.invalidArgument("expected a passphrase on stdin (one secret per line)")
	}
	return l.hasSuffix("\r") ? String(l.dropLast()) : l
}

// `--passphrase-file` / $VAULT_PASSPHRASE_FILE, for unattended boxes. Refuses a symlink,
// anything but a regular file, a file owned by another user, and a file the group or
// others can read. The checks run on the opened descriptor, so the file can't be
// swapped between check and read. One trailing newline is dropped.
func readPassphraseFile(_ path: String) throws -> Data {
	#if os(Windows)
		throw VaultError.invalidArgument("--passphrase-file is not supported on Windows")
	#else
		// O_NONBLOCK: a FIFO must be refused by the fstat check below, not hang the open.
		let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
		guard fd >= 0 else {
			throw VaultError.invalidArgument(errno == ELOOP ? "passphrase file is a symlink; refused" : "cannot open passphrase file")
		}
		defer { close(fd) }
		var st = stat()
		guard fstat(fd, &st) == 0 else { throw VaultError.invalidArgument("cannot stat passphrase file") }
		let mode = UInt32(st.st_mode)
		guard mode & 0o170000 == 0o100000 else { throw VaultError.invalidArgument("passphrase file is not a regular file; refused") }
		guard st.st_uid == geteuid() else { throw VaultError.invalidArgument("passphrase file is owned by another user; refused") }
		guard mode & 0o077 == 0 else { throw VaultError.invalidArgument("passphrase file is readable by group or others; refused (chmod 600)") }
		var data = (try? FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd()) ?? Data()
		if data.last == 0x0A { data.removeLast() }
		if data.last == 0x0D { data.removeLast() }
		guard !data.isEmpty else { throw VaultError.invalidArgument("passphrase file is empty") }
		return data
	#endif
}

func readPassphrase(_ prompt: String = "Passphrase: ", useEnv: Bool = true) throws -> Data {
	// An explicit passphrase file wins over every other source; secondary prompts
	// (an item's own password) never read it, like $VAULT_PASSPHRASE.
	if useEnv, let f = CommandContext.current.passphraseFile { return try readPassphraseFile(f) }
	// Embedded: secrets are handed over as values, in the order the command asks.
	if CommandContext.current.hasQueue {
		if CommandContext.current.queueExhausted() { throw VaultError.invalidArgument("expected a passphrase (one secret per prompt)") }
		return Data((CommandContext.current.nextSecret() ?? "").utf8)
	}
	if passphraseFromStdin {
		guard let d = readLineBytes() else {
			throw VaultError.invalidArgument("expected a passphrase on stdin (one secret per line)")
		}
		return d
	}
	if useEnv, let e = envVars()["VAULT_PASSPHRASE"] { return Data(e.utf8) }
	guard isTerminal(0) else {
		throw VaultError.invalidArgument("no TTY and VAULT_PASSPHRASE unset; cannot read passphrase")
	}
	writeErr(prompt)
	#if os(Windows)
		// Console echo off for the read, restored after (the termios equivalent below).
		let h = GetStdHandle(STD_INPUT_HANDLE)
		var old: DWORD = 0
		let muted = GetConsoleMode(h, &old) && SetConsoleMode(h, old & ~DWORD(ENABLE_ECHO_INPUT))
		defer {
			if muted { _ = SetConsoleMode(h, old) }
			writeErr("\n")
		}
		guard let d = readLineBytes() else { throw VaultError.invalidArgument("passphrase entry cancelled") }
		return d
	#else
		var old = termios()
		tcgetattr(0, &old)
		var muted = old
		muted.c_lflag &= ~tcflag_t(ECHO)
		tcsetattr(0, TCSAFLUSH, &muted)
		defer {
			tcsetattr(0, TCSAFLUSH, &old)
			writeErr("\n")
		}
		// Ctrl-D / EOF must abort, never resolve to an empty secret.
		guard let d = readLineBytes() else { throw VaultError.invalidArgument("passphrase entry cancelled") }
		return d
	#endif
}

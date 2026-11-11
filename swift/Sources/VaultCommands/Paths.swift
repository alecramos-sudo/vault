import Foundation
import VaultCore

// OS config-dir resolution: VAULT_HOME, XDG_CONFIG_HOME, then
// platform defaults. Each vault is an independent replica at <config>/vaults/<name>.db.

let defaultVault = "personal"

func configDir() -> String { VaultPaths.configDir(environment: envVars()) }

// The config tree holds the encrypted replica and cleartext membership metadata:
// restrict it to the owner so another local user cannot copy it for offline attack.
private func ensureDir700(_ path: String) throws {
	try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
	try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: path)
}

private func vaultsDir() throws -> String {
	let cfg = configDir()
	try ensureDir700(cfg)
	let dir = (cfg as NSString).appendingPathComponent("vaults")
	try ensureDir700(dir)
	return dir
}

private func safeName(_ name: String) throws -> String {
	guard !name.isEmpty, name.unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) || ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "." || $0 == "_" || $0 == "-" }) else {
		throw VaultError.invalidArgument("invalid vault name: \(name)")
	}
	return name
}

func dbPath(_ name: String = defaultVault) throws -> String {
	(try vaultsDir() as NSString).appendingPathComponent("\(try safeName(name)).db")
}

func listVaultNames() throws -> [String] {
	try FileManager.default.contentsOfDirectory(atPath: try vaultsDir()).filter { $0.hasSuffix(".db") }
		.map { String($0.dropLast(3)) }.sorted()
}

// Run-only box (fleet): a marker file in the config dir. While it exists, only the
// commands that never print a secret run, `run` masks child output, and a `.env`
// may not declare the vault's own credential names. It guards against accidents by
// an agent on the box, not against someone who can edit the files. There is no
// command to turn it off: deleting the marker stops new replicas being stamped, but
// replicas already stamped stay run-only (the flag lives in their metadata).
func runOnlyMarkerPath() -> String { (configDir() as NSString).appendingPathComponent("run-only") }

// Run-only is on when the box-wide marker is in the current config dir, or when the
// replica this command would open carries the `runOnly` flag in its own metadata. The
// flag lives inside the database, so it follows the replica through any path to it
// (symlink, hard link, `..`, a moved VAULT_HOME, even a copy). Editing the database to
// clear it is deliberate tampering, which this mode does not claim to stop.
func isRunOnly(_ a: ParsedArgs? = nil) -> Bool {
	if FileManager.default.fileExists(atPath: runOnlyMarkerPath()) { return true }
	guard let a else { return false }
	let path = a.value("db") ?? (try? safeName(a.value("vault") ?? defaultVault)).map {
		(((configDir() as NSString).appendingPathComponent("vaults")) as NSString).appendingPathComponent("\($0).db")
	}
	guard let path, FileManager.default.fileExists(atPath: path) else { return false }
	// Read-only, so probing never changes the file. A probe that fails (busy, locked,
	// unreadable) counts as run-only: fail closed rather than allow a printing command.
	// do/catch, not `try?`: `try?` would flatten "flag absent" (nil) into a failure.
	do { return try Store.peekMeta(path: path, runOnlyMetaKey) == "1" } catch { return true }
}

let runOnlyMetaKey = "fleet.runOnly"

// Stamp a replica as run-only (idempotent).
func stampRunOnly(_ store: Store) throws {
	if try store.meta(runOnlyMetaKey) != "1" { try store.setMeta(runOnlyMetaKey, "1") }
}

// Writes the box-wide marker and stamps every replica in the config dir, plus an
// explicit `--db`. Replicas opened later on this box are stamped by `openStore`.
func enableRunOnly(_ a: ParsedArgs) throws {
	_ = try vaultsDir()  // creates the config dir at 0700
	// Stamp every replica first, then write the marker: a failure part way leaves no
	// marker claiming the box is run-only while some replica is still unstamped.
	var dbs = try listVaultNames().map { try dbPath($0) }
	if let db = a.value("db") { dbs.append(db) }
	for db in dbs where FileManager.default.fileExists(atPath: db) {
		let store = try Store(path: db)
		defer { store.close() }
		try stampRunOnly(store)
	}
	let path = runOnlyMarkerPath()
	guard FileManager.default.createFile(atPath: path, contents: Data("run-only\n".utf8), attributes: [.posixPermissions: 0o600])
	else { throw VaultError.invalidArgument("cannot write \(path)") }
}

// Commands allowed on a run-only box: none of them prints an item's value.
// `proxy` is left out: it forwards binary upstream responses unredacted.
let runOnlyCommands: Set<String> = ["run", "list", "vaults", "sync", "auth", "invite", "join", "device-confirm", "run-only"]

// Names a `.env` may not declare on a run-only box: declared values win over the
// stripped vault credentials, so a manifest could hand them to the child.
func isReservedEnvName(_ k: String) -> Bool {
	let u = k.uppercased()
	return u.hasPrefix("VAULT_") || u.hasPrefix("CF_ACCESS_")
}

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
// an agent on the box, not against someone who can delete the file. There is no
// command to turn it off: delete the file by hand.
func runOnlyMarkerPath() -> String { (configDir() as NSString).appendingPathComponent("run-only") }

func isRunOnly() -> Bool { FileManager.default.fileExists(atPath: runOnlyMarkerPath()) }

func enableRunOnly() throws {
	_ = try vaultsDir()  // creates the config dir at 0700
	let path = runOnlyMarkerPath()
	guard FileManager.default.createFile(atPath: path, contents: Data("run-only\n".utf8), attributes: [.posixPermissions: 0o600])
	else { throw VaultError.invalidArgument("cannot write \(path)") }
}

// Commands allowed on a run-only box: none of them prints an item's value.
let runOnlyCommands: Set<String> = ["run", "proxy", "list", "vaults", "sync", "auth", "invite", "join", "device-confirm", "run-only"]

// Names a `.env` may not declare on a run-only box: declared values win over the
// stripped vault credentials, so a manifest could hand them to the child.
func isReservedEnvName(_ k: String) -> Bool {
	let u = k.uppercased()
	return u.hasPrefix("VAULT_") || u.hasPrefix("CF_ACCESS_")
}

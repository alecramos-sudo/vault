import Foundation
import Testing

@testable import VaultCore

// Fleet hardening (agents#241, Bastion review 2026-11-10).
@Suite struct LowOrderPointTests {
	// Curve25519 u-coordinates of small order, little-endian: 0, 1, and a point of order 8.
	// Each makes the X25519 shared secret all zeros, whatever the private key.
	static let lowOrder: [Data] = [
		Data(repeating: 0, count: 32),
		Data([1] + [UInt8](repeating: 0, count: 31)),
		Data(hex: "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
	]

	@Test func x25519RejectsLowOrderPublicKeys() {
		let me = VaultCrypto.generateX25519()
		for pub in Self.lowOrder {
			#expect(throws: VaultCryptoError.invalidKey) { try VaultCrypto.x25519(me.privateKey, pub) }
		}
	}

	@Test func sealingToALowOrderKeyFails() {
		for pub in Self.lowOrder {
			#expect(throws: VaultCryptoError.self) { try SealedBoxes.seal(Data("v".utf8), to: pub) }
		}
	}

	@Test func normalKeysStillAgree() throws {
		let a = VaultCrypto.generateX25519(), b = VaultCrypto.generateX25519()
		#expect(try VaultCrypto.x25519(a.privateKey, b.publicKey) == VaultCrypto.x25519(b.privateKey, a.publicKey))
	}
}

extension Data {
	fileprivate init(hex: String) {
		var bytes: [UInt8] = []
		var i = hex.startIndex
		while i < hex.endIndex {
			let j = hex.index(i, offsetBy: 2)
			bytes.append(UInt8(hex[i..<j], radix: 16)!)
			i = j
		}
		self.init(bytes)
	}
}

#if !os(Windows)
	@testable import VaultCommands

	@Suite struct FleetCommandTests {
		private func home() -> String { NSTemporaryDirectory() + "vault-fleet-\(UUID().uuidString)" }

		private func run(_ h: String, _ a: [String], _ secrets: [String] = [], stdin: Bool = false) async -> VaultCommands.Output {
			await VaultCommands.execute(["--json"] + (stdin ? ["--passphrase-stdin"] : []) + a, secrets: secrets, environment: ["VAULT_HOME": h])
		}

		private func write(_ path: String, _ s: String, mode: Int) throws {
			try Data(s.utf8).write(to: URL(fileURLWithPath: path))
			try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: path)
		}

		@Test func passphraseFileUnlocksAndRefusesUnsafeFiles() async throws {
			let h = home()
			defer { try? FileManager.default.removeItem(atPath: h) }
			#expect(await run(h, ["init"], ["pw"], stdin: true).exitCode == 0)
			let f = h + "/pass"
			try write(f, "pw\n", mode: 0o600)
			let ok = await run(h, ["list", "--passphrase-file", f])
			#expect(ok.exitCode == 0)

			try write(f, "pw\n", mode: 0o640)
			let loose = await run(h, ["list", "--passphrase-file", f])
			#expect(loose.exitCode == 1 && loose.stdout.contains("group or others"))

			try write(f, "pw\n", mode: 0o600)
			let link = h + "/link"
			try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: f)
			let viaLink = await run(h, ["list", "--passphrase-file", link])
			#expect(viaLink.exitCode == 1 && viaLink.stdout.contains("symlink"))

			let dir = await run(h, ["list", "--passphrase-file", h])
			#expect(dir.exitCode == 1)

			try write(f, "wrong\n", mode: 0o600)
			#expect(await run(h, ["list", "--passphrase-file", f]).exitCode == 1)
		}

		@Test func runOnlyBlocksPrintingCommandsAndReservedNames() async throws {
			let h = home()
			defer { try? FileManager.default.removeItem(atPath: h) }
			#expect(await run(h, ["init"], ["pw"], stdin: true).exitCode == 0)
			#expect(await run(h, ["add", "--field-stdin", "1", "--", "store"], ["pw", "password=value-1"], stdin: true).exitCode == 0)
			#expect(await run(h, ["run-only"]).stdout.contains("\"runOnly\":false"))
			#expect(await run(h, ["run-only", "enable"]).exitCode == 0)

			for cmd in [["get", "--", "store"], ["get", "--field", "password", "--", "store"], ["totp", "--", "store"], ["edit", "--", "store"], ["rotate"]] {
				let r = await run(h, cmd, ["pw"], stdin: true)
				#expect(r.exitCode == 1 && r.stdout.contains("run-only"), "\(cmd)")
				#expect(!r.stdout.contains("value-1") && !r.stderr.contains("value-1"))
			}
			#expect(await run(h, ["list"], ["pw"], stdin: true).exitCode == 0)

			let env = h + "/.env"
			for name in ["VAULT_PASSPHRASE", "vault_relay_token", "CF_ACCESS_CLIENT_SECRET"] {
				try write(env, "\(name)=x\n", mode: 0o600)
				let r = await run(h, ["run", "--env", env, "--", "true"], ["pw"], stdin: true)
				#expect(r.exitCode == 1 && r.stdout.contains("may not declare"), "\(name)")
			}
		}
	}
#endif

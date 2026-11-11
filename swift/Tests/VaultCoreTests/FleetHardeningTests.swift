import Foundation
import Testing

@testable import VaultCore

// Fleet hardening (agents#241, Bastion review 2026-11-10).
@Suite struct ForcedScrubTests {
	@Test func forceMasksShortValues() {
		let s = Scrubber()
		s.register("1234")
		#expect(s.scrub("pin 1234") == "pin 1234")
		s.register("1234", force: true)
		#expect(s.scrub("pin 1234") == "pin [REDACTED]")
		s.register("", force: true)
		#expect(s.scrub("x") == "x")
	}
}

@Suite struct SinglePassScrubTests {
	@Test func shortPatternCannotSplitALongerSecret() {
		let s = Scrubber()
		s.register("ab", force: true)
		s.register("abcd-secret-123", force: true)
		#expect(s.scrub("x abcd-secret-123 y ab") == "x [REDACTED] y [REDACTED]")
	}

	@Test func overlappingSecretsAreCoveredAsOneSpan() {
		let s = Scrubber()
		s.register("ab", force: true)
		s.register("bcd-secret-123", force: true)
		#expect(s.scrub("abcd-secret-123") == "[REDACTED]")
		#expect(s.scrub("x ab y bcd-secret-123 z") == "x [REDACTED] y [REDACTED] z")
		let text = Array("..abcd-secret-123..ab".utf8)
		let whole = s.scrub(String(decoding: text, as: UTF8.self))
		for size in 1...text.count {
			let st = s.stream()
			var out = Data()
			var i = 0
			while i < text.count {
				out += st.feed(Data(text[i..<min(i + size, text.count)]))
				i += size
			}
			out += st.flush()
			#expect(String(decoding: out, as: UTF8.self) == whole, "chunk \(size)")
		}
	}

	@Test func markersAreNeverRescanned() {
		let s = Scrubber()
		for c in ["R", "E", "D", "A", "C", "T"] { s.register(c, force: true) }
		#expect(s.scrub("R") == "[REDACTED]")
		let st = s.stream()
		var out = st.feed(Data("E".utf8))
		out += st.feed(Data("\n".utf8))
		out += st.flush()
		#expect(String(decoding: out, as: UTF8.self) == "[REDACTED]\n")
	}

	@Test func streamEqualsOnePassAcrossEveryChunking() {
		let s = Scrubber()
		s.register("ab", force: true)
		s.register("abcd-secret-123", force: true)
		let text = Array("..abcd-secret-123..ab.abcd-secret-12.ab".utf8)
		let whole = s.scrub(String(decoding: text, as: UTF8.self))
		for size in 1...text.count {
			let st = s.stream()
			var out = Data()
			var i = 0
			while i < text.count {
				out += st.feed(Data(text[i..<min(i + size, text.count)]))
				i += size
			}
			out += st.flush()
			#expect(String(decoding: out, as: UTF8.self) == whole, "chunk \(size)")
		}
	}
}

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

		@Test func runOnlyHoldsWhenVaultHomeMovesButDbPointsBack() async throws {
			let h = home(), other = home()
			defer {
				try? FileManager.default.removeItem(atPath: h)
				try? FileManager.default.removeItem(atPath: other)
			}
			#expect(await run(h, ["init"], ["pw"], stdin: true).exitCode == 0)
			#expect(await run(h, ["add", "--field-stdin", "1", "--", "store"], ["pw", "password=value-1"], stdin: true).exitCode == 0)
			#expect(await run(h, ["run-only", "enable"]).exitCode == 0)
			let db = h + "/vaults/personal.db"
			let r = await VaultCommands.execute(
				["--json", "--passphrase-stdin", "--db", db, "get", "--field", "password", "--", "store"], secrets: ["pw"], environment: ["VAULT_HOME": other])
			#expect(r.exitCode == 1 && r.stdout.contains("run-only"))
			#expect(!r.stdout.contains("value-1"))
		}

		@Test func runOnlyHoldsThroughSymlinkedReplicas() async throws {
			let h = home(), other = home()
			defer {
				try? FileManager.default.removeItem(atPath: h)
				try? FileManager.default.removeItem(atPath: other)
			}
			#expect(await run(h, ["init"], ["pw"], stdin: true).exitCode == 0)
			#expect(await run(h, ["add", "--field-stdin", "1", "--", "store"], ["pw", "password=value-1"], stdin: true).exitCode == 0)
			#expect(await run(h, ["run-only", "enable"]).exitCode == 0)
			let fm = FileManager.default
			try fm.createDirectory(atPath: other, withIntermediateDirectories: true)
			try fm.createSymbolicLink(atPath: other + "/alias.db", withDestinationPath: h + "/vaults/personal.db")
			try fm.createSymbolicLink(atPath: other + "/replicas", withDestinationPath: h + "/vaults")
			try fm.createSymbolicLink(atPath: other + "/vaults", withDestinationPath: h + "/vaults")
			try fm.createDirectory(atPath: other + "/xdg/vault", withIntermediateDirectories: true)
			try fm.createSymbolicLink(atPath: other + "/xdg/vault/vaults", withDestinationPath: h + "/vaults")
			try fm.linkItem(atPath: h + "/vaults/personal.db", toPath: other + "/hard.db")
			try fm.copyItem(atPath: h + "/vaults/personal.db", toPath: other + "/copy.db")
			try fm.createDirectory(atPath: h + "/vaults/sub", withIntermediateDirectories: true)
			try fm.createSymbolicLink(atPath: other + "/up", withDestinationPath: h + "/vaults/sub")
			let get = ["get", "--field", "password", "--", "store"]
			for (extra, env) in [
				(["--db", other + "/alias.db"], ["VAULT_HOME": other]),
				(["--db", other + "/replicas/personal.db"], ["VAULT_HOME": other]),
				(["--vault", "personal"], ["VAULT_HOME": other]),
				(["--vault", "personal"], ["XDG_CONFIG_HOME": other + "/xdg", "VAULT_HOME": ""]),
				(["--db", other + "/hard.db"], ["VAULT_HOME": other]),
				(["--db", other + "/copy.db"], ["VAULT_HOME": other]),
				(["--db", other + "/up/../personal.db"], ["VAULT_HOME": other]),
				(["--db", "file:" + h + "/vaults/personal.db?mode=rw"], ["VAULT_HOME": other]),
				(["--db", "FILE:" + h + "/vaults/personal.db"], ["VAULT_HOME": other]),
			] {
				let r = await VaultCommands.execute(["--json", "--passphrase-stdin"] + extra + get, secrets: ["pw"], environment: env)
				#expect(r.exitCode == 1 && (r.stdout.contains("run-only") || r.stdout.contains("not a SQLite URI")), "\(extra)")
				#expect(!r.stdout.contains("value-1"))
			}
		}

		@Test func probingRunOnlyNeverChangesTheFile() async throws {
			let h = home()
			defer { try? FileManager.default.removeItem(atPath: h) }
			try FileManager.default.createDirectory(atPath: h, withIntermediateDirectories: true)
			let other = h + "/relay.db"
			try Data("not a replica".utf8).write(to: URL(fileURLWithPath: other))
			try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: other)
			let before = try Data(contentsOf: URL(fileURLWithPath: other))
			_ = await run(h, ["list", "--db", other], ["pw"], stdin: true)
			#expect(try Data(contentsOf: URL(fileURLWithPath: other)) == before)
			#expect(Store.peekMeta(path: other, runOnlyMetaKey) == nil)
		}

		@Test func runOnlyRefusesProxy() async throws {
			let h = home()
			defer { try? FileManager.default.removeItem(atPath: h) }
			#expect(await run(h, ["init"], ["pw"], stdin: true).exitCode == 0)
			#expect(await run(h, ["run-only", "enable"]).exitCode == 0)
			let r = await run(h, ["proxy", "--config", h + "/p.env"], ["pw"], stdin: true)
			#expect(r.exitCode == 1 && r.stdout.contains("run-only"))
		}

		@Test func passphraseFifoIsRefusedNotHung() async throws {
			let h = home()
			defer { try? FileManager.default.removeItem(atPath: h) }
			#expect(await run(h, ["init"], ["pw"], stdin: true).exitCode == 0)
			let fifo = h + "/pass.fifo"
			#expect(mkfifo(fifo, 0o600) == 0)
			let r = await run(h, ["list", "--passphrase-file", fifo])
			#expect(r.exitCode == 1 && r.stdout.contains("not a regular file"))
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

#if !os(Windows)  // relay + /bin/sh: macOS + Linux only (see Package.swift)
import Foundation
import Testing

@testable import VaultCommands
@testable import VaultCore
@testable import VaultNet

private let kdf = KdfParams.scrypt(salt: Data(repeating: 7, count: 16), n: 1024, r: 8, p: 1, length: 32)
private let pass = Data("pw".utf8)

private func mem() throws -> Store { try Store(path: ":memory:") }

// Move a replica's logical state to another store the way a relay round would.
private func copyAll(_ from: Store, _ to: Store) throws {
	for e in try from.authLog() where e.body.type != "genesis" { try to.appendAuthEntry(e) }
	for r in try from.rotations() { if let p = RotationRecord.parse(r) { try to.putRotation(epoch: p.epoch, deviceId: p.deviceId, record: r) } }
	try to.putOps(try from.allOps())
}

// What a modified binary on the reader's box could do: encrypt a field op under the
// current key and sign the envelope with the reader's device key.
private func forgeOp(_ e: VaultEngine, _ op: FieldOp, seq: Int) async throws -> OpEnvelope {
	let commit = await e.currentKeyCommit
	let key = try #require(await e.keys[commit])
	let box = try key.withData { try VaultCrypto.aeadEncrypt(key: $0, plaintext: op.json.serialized()) }
	let b = VaultCrypto.encodeBox(box)
	let payload = JSONValue.obj(["keyCommit": .string(commit), "iv": .string(b.iv), "ct": .string(b.ct), "tag": .string(b.tag)]).serialized()
	let deviceId = await e.deviceId
	return try await e.priv.deviceSign.withData {
		try WireProtocol.makeEnvelope(deviceId: deviceId, seq: seq, payload: payload, signPriv: $0)
	}
}

private func snapshot(_ e: VaultEngine) async -> [String] {
	await e.listItems().map { "\($0.itemId)|\($0.fields.sorted { $0.key < $1.key })|\($0.passwords)" }.sorted()
}

@Suite struct ReaderRoleTests {
	// owner + member + reader, all converged.
	private func vault() async throws -> (so: Store, sm: Store, sr: Store, owner: VaultEngine, member: VaultEngine, reader: VaultEngine) {
		let so = try mem(), sm = try mem(), sr = try mem()
		_ = try await VaultEngine.initialize(store: so, password: pass, kdf: kdf)
		let owner = try await VaultEngine.unlock(store: so, password: pass)
		try await owner.addItem(title: "gh", fields: [("username", "octo"), ("password", "pw1")])
		let im = try VaultEngine.inviteInit(store: sm, password: pass, kdf: kdf)
		_ = try await VaultEngine.joinConfirm(store: sm, password: pass, token: try await owner.shareVault(im, role: .member))
		let ir = try VaultEngine.inviteInit(store: sr, password: pass, kdf: kdf)
		_ = try await VaultEngine.joinConfirm(store: sr, password: pass, token: try await owner.shareVault(ir, role: .reader))
		for s in [sm, sr] { try copyAll(s, so) }
		for s in [sm, sr] { try copyAll(so, s) }
		try await owner.rebuildSession()
		return (so, sm, sr, owner, try await VaultEngine.unlock(store: sm, password: pass), try await VaultEngine.unlock(store: sr, password: pass))
	}

	@Test func readerReadsResolvesButCannotWriteOrAdminister() async throws {
		let v = try await vault()
		#expect(await v.reader.role == .reader)
		#expect(await v.member.role == .member)
		#expect(await v.reader.listItems().map(\.title) == ["gh"])
		#expect(await v.reader.item(title: "gh")?.passwords == ["pw1"])
		let envFile = NSTemporaryDirectory() + "reader-\(UUID().uuidString).env"
		defer { try? FileManager.default.removeItem(atPath: envFile) }
		try "GH=vault://personal/gh\nGH_USER=vault://personal/gh/username\n".write(toFile: envFile, atomically: true, encoding: .utf8)
		let r = try await v.reader.resolveEnv(envFile: envFile, openVault: "personal")
		#expect(r.missing.isEmpty && r.env.map(\.1) == ["pw1", "octo"])

		// Local writes are refused with notAuthorized and leave the replica untouched.
		let before = try v.sr.allOps().count
		await #expect(throws: VaultError.self) { try await v.reader.addItem(title: "new", fields: [("password", "x")]) }
		await #expect(throws: VaultError.self) { try await v.reader.editItem(title: "gh", fields: [("password", "x")]) }
		await #expect(throws: VaultError.self) { try await v.reader.removeItem(title: "gh") }
		do {
			try await v.reader.addItem(title: "new")
			Issue.record("reader add succeeded")
		} catch let VaultError.notAuthorized(msg) { #expect(msg.contains("reader")) }
		#expect(try v.sr.allOps().count == before)

		// No rotation, sharing, user management or sibling devices.
		await #expect(throws: VaultError.self) { try await v.reader.rotate() }
		let other = try VaultEngine.inviteInit(store: try mem(), password: pass, kdf: kdf)
		await #expect(throws: VaultError.self) { try await v.reader.shareVault(other, role: .reader) }
		await #expect(throws: VaultError.self) { try await v.reader.removeUser(await v.member.userId) }
		await #expect(throws: VaultError.self) { try await v.reader.removeDevice(await v.member.deviceId) }
		let a = try VaultEngine.authNewDevice(store: try mem(), password: pass, kdf: kdf)
		let authBefore = try v.sr.authLog().count
		await #expect(throws: VaultError.self) { try await v.reader.deviceAdd(a) }
		#expect(try v.sr.authLog().count == authBefore)

		// A forged add-device for the reader's own user, signed by its device, is not
		// admitted by the log; an owner device enrolling for the reader (recovery) is.
		let readerUser = await v.reader.userId, vaultId = await v.owner.vaultId
		let sibling = try VaultEngine.signedEntry(
			try v.so.authLog(), .addDevice(userId: readerUser, deviceId: a.deviceId, deviceSignPub: a.signPub, deviceEncPub: a.encPub),
			signerId: await v.reader.deviceId, kind: .device, priv: await v.reader.priv.deviceSign)
		#expect(AuthLog.admissible([sibling], existing: try v.so.authLog(), expectedVaultId: vaultId).isEmpty)
		let byOwner = try VaultEngine.signedEntry(
			try v.so.authLog(), .addDevice(userId: readerUser, deviceId: a.deviceId, deviceSignPub: a.signPub, deviceEncPub: a.encPub),
			signerId: await v.owner.deviceId, kind: .device, priv: await v.owner.priv.deviceSign)
		#expect(AuthLog.admissible([byOwner], existing: try v.so.authLog(), expectedVaultId: vaultId).count == 1)

		// Readers still receive the next epoch's key.
		_ = try await v.owner.rotate()
		try copyAll(v.so, v.sr)
		try await v.reader.rebuildSession()
		let commit = await v.reader.currentKeyCommit
		let hasKey = await v.reader.keys[commit] != nil
		#expect(await v.reader.currentEpoch == 2 && hasKey)
		#expect(await v.reader.item(title: "gh")?.passwords == ["pw1"])
	}

	@Test func forgedReaderOpsAreRejectedByEveryReplicaAndRelay() async throws {
		let v = try await vault()
		let gh = try #require(await v.owner.item(title: "gh"))
		let live = await v.owner.state.livePasswordHlcs(gh.itemId)
		let hlc = try HLCCodec.encode(HLC(millis: HLCCodec.nowMillis(), counter: 0, deviceId: await v.reader.deviceId))
		let forged = [
			try await forgeOp(v.reader, FieldOp(itemId: gh.itemId, field: "password", value: "evil", hlc: hlc, replaces: live), seq: 1),
			try await forgeOp(v.reader, ItemOps.delete(itemId: gh.itemId, hlc: hlc), seq: 2),
		]
		let ownerBefore = await snapshot(v.owner)

		// A relay that does not know the role (an upstream relay or Worker) holds the
		// forged ops; the owner's sync round still refuses to store or apply them.
		let rstore = try RelayStore(path: ":memory:")
		let open = RelayDeps(authorize: { _ in true }, verifyOp: { _, _ in true }, verifyRotation: { _, _ in true }, verifyGrant: { _, _ in false })
		let server = try await HTTPServer.start(host: "127.0.0.1", port: 0) { req in
			let r = await RelayHandler.handle(RelayRequest(method: req.method, path: req.path, headers: req.headers, body: req.body), store: rstore, deps: open)
			return .json(r.status, r.body.serialized())
		}
		defer { Task { await server.stop() } }
		let url = "http://127.0.0.1:\(server.port)"
		try await v.owner.syncWithRelay(url: url)
		let team = await v.owner.vaultId
		for op in forged { #expect(try rstore.putOp(team, op)) }
		let stats = try await v.owner.syncWithRelay(url: url)
		#expect(stats.pulled == 0)
		#expect(try v.so.maxSeq(for: await v.reader.deviceId) == 0)
		#expect(await snapshot(v.owner) == ownerBefore)

		// Even when the ops reach the replica's store directly (a tailnet peer, an older
		// copy), replay ignores them and the replica stays usable.
		try v.so.putOps(forged)
		try await v.owner.rebuildSession()
		#expect(await snapshot(v.owner) == ownerBefore)
		#expect(await v.owner.item(title: "gh")?.passwords == ["pw1"])
		// A rotation does not launder them by re-encrypting them under the owner's key.
		_ = try await v.owner.rotate()
		#expect(await snapshot(v.owner) == ownerBefore)
		try await v.owner.addItem(title: "after", fields: [("k", "v")])
		#expect(await v.owner.item(title: "after") != nil)

		// The fork's relay refuses them at push; a member's real op is still accepted.
		let fork = RelayServer.deps(store: rstore, access: AccessVerifier(AccessConfig()))
		func push(_ ops: [OpEnvelope]) async -> Int64? {
			let body = JSONValue.object([JSONMember("teamId", .string(team)), JSONMember("ops", .array(ops.map(\.json)))]).serialized()
			return await RelayHandler.handle(RelayRequest(method: "POST", path: "/push", headers: [:], body: body), store: rstore, deps: fork).body["accepted"]?.int
		}
		let forged2 = try await forgeOp(v.reader, ItemOps.delete(itemId: gh.itemId, hlc: hlc), seq: 3)
		#expect(await push([forged2]) == 0)
		try await v.member.editItem(title: "gh", fields: [("username", "member-edit")])
		let memberDevice = await v.member.deviceId
		let memberOps = try v.sm.allOps().filter { $0.deviceId == memberDevice }
		#expect(await push(memberOps) == Int64(memberOps.count))
	}

	@Test func memberWritesAreUnchanged() async throws {
		let v = try await vault()
		try await v.member.editItem(title: "gh", fields: [("username", "member-edit")])
		try await v.member.addItem(title: "m", fields: [("k", "v")])
		try copyAll(v.sm, v.so)
		try await v.owner.rebuildSession()
		#expect(await v.owner.item(title: "gh")?.fields["username"] == "member-edit")
		#expect(await v.owner.item(title: "m")?.fields["k"] == "v")
		// The reader sees the member's writes too.
		try copyAll(v.so, v.sr)
		try await v.reader.rebuildSession()
		#expect(await v.reader.item(title: "m")?.fields["k"] == "v")
		try await v.member.removeItem(title: "m")
		// A member device still enrolls its own sibling.
		let a = try VaultEngine.authNewDevice(store: try mem(), password: pass, kdf: kdf)
		_ = try await v.member.deviceAdd(a)
	}

	// The CLI end to end: share --role reader, join, then read and run but never write.
	@Test func cliShareReaderJoinAndRefuseWrites() async throws {
		let ho = NSTemporaryDirectory() + "vault-reader-o-\(UUID().uuidString)"
		let hr = NSTemporaryDirectory() + "vault-reader-r-\(UUID().uuidString)"
		defer { for h in [ho, hr] { try? FileManager.default.removeItem(atPath: h) } }
		func run(_ h: String, _ a: [String], _ secrets: [String] = ["pw"]) async -> (Int32, JSONValue?) {
			let r = await VaultCommands.execute(["--json", "--passphrase-stdin"] + a, secrets: secrets, environment: ["VAULT_HOME": h])
			return (r.exitCode, try? JSONValue.parse(r.stdout.split(separator: "\n").first.map(String.init) ?? ""))
		}
		#expect(await run(ho, ["init"]).0 == 0)
		#expect(await run(ho, ["add", "--password", "--", "gh"], ["pw", "pw1"]).0 == 0)
		let (_, inv) = await run(hr, ["invite"])
		let invite = try #require(inv?["inviteToken"]?.string)
		#expect(await run(ho, ["share", "--token", invite, "--role", "bogus"]).0 == 1)
		let (cs, share) = await run(ho, ["share", "--token", invite, "--role", "reader"])
		#expect(cs == 0)
		let (cj, _) = await run(hr, ["join", "--token", try #require(share?["joinToken"]?.string)])
		#expect(cj == 0)
		// Stand in for a relay round between the two replicas.
		let so = try Store(path: ho + "/vaults/personal.db"), sr = try Store(path: hr + "/vaults/personal.db")
		try copyAll(sr, so)
		try copyAll(so, sr)
		so.close()
		sr.close()

		let (cl, list) = await run(hr, ["list"])
		#expect(cl == 0 && list?["items"]?.array?.count == 1)
		let env = hr + "/app.env"
		try "GH=vault://personal/gh\n".write(toFile: env, atomically: true, encoding: .utf8)
		#expect(await run(hr, ["run", "--env", env, "--", "/bin/sh", "-c", "test \"$GH\" = pw1"]).0 == 0)

		// Refused before the item password is read: only the passphrase is supplied.
		let (ca, add) = await run(hr, ["add", "--password", "--", "new"])
		#expect(ca == 1 && add?["error"]?.string?.contains("reader") == true)
		#expect(await run(hr, ["edit", "gh", "--field", "a=b"]).0 == 1)
		#expect(await run(hr, ["rm", "gh"]).0 == 1)
		#expect(await run(hr, ["rotate"]).0 == 1)
		let tokenA = try VaultEngine.authNewDevice(store: try mem(), password: pass, kdf: kdf)
		#expect(await run(hr, ["device-add", "--token", tokenA.encoded]).0 == 1)
		let (_, list2) = await run(ho, ["list"])
		#expect(list2?["items"]?.array?.count == 1)
	}
}
#endif

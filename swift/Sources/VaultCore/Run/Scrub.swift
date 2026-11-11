import Foundation

// Last-line-of-defense secret redaction. The primary rule stays
// "never put a secret in a message"; this is the backstop for output we don't
// author (a child that echoes an injected value). Best-effort: exotic encodings
// and values shorter than `minLength` pass through.

public final class Scrubber: @unchecked Sendable {
	public static let redaction = "[REDACTED]"
	static let minLength = 6

	private let lock = NSLock()
	private var patterns: [[UInt8]] = []
	private var seen = Set<[UInt8]>()

	public init() {}

	private func add(_ s: String) {
		let b = Array(s.utf8)
		guard !b.isEmpty, seen.insert(b).inserted else { return }
		patterns.append(b)
	}

	private static func percentEncode(_ s: String, keep: String, spaceAsPlus: Bool) -> String {
		var out = ""
		for byte in s.utf8 {
			let c = Character(Unicode.Scalar(byte))
			if byte < 0x80, c.isASCII, c.isLetter || c.isNumber || keep.contains(c) {
				out.append(c)
			} else if spaceAsPlus && byte == 0x20 {
				out.append("+")
			} else {
				out += "%" + String(format: "%02X", byte)
			}
		}
		return out
	}

	// Register a value plus the encodings it commonly travels under.
	// `force` registers values shorter than `minLength` too (run-only boxes, where an
	// unmasked short secret is worse than over-redacted output).
	public func register(_ value: String, force: Bool = false) {
		guard !value.isEmpty, force || value.count >= Self.minLength else { return }
		lock.lock()
		defer { lock.unlock() }
		add(value)
		add(Self.percentEncode(value, keep: "-_.!~*'()", spaceAsPlus: false))  // encodeURIComponent
		add(Self.percentEncode(value, keep: "*-._", spaceAsPlus: true))  // x-www-form-urlencoded
		add(Self.percentEncode(value, keep: "-._~", spaceAsPlus: false))  // strict RFC 3986 (the proxy's query form)
		add(String(JSONValue.string(value).stringify().dropFirst().dropLast()))  // JSON-escaped
		add(Data(value.utf8).base64)  // Basic-auth form
	}

	// One left-to-right pass over the ORIGINAL bytes. Every position is checked, even
	// inside a redacted span, and a match there extends the span, so overlapping
	// secrets ("ab" + "bcd-secret") are covered as one union and nothing leaks between
	// them. One marker per span; markers are output, never rescanned. New matches
	// start only before `limit`. `skip` is how many leading bytes are already inside
	// a span (marker emitted). Returns output, where it stopped, and the bytes of the
	// open span past that point.
	fileprivate func redactPrefix(_ hay: [UInt8], upTo limit: Int, skip: Int = 0) -> ([UInt8], Int, Int) {
		let marker = Array(Self.redaction.utf8)
		var out: [UInt8] = []
		out.reserveCapacity(hay.count)
		var spanEnd = skip
		var i = 0
		while i < limit {
			var best = 0
			for p in patterns where p.count > best && i + p.count <= hay.count && hay[i] == p[0] && hay[i..<i + p.count].elementsEqual(p) {
				best = p.count
			}
			if i < spanEnd {
				spanEnd = max(spanEnd, i + best)
			} else if best > 0 {
				out += marker
				spanEnd = i + best
			} else {
				out.append(hay[i])
			}
			i += 1
		}
		return (out, i, max(0, spanEnd - i))
	}

	private func redact(_ bytes: [UInt8]) -> [UInt8] {
		guard !patterns.isEmpty else { return bytes }
		return redactPrefix(bytes, upTo: bytes.count).0
	}

	// Scrub a short string (error messages, audit lines).
	public func scrub(_ text: String) -> String {
		lock.lock()
		defer { lock.unlock() }
		return patterns.isEmpty ? text : String(decoding: redact(Array(text.utf8)), as: UTF8.self)
	}

	// Streaming, binary-safe form: holds back only the tail that could begin a
	// not-yet-complete match.
	public final class Stream: @unchecked Sendable {
		private let owner: Scrubber
		private var carry: [UInt8] = []
		private var skip = 0  // leading carry bytes already inside a redacted span
		init(_ o: Scrubber) { owner = o }

		// Holds back raw input (never redacted output): a match can only start where
		// every pattern still fits inside what has arrived, so the result equals one
		// pass over the whole stream.
		public func feed(_ chunk: Data) -> Data {
			owner.lock.lock()
			defer { owner.lock.unlock() }
			if owner.patterns.isEmpty && carry.isEmpty && skip == 0 { return chunk }
			let buf = carry + Array(chunk)
			let maxLen = owner.patterns.map(\.count).max() ?? 0
			let (out, next, open) = owner.redactPrefix(buf, upTo: buf.count - max(0, maxLen - 1), skip: skip)
			carry = Array(buf[next...])
			skip = open
			return Data(out)
		}

		public func flush() -> Data {
			owner.lock.lock()
			defer { owner.lock.unlock() }
			let out = owner.redactPrefix(carry, upTo: carry.count, skip: skip).0
			carry = []
			skip = 0
			return Data(out)
		}
	}

	public func stream() -> Stream { Stream(self) }
}

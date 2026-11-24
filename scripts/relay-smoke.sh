#!/usr/bin/env bash
#
# Smoke test for a built vault binary: start a relay on loopback, then have one vault
# sync with it several times. `swift test` covers the same path in a debug build; this
# runs the binary we ship (release, static runtime), where the networking stack differs.
#
# Usage: scripts/relay-smoke.sh <path-to-vault>
#
set -euo pipefail

[[ $# -eq 1 ]] || {
	echo "usage: $0 <path-to-vault>" >&2
	exit 2
}
vault="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
[[ -x "$vault" ]] || {
	echo "relay-smoke: $1 is not executable" >&2
	exit 2
}

work="$(mktemp -d)"
relay_pid=""
cleanup() {
	[[ -n "$relay_pid" ]] && kill "$relay_pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

umask 077
printf 'smoke-relay-token\n' >"$work/relay-token"
printf 'smoke-passphrase\n' >"$work/passphrase"

# Port 0: the relay picks a free port and prints it.
VAULT_RELAY_TOKENS=smoke-relay-token "$vault" relay --host 127.0.0.1 --port 0 --db "$work/relay.db" >"$work/relay.log" 2>&1 &
relay_pid=$!
port=""
for _ in $(seq 1 50); do
	port="$(sed -n 's/^relay listening on 127\.0\.0\.1:\([0-9][0-9]*\)$/\1/p' "$work/relay.log")"
	[[ -n "$port" ]] && break
	kill -0 "$relay_pid" 2>/dev/null || {
		cat "$work/relay.log" >&2
		echo "relay-smoke: relay exited before listening" >&2
		exit 1
	}
	sleep 0.2
done
[[ -n "$port" ]] || {
	cat "$work/relay.log" >&2
	echo "relay-smoke: relay did not report a port" >&2
	exit 1
}

v() { "$vault" --db "$work/client.db" --passphrase-file "$work/passphrase" "$@"; }
v init >/dev/null
v add smoke-item --field note=hello >/dev/null
for round in 1 2 3; do
	if ! v sync --relay "http://127.0.0.1:$port" --relay-token-file "$work/relay-token"; then
		echo "relay-smoke: sync round $round failed" >&2
		exit 1
	fi
done
echo "relay-smoke: ok (3 sync rounds against 127.0.0.1:$port)"

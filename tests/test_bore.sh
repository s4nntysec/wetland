#!/usr/bin/env bash
#
# wetland — bore-style auto-tunnel test.
#
# Exercises the zero-config listener: embedded relay + bore reverse-tunnel
# client, against a local stand-in bore server (tests/fakebore.py) that speaks
# bore's wire protocol. Needs python3; skips cleanly if it is missing.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WLD="$ROOT/bin/wld"
FAKE="$ROOT/tests/fakebore.py"
WORK="$(mktemp -d)"
FAILS=0

if ! command -v python3 >/dev/null 2>&1; then
	echo "bore: python3 not found — skipping"
	exit 0
fi

BORE_PORT=$(( (RANDOM % 20000) + 20000 ))

cleanup() {
	[ -n "${FB:-}" ] && kill "$FB" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; FAILS=$((FAILS+1)); }

echo "bore (fake server on 127.0.0.1:$BORE_PORT):"

python3 "$FAKE" "$BORE_PORT" > "$WORK/bore.log" 2>&1 &
FB=$!
# wait for the fake bore control port
for _ in $(seq 1 50); do
	(exec 3<>"/dev/tcp/127.0.0.1/$BORE_PORT") 2>/dev/null && { exec 3>&-; break; }
	sleep 0.1
done

# No relay configured -> wld must auto-start embedded relay + bore tunnel.
export WLD_BORE_HOST=127.0.0.1 WLD_BORE_PORT="$BORE_PORT"
unset WLD_RELAY_HOST WLD_RELAY_PORT WLD_RELAY_POOL

getpub() { # $1 = logfile -> prints assigned public port
	local p=""
	for _ in $(seq 1 60); do
		p=$(grep -oE '\-p [0-9]+' "$1" | head -1 | awk '{print $2}')
		[ -n "$p" ] && break
		sleep 0.1
	done
	echo "$p"
}

# --- 1: connector -> listener (forward) through the tunnel ---
head -c 200000 /dev/urandom > "$WORK/f_in"
timeout 20 "$WLD" -s fwd -l < /dev/null > "$WORK/f_out" 2>"$WORK/l1" &
L=$!
P=$(getpub "$WORK/l1")
if [ -n "$P" ]; then
	timeout 15 "$WLD" -s fwd -H 127.0.0.1 -p "$P" -w < "$WORK/f_in" >/dev/null 2>/dev/null
	wait "$L" 2>/dev/null
	cmp -s "$WORK/f_in" "$WORK/f_out" && pass "forward 200KB through bore tunnel" \
		|| fail "forward transfer ($(wc -c <"$WORK/f_out")B of 200000)"
else
	kill "$L" 2>/dev/null
	fail "listener never reported a public port (tunnel did not come up)"
fi

# --- 2: listener -> connector (reverse) through the tunnel ---
head -c 170000 /dev/urandom > "$WORK/r_in"
timeout 20 "$WLD" -s rev -l < "$WORK/r_in" >/dev/null 2>"$WORK/l2" &
L=$!
P=$(getpub "$WORK/l2")
if [ -n "$P" ]; then
	timeout 15 "$WLD" -s rev -H 127.0.0.1 -p "$P" -w < /dev/null > "$WORK/r_out" 2>/dev/null
	wait "$L" 2>/dev/null
	cmp -s "$WORK/r_in" "$WORK/r_out" && pass "reverse 170KB through bore tunnel (drain OK)" \
		|| fail "reverse transfer ($(wc -c <"$WORK/r_out")B of 170000)"
else
	kill "$L" 2>/dev/null
	fail "listener never reported a public port (reverse)"
fi

# --- 3: exec round-trip through the tunnel ---
timeout 20 "$WLD" -s exc -l -e 'tr a-z A-Z' 2>"$WORK/l3" &
L=$!
P=$(getpub "$WORK/l3")
if [ -n "$P" ]; then
	OUT=$(printf 'hello bore\n' | timeout 15 "$WLD" -s exc -H 127.0.0.1 -p "$P" -w 2>/dev/null)
	wait "$L" 2>/dev/null
	[ "$OUT" = "HELLO BORE" ] && pass "exec round-trip through bore tunnel" \
		|| fail "exec round-trip (got '$OUT')"
else
	kill "$L" 2>/dev/null
	fail "listener never reported a public port (exec)"
fi

echo
if [ "$FAILS" -eq 0 ]; then
	echo "ALL BORE TESTS PASSED"
else
	echo "$FAILS BORE TEST(S) FAILED"
	exit 1
fi

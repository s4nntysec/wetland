#!/usr/bin/env bash
#
# wetland — end-to-end test: relay + two clients on localhost.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WLD="$ROOT/bin/wld"
RELAY="$ROOT/bin/wetland-relay"
PORT=$(( (RANDOM % 20000) + 20000 ))
WORK="$(mktemp -d)"
FAILS=0

cleanup() {
	[ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; FAILS=$((FAILS+1)); }

echo "e2e (relay port $PORT):"

# --- start relay ---
"$RELAY" -p "$PORT" >/dev/null 2>&1 &
RELAY_PID=$!
for _ in $(seq 1 50); do
	(exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && { exec 3>&-; break; }
	sleep 0.1
done

export WLD_RELAY_HOST=127.0.0.1
export WLD_RELAY_PORT="$PORT"

# --- test 1: file transfer (connector stdin -> listener stdout) ---
head -c 200000 /dev/urandom > "$WORK/in.bin"
SEC="secret-file-xfer-$$"
timeout 15 "$WLD" -s "$SEC" -l < /dev/null > "$WORK/out.bin" 2>/dev/null &
LPID=$!
sleep 0.4
timeout 15 "$WLD" -s "$SEC" -w < "$WORK/in.bin" >/dev/null 2>&1
wait $LPID 2>/dev/null
if cmp -s "$WORK/in.bin" "$WORK/out.bin"; then
	pass "200 KB file transferred intact through the tunnel"
else
	fail "file transfer (sizes: in=$(wc -c <"$WORK/in.bin") out=$(wc -c <"$WORK/out.bin" 2>/dev/null))"
fi

# --- test 2: exec mode (bidirectional) ---
SEC2="secret-exec-$$"
timeout 15 "$WLD" -s "$SEC2" -l -e 'tr a-z A-Z' >/dev/null 2>&1 &
sleep 0.4
OUT=$(echo "hello wetland" | timeout 15 "$WLD" -s "$SEC2" -w 2>/dev/null)
if [ "$OUT" = "HELLO WETLAND" ]; then
	pass "exec mode round-trips data bidirectionally"
else
	fail "exec mode (got: '$OUT')"
fi

# --- test 3: wrong secret -> different rendezvous address -> no pairing ---
# (The cryptographic MITM/auth rejection is covered directly in test_crypto.)
timeout 15 "$WLD" -s "right-secret-$$" -l < /dev/null >/dev/null 2>&1 &
WPID=$!
sleep 0.4
echo data | timeout 10 "$WLD" -s "wrong-secret-$$" >/dev/null 2>&1
RC=$?
kill $WPID 2>/dev/null; wait $WPID 2>/dev/null
if [ "$RC" -ne 0 ] && [ "$RC" -ne 124 ]; then
	pass "mismatched secret -> peers never meet, connect fails (rc=$RC)"
else
	fail "mismatched secret was NOT rejected (rc=$RC)"
fi

# --- test 4: no listener without -w fails fast ---
echo x | timeout 10 "$WLD" -s "nobody-home-$$" >/dev/null 2>&1
if [ $? -ne 0 ]; then
	pass "connect with no listener fails cleanly"
else
	fail "connect with no listener should have failed"
fi

# --- test 5: concurrent pairs are isolated and intact ---
LPIDS=""; CPIDS=""
for i in 1 2 3; do
	head -c 300000 /dev/urandom > "$WORK/m$i.in"
	timeout 20 "$WLD" -s "multi$i-$$" -l < /dev/null > "$WORK/m$i.out" 2>/dev/null &
	LPIDS="$LPIDS $!"
done
sleep 0.5
for i in 1 2 3; do
	timeout 20 "$WLD" -s "multi$i-$$" -w < "$WORK/m$i.in" >/dev/null 2>&1 &
	CPIDS="$CPIDS $!"
done
for pid in $CPIDS $LPIDS; do wait "$pid" 2>/dev/null; done
MOK=0
for i in 1 2 3; do cmp -s "$WORK/m$i.in" "$WORK/m$i.out" && MOK=$((MOK+1)); done
if [ "$MOK" -eq 3 ]; then
	pass "3 concurrent pairs stayed isolated and intact"
else
	fail "concurrent pairs ($MOK/3 intact)"
fi

echo
if [ "$FAILS" -eq 0 ]; then
	echo "ALL E2E TESTS PASSED"
	exit 0
else
	echo "E2E TESTS FAILED ($FAILS)"
	exit 1
fi

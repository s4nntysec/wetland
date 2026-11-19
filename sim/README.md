# wetland — SOC detection scenarios (OpenAEV / OpenBAS)

Two **breach-and-attack-simulation scenarios** that exercise the **real wetland
tool** so a SOC can validate it detects the tool's activity. Every inject
downloads `wld` from the **v0.1.0 GitHub Release** and runs it a different way —
this is a detection test of the tool itself, not a stand-in.

- `wetland-soc-detection-linux.openaev.zip` — Linux assets (`bash`/`sh`)
- `wetland-soc-detection-windows.openaev.zip` — Windows assets (`psh`)

> **Import the `.zip`, not the `.json`.** OpenAEV reads a ZIP whose single entry
> carries the zip **entry comment `Scenario`** — a bare `.json` can be rejected.
> The `.json` is included only for review. The envelope + injector-contract
> scaffolding were templated from a real export of a ThreatOps/OpenAEV instance,
> so the field set, domain id and implant-injector ids match the platform.

> ⚠️ **Authorized lab use only.** Every inject is loud, tags its artifacts with
> `WETLAND-LAB`, prints an ATT&CK-mapped detection hint, and ships a **cleanup
> command** OpenAEV runs afterwards. The goal is detectable telemetry.

Pulled from:
`https://github.com/s4nntysec/wetland/releases/download/v0.1.0/wld-linux-x86_64`
and `…/wld-windows-x86_64.exe` (saved as `wld.exe`).

## Linux injects — the `wld lab` techniques + the C2 channel

| # | delay | Inject | wld invocation | ATT&CK |
|---|-------|--------|----------------|--------|
| 1 | 0s   | Ingress + exec | download + `wld -h` (SHA256) | T1105 / T1059.004 |
| 2 | 60s  | Masquerade | `wld lab masquerade --name '[kworker/0:0]'` | T1036.004/.005 |
| 3 | 120s | Persistence | `wld lab persist --method both` | T1053.003 / T1543.002 |
| 4 | 180s | Hidden + timestomp | `wld lab hide` | T1564.001 / T1070.006 |
| 5 | 240s | C2 beacon | `wld lab beacon --to RELAY --as http` | T1071.001 / T1571 / T1008 |
| 6 | 300s | Encrypted C2 channel | `wld -s … -H RELAY -p PORT` (≤20s) | T1572 / T1573 / T1071.001 |

Cleanup uses `wld lab uninstall` (injects 3–4) and removes the binary.

## Windows injects — wld.exe as the core client

`wld`'s `lab` sub-techniques are **POSIX-only**, so on Windows the tool is
exercised as the core client (download/exec, masquerade-by-rename, persistence
*of* `wld.exe`, and the encrypted channel):

| # | delay | Inject | wld invocation | ATT&CK |
|---|-------|--------|----------------|--------|
| 1 | 0s   | Ingress + exec | download `wld.exe` + `wld -h` (SHA256) | T1105 / T1059.001 |
| 2 | 60s  | Masquerade | copy `wld.exe`→`svchost.exe`, run it | T1036.004/.005 |
| 3 | 120s | Persistence (task) | scheduled task runs `wld.exe` | T1053.005 |
| 4 | 180s | Persistence (Run key) | HKCU `Run` → `wld.exe` | T1547.001 |
| 5 | 240s | Encrypted C2 channel | `wld.exe -s … -H RELAY -p PORT` (≤20s) | T1572 / T1573 / T1071.001 |
| 6 | 300s | Masqueraded C2 | fake `svchost.exe` (wld) → relay (≤20s) | T1036.005 / T1572 / T1573 |

Each inject downloads `wld.exe` if missing and cleans it up (kills processes,
deletes the task / Run value / dropped files).

## Import & run

1. OpenAEV: **Scenarios → Import** → upload the `.zip`.
2. Set **targets** — your Linux/Windows **assets** or an **asset group** with an
   OpenAEV agent. Without a target the injects show *Missing Content*.
3. **Edit the relay lines** (beacon + C2 injects): `RELAY` / `RELAY_HOST` /
   `RELAY_PORT` / `SECRET` (Linux) and `$RelayHost` / `$RelayPort` / `$Secret`
   (Windows) → your wetland relay/tunnel and the matching shared secret. Stand a
   listener up with `wld -l` (or `wetland-relay`) so the channel has a peer.
4. Launch. Review prevention/detection per inject; OpenAEV runs each cleanup.

## What the SOC should catch

- **The tool on disk / executing:** `wld`/`wld.exe` written by curl then run;
  on Windows the SHA256 matches the known Release asset.
- **Masquerade:** a process named `[kworker/…]` (Linux) or `svchost.exe` outside
  System32 (Windows) whose real image is `wld`.
- **Persistence referencing the tool:** cron/systemd (Linux) or scheduled task /
  Run key (Windows) whose action is `wld`.
- **The encrypted channel:** the `wld` process making outbound connections to the
  relay (custom XChaCha20 E2E handshake; rare-destination, beaconing cadence).

## Notes

- Needs a recent OpenAEV/OpenBAS with the **OpenAEV Implant** injector and an
  agent on the targets. Linux injects need `bash`/`curl`; Windows needs
  `curl.exe` + PowerShell (both present on current Windows).
- The native export format is version-sensitive; these were templated
  field-for-field from a real export of your instance, so they import where it
  does.
- Manual cleanup if ever needed — Linux: `~/.wetland-lab-wld lab uninstall`;
  `rm ~/.wetland-lab-wld ~/.wetland-lab`; `crontab -l | grep -v WETLAND-LAB |
  crontab -`; remove `~/.config/systemd/user/wetland-lab.service`. Windows:
  `schtasks /Delete /TN WETLAND-LAB /F`; delete HKCU `Run\WETLAND-LAB`;
  `rm $env:TEMP\wld.exe $env:TEMP\svchost.exe $env:LOCALAPPDATA\wld.exe`.

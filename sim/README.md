# wetland — OpenAEV / OpenBAS simulation

`wetland-purple-c2.openaev.zip` (Linux) and `wetland-purple-c2-windows.openaev.zip`
(Windows) are **breach-and-attack-simulation scenarios** you import into
[OpenAEV](https://docs.openaev.io/) (formerly OpenBAS). They reproduce the
`wld lab` purple-team techniques as self-cleaning command payloads so a blue team
can exercise detections. The **first inject pulls the real `wld` tool onto the
host** (T1105), the rest exercise evasion → persistence → C2.

> **Import the `.zip`, not the `.json`.** OpenAEV's importer reads a ZIP whose
> single entry is tagged with the zip **entry comment `Scenario`** — a bare
> `.json` can be rejected. The `.zip` is built that way; the `.json` is included
> only for review/diffing. The envelope and injector-contract scaffolding were
> templated from a real export of a ThreatOps/OpenAEV instance, so the field set,
> domain id and implant-injector ids match what the platform expects.

> ⚠️ **Authorized lab use only.** Every inject is intentionally loud, tags its
> artifacts with `WETLAND-LAB`, prints an ATT&CK-mapped detection hint, and ships
> a **cleanup command** that OpenAEV runs to undo it. The goal is detectable
> telemetry, not stealth.

## Injects

**Linux** (`wetland-purple-c2.openaev.json`, `bash`/`sh`):

| # | delay | Inject | ATT&CK | mirrors |
|---|-------|--------|--------|---------|
| 1 | 0s   | **Ingress tool transfer** — `curl` pulls `wld` + runs `wld -h` | T1105 | — |
| 2 | 60s  | Masquerade — process named as a kernel thread | T1036.004/.005 | `wld -M` / `wld lab masquerade` |
| 3 | 120s | Persistence — `@reboot` cron entry | T1053.003 | `wld lab persist --method cron` |
| 4 | 180s | Persistence — systemd `--user` service | T1543.002 | `wld lab persist --method systemd` |
| 5 | 240s | Hidden file + timestomp | T1564.001/T1070.006 | `wld lab hide` |
| 6 | 300s | HTTP-shaped C2 beacon | T1071.001/T1571 | `wld lab beacon --as http` |

**Windows** (`wetland-purple-c2-windows.openaev.json`, `psh`):

| # | delay | Inject | ATT&CK |
|---|-------|--------|--------|
| 1 | 0s   | **Ingress tool transfer** — `curl.exe` pulls `wld.exe` + runs `wld -h` | T1105 |
| 2 | 60s  | Masquerade — fake `svchost.exe` from a user path | T1036.004/.005 |
| 3 | 120s | Persistence — scheduled task (`schtasks`) | T1053.005 |
| 4 | 180s | Persistence — HKCU `Run` key | T1547.001 |
| 5 | 240s | Hidden file + timestomp | T1564.001/T1070.006 |
| 6 | 300s | HTTP-shaped C2 beacon | T1071.001/T1571 |

Each payload is a **Command** payload on the built-in **OpenAEV Implant**
(`openaev_implant`) injector, with DETECTION expectations.

## The download (inject #1, T1105)

Inject #1 fetches the **real `wld` tool-under-test** from this repo and runs
`wld -h` (benign — just prints usage) to produce the download+execute signal:
curl writing an executable to disk and a new process spawning from it
(proxy/NDR tool-transfer, EDR exec-after-download). It does **not** start a live
C2 connection — that stays in the beacon inject's editable `C2=` line, so the
scenario is a detection test, not a canned implant deployment. Cleanup removes
the downloaded file.

Download source:
- **Windows** pulls from the published **v0.1.0 Release**, saves it as `wld.exe`,
  verifies SHA256 + size, then runs `wld -h`:
  `https://github.com/s4nntysec/wetland/releases/download/v0.1.0/wld-windows-x86_64.exe`
- **Linux** pulls the committed binary over raw (no release asset assumed):
  `https://raw.githubusercontent.com/s4nntysec/wetland/main/dist/release/wld-linux-x86_64`
  (swap to `releases/download/v0.1.0/wld-linux-x86_64` if you add it to the Release).

### Prefer a GitHub Release (recommended)

A Release keeps binaries out of git history and gives a stable
`releases/latest/download/…` URL. **This environment can't create Releases**
(no `gh`/API/release tooling here — only `git push`), so publish it yourself:

1. `dist/release/` already holds the built assets (`wld-*`, `wetland-relay-*`,
   `SHA256SUMS.txt`). A `v0.1.0` tag is pushed.
2. GitHub → **Releases → Draft a new release** → choose tag `v0.1.0` → attach the
   four binaries + `SHA256SUMS.txt` → **Publish**.
3. In both inject #1 payloads, swap the `url` to
   `https://github.com/s4nntysec/wetland/releases/latest/download/wld-<os>-x86_64[.exe]`
   (the commented alternative is already in the payload).

macOS: not cross-buildable in this environment — run `make` on a Mac to produce
`bin/wld` and add it to the Release as `wld-macos-<arch>`.

## Import & run

1. OpenAEV: **Scenarios → Import** → upload the `.zip`.
2. Set **targets** — your Linux/Windows **assets** or an **asset group** with an
   OpenAEV agent. Without a target the injects show *Missing Content*.
3. **Edit the beacon's `C2=` / `$C2` line** (last inject) to your wetland
   relay/tunnel `host:port` — e.g. the public address `wld -l` prints.
4. Launch. Review prevention/detection per inject; OpenAEV runs each cleanup.

## Notes

- A recent OpenAEV/OpenBAS with the **OpenAEV Implant** injector and an agent on
  the targets. Linux injects need **bash** (beacon uses `/dev/tcp`); cron/systemd
  injects are best-effort and say so if there is no cron spool / user-systemd.
- The native export format is **version-sensitive**; these were templated
  field-for-field from a real export of your instance. If an upgrade changes the
  format, regenerate from a fresh export (below).
- Manual cleanup if ever needed: `rm ~/.wetland-lab ~/.wetland-lab-wld
  /tmp/.wetland-lab-kworker ~/.wetland-lab.log`; `crontab -l | grep -v
  WETLAND-LAB | crontab -`; remove `~/.config/systemd/user/wetland-lab.service`;
  Windows: `schtasks /Delete /TN WETLAND-LAB /F`, delete the HKCU `Run\WETLAND-LAB`
  value, `rm $env:TEMP\wetland-lab-*`, `rm $env:APPDATA\.wetland-lab.bin`.

Regenerate: `python3 sim/gen_scn.py <export.json>` (Linux) /
`python3 sim/gen_scn_win.py <export.json>` (Windows) — the export is used only as
a structural template; none of its content is copied.

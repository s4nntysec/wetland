# wetland — OpenAEV / OpenBAS simulation

`wetland-purple-c2.openaev.zip` is a **breach-and-attack-simulation scenario**
you import into [OpenAEV](https://docs.openaev.io/) (formerly OpenBAS). It
reproduces the `wld lab` purple-team techniques as portable, self-cleaning
command payloads so a blue team can exercise detections — **no `wld` binary is
deployed on the target**; each inject is plain shell run by the OpenAEV agent.

> **Import the `.zip`, not the `.json`.** OpenAEV's importer reads a ZIP whose
> single entry is tagged with the zip **entry comment `Scenario`** — a bare
> `.json` can be rejected. The `.zip` here is built that way; the `.json` is
> included only for review/diffing. This scenario's envelope and injector-contract
> scaffolding were templated from a real export of a ThreatOps/OpenAEV instance,
> so the field set, domain id and implant-injector ids match what the platform
> expects.

> ⚠️ **Authorized lab use only.** Every inject is intentionally loud, tags its
> artifacts with `WETLAND-LAB`, prints an ATT&CK-mapped detection hint, and ships
> a **cleanup command** that OpenAEV runs to undo it. The goal is detectable
> telemetry, not stealth.

## Injects (→ ATT&CK, → `wld lab`)

| # | Inject | ATT&CK | mirrors |
|---|--------|--------|---------|
| 1 | Masquerade — process named as a kernel thread | T1036.004 / T1036.005 | `wld -l -M '[kworker/0:0]'` / `wld lab masquerade` |
| 2 | Persistence — `@reboot` cron entry | T1053.003 | `wld lab persist --method cron` |
| 3 | Persistence — systemd `--user` service | T1543.002 | `wld lab persist --method systemd` |
| 4 | Hidden file + timestomp | T1564.001 / T1070.006 | `wld lab hide` |
| 5 | HTTP-shaped C2 beacon | T1071.001 / T1571 | `wld lab beacon --as http` |

Each payload is a **Command** payload on the built-in **OpenAEV Implant**
(`openaev_implant`) injector, platform **Linux**, with DETECTION/PREVENTION
expectations. Injects are staggered (0/60/120/180/240 s) into an evasion →
persistence → C2 timeline.

## Import

1. In OpenAEV: **Scenarios → Import**, and upload
   `wetland-purple-c2.openaev.zip`.
2. Open the imported scenario and set **targets** — your Linux **assets** or an
   **asset group** that has an OpenAEV agent/implant. Without a target the
   injects show *Missing Content*.
3. **Edit the beacon's `C2=` line** (inject #5) to your wetland relay/tunnel
   `host:port` — e.g. the public address `wld -l` prints.
4. Launch the scenario (or schedule it). Review prevention/detection results per
   inject; OpenAEV runs each payload's cleanup afterwards.

## Windows version

`wetland-purple-c2-windows.openaev.zip` is the Windows counterpart — six
PowerShell (`psh`) injects for Windows assets:

| # | Inject | ATT&CK |
|---|--------|--------|
| 1 | Masquerade — fake `svchost.exe` from a user path | T1036.004 / T1036.005 |
| 2 | Persistence — scheduled task (`schtasks`) | T1053.005 |
| 3 | Persistence — HKCU `Run` key | T1547.001 |
| 4 | Hidden file + timestomp | T1564.001 / T1070.006 |
| 5 | HTTP-shaped C2 beacon | T1071.001 / T1571 |
| 6 | Ingress tool transfer — **benign EICAR** download via `curl.exe` | T1105 |

### On "pulling the binary onto the machine"

Inject #6 tests the *behaviour* of a tool being fetched to a host (`curl.exe`
writing a file to disk → proxy/NDR tool-transfer detection, plus endpoint AV
on-write). It downloads the **EICAR test file** — the industry-standard,
deliberately harmless detection artifact — **not** the real `wld` implant. For a
breach-and-attack-simulation that stand-in produces the same download/AV/EDR
signals, so there is no need to publish and auto-deploy the live C2 binary to
endpoints. Blue team can also exercise the `certutil` / `bitsadmin` download
LOLBins noted in the inject. If you run a genuine hands-on-keyboard red-team
engagement that requires the real tool on a host, deploy it yourself under your
rules of engagement; `make windows` already builds `dist/windows/wld.exe`.

## Requirements & notes

- A recent OpenAEV/OpenBAS with the **OpenAEV Implant** injector and a Linux
  agent on the targets. Most injects need **bash** (the beacon uses
  `/dev/tcp`); the cron/systemd injects are best-effort and say so if there is no
  cron spool / user-systemd session.
- The native scenario export format is **version-sensitive**. This file was
  templated field-for-field from a real export of your instance, so it should
  import where that export does. If a future upgrade changes the format,
  regenerate (below) from a fresh export.
- Cleanup: everything is removable even if an inject's own cleanup is skipped —
  `crontab -l | grep -v WETLAND-LAB | crontab -`, remove
  `~/.config/systemd/user/wetland-lab.service`, and `rm ~/.wetland-lab
  /tmp/.wetland-lab-kworker ~/.wetland-lab.log`.

Regenerate with `python3 sim/gen_scn.py <a-real-openaev-scenario-export.json>` —
it uses that export purely as a structural template (none of its scenario content
is copied) and rewrites the `.json` + `.zip` with the wetland injects.

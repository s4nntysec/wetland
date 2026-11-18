# wetland — OpenAEV / OpenBAS simulation

`wetland-purple-c2.openaev.json` is a **breach-and-attack-simulation scenario**
you import into [OpenAEV](https://docs.openaev.io/) (formerly OpenBAS). It
reproduces the `wld lab` purple-team techniques as portable, self-cleaning
command payloads so a blue team can exercise detections — **no `wld` binary is
deployed on the target**; each inject is plain shell run by the OpenAEV agent.

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
   `wetland-purple-c2.openaev.json` (the raw `.json`; no zip needed).
2. Open the imported scenario and set **targets** — your Linux **assets** or an
   **asset group** that has an OpenAEV agent/implant. Without a target the
   injects show *Missing Content*.
3. **Edit the beacon's `C2=` line** (inject #5) to your wetland relay/tunnel
   `host:port` — e.g. the public address `wld -l` prints.
4. Launch the scenario (or schedule it). Review prevention/detection results per
   inject; OpenAEV runs each payload's cleanup afterwards.

## Requirements & notes

- A recent OpenAEV/OpenBAS with the **OpenAEV Implant** injector and a Linux
  agent on the targets. Most injects need **bash** (the beacon uses
  `/dev/tcp`); the cron/systemd injects are best-effort and say so if there is no
  cron spool / user-systemd session.
- The native scenario export format is **version-sensitive**. This file uses the
  `export_version: 1` / `scenario_injects` form (the same shape the current
  marketplace catalogue ships). If your instance rejects it, say which
  version/edition you run and I'll regenerate in the matching form.
- Cleanup: everything is removable even if an inject's own cleanup is skipped —
  `crontab -l | grep -v WETLAND-LAB | crontab -`, remove
  `~/.config/systemd/user/wetland-lab.service`, and `rm ~/.wetland-lab
  /tmp/.wetland-lab-kworker ~/.wetland-lab.log`.

Regenerate from source with `sim/gen_scn.py` (pulls the real injector-contract
template from the OpenAEV scenarios repo).

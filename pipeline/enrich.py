"""Constrói a base de conhecimento final (kb.json) para o APT Threat Map:
entidades normalizadas + técnica → {D3FEND, RE&CT, Defender (tabelas/ASR), mitigações, data components (DeTT&CT), regras multi-formato}."""
from paths import BUILD, EXT, OUT, RAW, REPO  # diretórios configuráveis: ver pipeline/paths.py
import json, glob, re, math, collections, yaml, os, sys
import pycountry
sys.path.insert(0, BUILD)
from detections import PRIORITY

D = json.load(open(BUILD + "/data2.json"))
RI = json.load(open(BUILD + "/rules_index.json"))
CONV = {}
for env in ("sys", "kusto", "qradar"):
    for rid, v in json.load(open(f"{BUILD}/conv_{env}.json")).items():
        CONV.setdefault(rid, {}).update(v)
ents, tech, soft = D["ents"], D["tech"], D["soft"]

# ------------------------------------------------------------------ normalização de setores
SECT = [
 ("Governo", r"govern|ministr|public sector|state bod|local gov|federal|law enforcement|judiciar|eu institutions|european union state|intergovernmental|politic|election|parliament"),
 ("Defesa/Militar", r"defen[cs]e|military|armed|naval|weapons"),
 ("Diplomacia", r"embass|diplomat|foreign (affairs|govern)"),
 ("Financeiro", r"financ|bank|insur|payment|fintech|stock|nyse|bancorp|capital one|citigroup|hsbc|wells fargo"),
 ("Telecom", r"telecom|communications|isp\b|internet provider|satellite"),
 ("Educação/Pesquisa", r"educat|universit|academ|research|school|think tank"),
 ("Energia/Utilities", r"energy|oil|gas\b|utilit|nuclear|water|power|petro|electric|solar"),
 ("Saúde/Farma", r"health|pharma|medical|biotech|vaccine|hospital|covid"),
 ("Mídia/Entretenimento", r"media|journalis|entertainment|broadcast|news|sony"),
 ("Indústria/Manufatura", r"manufactur|industrial|chemical|automotive|semiconductor|electronics|metal|steel|mining"),
 ("Tecnologia/TI", r"\bit\b|technology|high[- ]tech|software|hosting|service provider|virtualization|routers|edge devices|cloud|msp|information tech"),
 ("Aeroespacial/Aviação", r"aerospace|aviation|airline|space"),
 ("Transporte/Logística", r"transport|logistic|shipping|maritime|rail|shipbuild"),
 ("ONGs/Sociedade civil", r"ngo|non-?profit|civil society|religio|dissident|activist|uighur|tibet|labor union|human rights|critics"),
 ("Varejo/Hotelaria", r"retail|hospitality|restaurant|hotel|travel|lodging|e-?commerce"),
 ("Construção/Engenharia", r"construction|engineering"),
 ("Jurídico", r"legal|law firm"),
 ("Jogos/Apostas", r"casino|gambl|betting|video ?game|gaming|online game"),
 ("Cripto/Blockchain", r"crypto|blockchain|bitcoin"),
 ("Infraestrutura crítica/ICS", r"critical infra|industrial control|\bics\b|scada|ot\b"),
 ("Alimentos/Agro", r"food|agricultur"),
]
SECT_RX = [(n, re.compile(rx, re.I)) for n, rx in SECT]
def norm_sectors(vals):
    out = set()
    for v in vals:
        for n, rx in SECT_RX:
            if rx.search(v): out.add(n)
    return sorted(out)

# ------------------------------------------------------------------ países (vitimologia) → ISO2 / numérico (topojson world-atlas)
ALI = {"USA": "US", "United States": "US", "UK": "GB", "United Kingdom": "GB", "UAE": "AE", "United Arab Emirates": "AE", "Russia": "RU",
       "Russian Federation": "RU", "South Korea": "KR", "North Korea": "KP", "Iran": "IR", "Syria": "SY", "Vietnam": "VN", "Laos": "LA",
       "Taiwan": "TW", "Palestine": "PS", "Gaza": "PS", "Macedonia": "MK", "Swaziland": "SZ", "Ivory Coast": "CI", "Cote d'Ivoire": "CI",
       "Congo": "CG", "Bolivia": "BO", "Venezuela": "VE", "Tanzania": "TZ", "Moldova": "MD", "Brunei": "BN", "Macao": "MO", "Czech": "CZ",
       "Czech Republic": "CZ", "Dubai": "AE", "Lebonon": "LB", "The Philippines": "PH", "Central-African Republic": "CF",
       "Central African Republic": "CF", "Turkey": "TR", "Kosovo": "XK", "Korea": "KR", "Hong Kong": "HK", "Tibet": "CN", "Chechnya": "RU",
       "Bosnia": "BA", "Bosnia and Herzegovina": "BA", "Kyrgyzstan": "KG", "Cape Verde": "CV", "East Timor": "TL", "Burma": "MM"}
def to_iso(n):
    n = (n or "").strip()
    if n in ALI: return ALI[n]
    if re.fullmatch(r"[A-Z]{2}", n):
        return n if pycountry.countries.get(alpha_2=n) else ""
    try: return pycountry.countries.lookup(n).alpha_2
    except Exception: pass
    try:
        r = pycountry.countries.search_fuzzy(n)
        return r[0].alpha_2 if r and len(n) > 4 else ""
    except Exception: return ""
COUNTRIES = {}
def reg_country(iso):
    if not iso or iso in COUNTRIES: return
    c = pycountry.countries.get(alpha_2=iso)
    if iso == "XK": COUNTRIES[iso] = dict(n="Kosovo", num="-99"); return
    if c: COUNTRIES[iso] = dict(n=getattr(c, "common_name", None) or c.name, num=c.numeric)

# ------------------------------------------------------------------ motivação
def norm_motiv(e):
    s = " ".join(e["motivation"] + [e.get("etype") or "", e.get("sponsor") or ""]).lower()
    out = set()
    if re.search(r"espionage|information theft|intelligence|surveillance", s): out.add("Espionagem")
    if re.search(r"financ|ransom|fraud|crime|monetar", s) or (e.get("etype") or "").lower() in ("ransomware", "cybercrime", "criminal"): out.add("Financeiro")
    if re.search(r"sabotage|destruct|wiper|disrupt", s): out.add("Sabotagem/Destrutivo")
    if re.search(r"hacktiv|influence|propaganda|denial of service|subversion|information op", s): out.add("Hacktivismo/Influência")
    return sorted(out)

# ------------------------------------------------------------------ ferramentas unificadas
snorm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
sw_index = {}
for sid, s in soft.items():
    for n in [s["n"]] + s["al"]:
        if len(snorm(n)) >= 3: sw_index.setdefault(snorm(n), sid)
GENERIC_TOOL = re.compile(r"^(many others|others|custom|various|unknown|malware|backdoor|rat|tools?|and more|etc\.?|n/a|none|several.*|multiple.*|own .*|.*\bmany\b.*)$", re.I)
TOOLS = {}   # key -> {n, s(mitre id or ''), ty, d}
def tool_key(name, desc=""):
    n = name.strip().strip(".").strip()
    if not n or len(n) > 40 or GENERIC_TOOL.match(n): return None
    sid = sw_index.get(snorm(n)) or sw_index.get(snorm(re.sub(r"\(.*?\)", "", n)))
    if sid:
        if sid not in TOOLS: TOOLS[sid] = dict(n=soft[sid]["n"], s=sid, ty=soft[sid]["ty"], d=soft[sid]["d"])
        return sid
    k = "X:" + snorm(n)
    if len(k) < 5: return None
    if k not in TOOLS: TOOLS[k] = dict(n=n, s="", ty="tool/malware", d=desc)
    elif desc and not TOOLS[k]["d"]: TOOLS[k]["d"] = desc
    return k

for e in ents:
    tl = []
    for sid in e["sw_ids"]:
        if sid in soft:
            TOOLS.setdefault(sid, dict(n=soft[sid]["n"], s=sid, ty=soft[sid]["ty"], d=soft[sid]["d"])); tl.append(sid)
    for t in e["am_tools"]:
        k = tool_key(t["n"], t["d"])
        if k and k not in tl: tl.append(k)
    for tok in re.split(r",|;|\n| and |\|", e.get("tools") or ""):
        k = tool_key(re.sub(r"\s+", " ", tok))
        if k and k not in tl: tl.append(k)
    e["tl"] = tl
# software → técnicas (somente MITRE)
for k, t in TOOLS.items():
    t["t"] = sorted(soft[k]["t"]) if t["s"] else []
tool_groups = collections.Counter(k for e in ents for k in e["tl"])

# ------------------------------------------------------------------ similaridade TTP+ferramentas (TF-IDF cosseno)
feat = {}
for i, e in enumerate(ents):
    f = set("T:" + t for t in e["techniques"]) | set("S:" + k for k in e["tl"])
    if len(f) >= 8: feat[i] = f
df = collections.Counter(x for f in feat.values() for x in f); N = len(feat)
vec = {}
for i, f in feat.items():
    v = {x: math.log(1 + N / df[x]) for x in f}
    nrm = math.sqrt(sum(w * w for w in v.values())); vec[i] = {x: w / nrm for x, w in v.items()}
inv = collections.defaultdict(list)
for i, v in vec.items():
    for x, w in v.items(): inv[x].append((i, w))
for i, v in vec.items():
    acc = collections.Counter()
    for x, w in v.items():
        if df[x] > N * 0.6: continue
        for j, w2 in inv[x]:
            if j != i: acc[j] += w * w2
    ents[i]["sim"] = [[j, round(s, 3)] for j, s in acc.most_common(6) if s >= 0.22]
for e in ents: e.setdefault("sim", [])

# ------------------------------------------------------------------ D3FEND
D3, d3_by_tech = {}, {}
for f in glob.glob(EXT + "/d3f/*.json"):
    t = os.path.basename(f)[:-5]
    b = json.load(open(f))["off_to_def"]["results"]["bindings"]
    rows, seen = [], set()
    for x in b:
        g = lambda k: x.get(k, {}).get("value", "")
        if not g("def_tech_id"): continue
        did = g("def_tech_id")
        D3.setdefault(did, [g("def_tech_label"), g("def_tactic_label"), g("def_tech_parent_label"), g("def_tech").split("#")[-1]])
        key = (did, g("off_artifact_label"))
        if key in seen: continue
        seen.add(key)
        rows.append([did, g("off_artifact_rel_label") + " " + g("off_artifact_label"), g("def_artifact_rel_label") + " " + g("def_artifact_label")])
    d3_by_tech[t] = rows
D3_ORDER = {"Model": 0, "Harden": 1, "Detect": 2, "Isolate": 3, "Deceive": 4, "Evict": 5, "Restore": 6}

# ------------------------------------------------------------------ RE&CT
RA = {}
for f in glob.glob(EXT + "/atc-react-master/response_actions/*.yml"):
    y = yaml.safe_load(open(f))
    rid = y["id"]
    title = re.sub(r"^RA_\d+_", "", y["title"]).replace("_", " ")
    RA[rid] = [title[:1].upper() + title[1:], y.get("stage", ""), int(rid[3]), re.sub(r"\s+", " ", (y.get("description") or "")).strip()[:160], os.path.basename(f)[:-4]]
FACET_RA = {
 "net_ext": ["RA2113", "RA2114", "RA2115", "RA2104", "RA2105", "RA2106", "RA3101", "RA3103", "RA3105", "RA5101", "RA5102", "RA5103"],
 "web":     ["RA2117", "RA2106"],
 "exfil":   ["RA2110", "RA2111", "RA2112", "RA2116", "RA3111", "RA3109"],
 "net_int": ["RA2102", "RA2101", "RA2107", "RA2109", "RA3102", "RA3108", "RA3110", "RA5104", "RA5105"],
 "port":    ["RA2107", "RA3107", "RA5104"],
 "email":   ["RA2201", "RA2202", "RA2203", "RA2204", "RA2205", "RA2206", "RA3201", "RA3202", "RA3203", "RA4201", "RA5201", "RA5202", "RA5203"],
 "file":    ["RA2301", "RA2302", "RA2306", "RA2307", "RA2308", "RA2310", "RA2311", "RA2312", "RA3302", "RA3303", "RA3304", "RA4301", "RA5301"],
 "download":["RA2304", "RA2313"],
 "timestomp":["RA2305"],
 "deleted": ["RA2303"],
 "office":  ["RA2316", "RA2317"],
 "script":  ["RA2318"],
 "process": ["RA2401", "RA2402", "RA2403", "RA2404", "RA2406", "RA3401", "RA3402", "RA3403", "RA3405", "RA5401"],
 "registry":["RA2501", "RA2504", "RA2508", "RA4501"],
 "service": ["RA2505", "RA2506", "RA2507", "RA3501", "RA4502", "RA5501"],
 "identity":["RA2003", "RA2601", "RA2602", "RA3601", "RA4601", "RA5601"],
 "acct_new":["RA4602"],
 "vuln":    ["RA2002", "RA3001"],
 "destroy": ["RA5001", "RA5002"],
}
PREP = {"net_ext": 1, "net_int": 1, "exfil": 1, "web": 1, "email": 2, "file": 3, "process": 4, "registry": 5, "service": 5, "identity": 6}
def facets(tid, t, d3rows):
    dc = " ".join(t.get("ds", [])).lower(); ta = set(t.get("tactics", [])); art = " ".join(r[1] for r in d3rows).lower()
    base = tid.split(".")[0]; F = set()
    if ta & {"command-and-control", "exfiltration"} or (("network" in dc) and "initial-access" in ta): F.add("net_ext")
    if base in ("T1071", "T1102", "T1189", "T1190", "T1505", "T1567", "T1105") or "web traffic" in art: F.add("web")
    if "exfiltration" in ta or base in ("T1020", "T1030", "T1048", "T1041", "T1567", "T1537"): F.add("exfil")
    if ta & {"lateral-movement"} or ("network" in dc and ta & {"discovery"}) or "intranet" in art or "network share" in dc: F.add("net_int")
    if base in ("T1571", "T1095", "T1205"): F.add("port")
    if base in ("T1566", "T1534", "T1114", "T1598", "T1656") or "email" in art or "email" in dc: F.add("email")
    if "file" in dc or "file" in art: F.add("file")
    if base in ("T1105", "T1608", "T1204") : F.add("download")
    if tid == "T1070.006": F.add("timestomp")
    if "file deletion" in dc or tid in ("T1070.004",): F.add("deleted")
    if base in ("T1566", "T1137", "T1221", "T1203") or tid in ("T1204.002",): F.add("office")
    if base in ("T1059", "T1027") or "script" in dc: F.add("script")
    if re.search(r"process|command execution|module load|os api|script execution", dc) or "process" in art: F.add("process")
    if "registry" in dc or "registry" in art or "system configuration database" in art: F.add("registry")
    if re.search(r"service (creation|modification|metadata)", dc) or tid in ("T1543.003", "T1569.002"): F.add("service")
    if re.search(r"user account|logon session|active directory|group (enum|mod|meta)|web credential", dc) or "credential-access" in ta or re.search(r"user account|credential|authentication|kerberos|access token", art): F.add("identity")
    if re.search(r"user account creation", dc) or base == "T1136": F.add("acct_new")
    if base in ("T1190", "T1203", "T1210", "T1211", "T1212", "T1068", "T1189", "T1195"): F.add("vuln")
    if base in ("T1485", "T1486", "T1490", "T1561", "T1529", "T1491", "T1495"): F.add("destroy")
    return F

# ------------------------------------------------------------------ Microsoft Defender XDR – tabelas por data component
DC2MDE = {
 "Process Creation": ["DeviceProcessEvents"], "Command Execution": ["DeviceProcessEvents", "DeviceEvents:PowerShellCommand"],
 "Script Execution": ["DeviceEvents:PowerShellCommand", "DeviceEvents:AmsiScriptDetection"],
 "File Creation": ["DeviceFileEvents:FileCreated"], "File Modification": ["DeviceFileEvents:FileModified", "DeviceFileEvents:FileRenamed"],
 "File Deletion": ["DeviceFileEvents:FileDeleted"], "File Access": ["DeviceFileEvents (parcial)"], "File Metadata": ["DeviceFileCertificateInfo", "DeviceFileEvents"],
 "Network Connection Creation": ["DeviceNetworkEvents"], "Network Traffic Flow": ["DeviceNetworkEvents"],
 "Network Traffic Content": ["DeviceNetworkEvents:*ConnectionInspected"], "Network Share Access": ["DeviceFileEvents (RequestProtocol=SMB)", "DeviceNetworkEvents"],
 "Module Load": ["DeviceImageLoadEvents"], "Driver Load": ["DeviceEvents:DriverLoad"],
 "Windows Registry Key Modification": ["DeviceRegistryEvents:RegistryValueSet"], "Windows Registry Key Creation": ["DeviceRegistryEvents:RegistryKeyCreated"],
 "Windows Registry Key Deletion": ["DeviceRegistryEvents:RegistryKeyDeleted"],
 "Process Access": ["DeviceEvents:OpenProcessApiCall"], "OS API Execution": ["DeviceEvents:*ApiCall"], "Process Modification": ["DeviceEvents:*ApiCall"],
 "Process Metadata": ["DeviceProcessEvents"], "Logon Session Creation": ["DeviceLogonEvents", "IdentityLogonEvents"],
 "Logon Session Metadata": ["DeviceLogonEvents", "IdentityLogonEvents", "EntraIdSignInEvents"],
 "User Account Authentication": ["IdentityLogonEvents", "DeviceLogonEvents", "EntraIdSignInEvents"],
 "User Account Creation": ["IdentityDirectoryEvents", "DeviceEvents:UserAccountCreated", "CloudAppEvents"],
 "User Account Modification": ["IdentityDirectoryEvents", "CloudAppEvents"], "User Account Deletion": ["IdentityDirectoryEvents", "CloudAppEvents"],
 "User Account Metadata": ["IdentityInfo"], "Active Directory Object Modification": ["IdentityDirectoryEvents"],
 "Active Directory Object Creation": ["IdentityDirectoryEvents"], "Active Directory Object Deletion": ["IdentityDirectoryEvents"],
 "Active Directory Object Access": ["IdentityQueryEvents"], "Active Directory Credential Request": ["IdentityLogonEvents", "IdentityDirectoryEvents"],
 "Group Enumeration": ["IdentityQueryEvents"], "Group Modification": ["IdentityDirectoryEvents"], "Group Metadata": ["IdentityQueryEvents"],
 "Scheduled Job Creation": ["DeviceEvents:ScheduledTaskCreated"], "Scheduled Job Modification": ["DeviceEvents:ScheduledTaskUpdated"],
 "Scheduled Job Metadata": ["DeviceEvents:ScheduledTask*"], "Service Creation": ["DeviceEvents:ServiceInstalled", "DeviceRegistryEvents"],
 "Service Modification": ["DeviceRegistryEvents"], "Service Metadata": ["DeviceRegistryEvents"], "WMI Creation": ["DeviceEvents:WmiBindEventFilterToConsumer"],
 "Named Pipe Metadata": ["DeviceEvents:NamedPipeEvent"], "Drive Access": ["DeviceEvents:UsbDriveMounted"], "Drive Creation": ["DeviceEvents:PnpDeviceConnected"],
 "Drive Modification": ["DeviceEvents:UsbDriveMounted"], "Host Status": ["DeviceInfo"], "Firmware Modification": ["DeviceTvmHardwareFirmware"],
 "Firewall Rule Modification": ["DeviceProcessEvents (netsh/Set-NetFirewallRule)", "DeviceRegistryEvents"], "Firewall Disable": ["DeviceRegistryEvents", "DeviceProcessEvents"],
 "Application Log Content": ["CloudAppEvents"], "Cloud Service Modification": ["CloudAppEvents"], "Cloud Service Metadata": ["CloudAppEvents"],
 "Cloud Service Enumeration": ["CloudAppEvents"], "Cloud Service Disable": ["CloudAppEvents"], "Cloud Storage Access": ["CloudAppEvents"],
 "Cloud Storage Enumeration": ["CloudAppEvents"], "Cloud Storage Deletion": ["CloudAppEvents"], "Cloud Storage Modification": ["CloudAppEvents"],
 "Cloud Storage Metadata": ["CloudAppEvents"], "Web Credential Usage": ["CloudAppEvents", "EntraIdSignInEvents"], "Web Credential Creation": ["CloudAppEvents"],
 "Malware Metadata": ["DeviceFileEvents", "AlertEvidence"], "Malware Content": ["AlertEvidence"],
}
TECH_MDE = {"T1566": ["EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo", "UrlClickEvents"], "T1534": ["EmailEvents", "EmailUrlInfo"],
            "T1114": ["CloudAppEvents:MailItemsAccessed"], "T1598": ["EmailEvents", "EmailUrlInfo"], "T1078.004": ["EntraIdSignInEvents", "CloudAppEvents"],
            "T1110": ["IdentityLogonEvents", "EntraIdSignInEvents", "DeviceLogonEvents"], "T1556": ["IdentityDirectoryEvents", "CloudAppEvents"]}
def mde_product(tb):
    return ("MDE" if tb.startswith("Device") else "MDI" if tb.startswith("Identity") else "MDO" if tb.startswith(("Email", "UrlClick")) else
            "Defender for Cloud Apps" if tb.startswith("CloudApp") else "Entra ID" if tb.startswith("EntraId") else "XDR")
ASR = [
 ["56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers", "AsrVulnerableSignedDriver", ["T1068", "T1014", "T1543.003", "T1562.001"]],
 ["7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes", "AsrAdobeReaderChildProcess", ["T1203", "T1204.002"]],
 ["d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes", "AsrOfficeChildProcess", ["T1204.002", "T1566.001", "T1059.001", "T1059.005", "T1218"]],
 ["9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from the Windows local security authority subsystem (lsass.exe)", "AsrLsassCredentialTheft", ["T1003.001"]],
 ["be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail", "AsrExecutableEmailContent", ["T1566.001", "T1204.002"]],
 ["01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files from running unless they meet a prevalence, age, or trusted list criterion", "AsrUntrustedExecutable", ["T1204.002", "T1036"]],
 ["5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts", "AsrObfuscatedScript", ["T1027", "T1027.010", "T1059.001", "T1059.005", "T1059.007"]],
 ["d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content", "AsrScriptExecutableDownload", ["T1059.005", "T1059.007", "T1105", "T1204.002"]],
 ["3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content", "AsrExecutableOfficeContent", ["T1204.002", "T1105"]],
 ["75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes", "AsrOfficeProcessInjection", ["T1055"]],
 ["26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes", "AsrOfficeCommAppChildProcess", ["T1566.001", "T1204.002", "T1137.003", "T1137.005"]],
 ["e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription", "AsrPersistenceThroughWmi", ["T1546.003"]],
 ["d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands", "AsrPsexecWmiChildProcess", ["T1047", "T1569.002", "T1021.002"]],
 ["33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode", "AsrSafeModeReboot", ["T1562.009"]],
 ["b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB", "AsrUntrustedUsbProcess", ["T1091"]],
 ["c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools", "AsrAbusedSystemTool", ["T1036.003", "T1036.005"]],
 ["a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers", "", ["T1505.003"]],
 ["92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros", "AsrOfficeMacroWin32ApiCalls", ["T1059.005", "T1106"]],
 ["c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware", "AsrRansomware", ["T1486"]],
]
asr_by_tech = collections.defaultdict(list)
for k, a in enumerate(ASR):
    for t in a[3]: asr_by_tech[t].append(k)

# ------------------------------------------------------------------ técnicas usadas
used = set()
for e in ents: used |= set(e["techniques"])
for k, t in TOOLS.items(): used |= set(t["t"])
used |= {t.split(".")[0] for t in used}
TR = RI["tech_rules"]
group_count = collections.Counter(t for e in ents for t in e["techniques"])
TK = {}
for tid in sorted(used):
    t = tech.get(tid)
    if not t: continue
    rows = d3_by_tech.get(tid) or []; inh = False
    if not rows and "." in tid:
        rows = d3_by_tech.get(tid.split(".")[0]) or []; inh = bool(rows)
    rows = sorted(rows, key=lambda r: (D3_ORDER.get(D3[r[0]][1], 9), r[0]))
    F = facets(tid, t, rows)
    ra = []
    for f in sorted(F):
        for r in FACET_RA.get(f, []):
            if r in RA and r not in ra: ra.append(r)
    ra = ["RA2001"] + ra
    mde = []
    for dc in t.get("ds", []):
        for tb in DC2MDE.get(dc, []):
            if tb not in mde: mde.append(tb)
    for k2, tbs in TECH_MDE.items():
        if tid == k2 or tid.startswith(k2 + "."):
            mde = tbs + [x for x in mde if x not in tbs]
    asr = sorted(set(asr_by_tech.get(tid, []) + (asr_by_tech.get(tid.split(".")[0], []) if "." in tid else [])))
    rules = TR.get(tid, [])
    TK[tid] = dict(n=t["name"], ta=t["tactics"], dc=t.get("ds", []), ls=t.get("ls", [])[:8], pl=t.get("pl", []), mit=t.get("mit", []),
                   d3=rows[:40], d3i=inh, ra=ra, fa=sorted(F), mde=mde, asr=asr, r=rules, ng=group_count.get(tid, 0))

# ------------------------------------------------------------------ regras (multi-formato)
RULES = {}
FMTS = ["splunk", "elastic", "eql", "esql", "opensearch", "qradar", "stellar", "defender"]
for rid, r in RI["rules"].items():
    y = open(r["path"], encoding="utf-8").read()
    y = re.sub(r"\n{3,}", "\n\n", y)
    conv = CONV.get(rid, {})
    RULES[rid] = dict(t=r["title"], lv=r["level"], st=r["status"], src=r["src"], u=r["url"], ls=r["ls"], tg=r["tags"], d=r["desc"], fp=r["fp"],
                      g=r.get("group", ""), y=y, f={k: conv.get(k) for k in FMTS if k in conv})
# detecções manuais por grupo prioritário (KQL/SPL com agregação)
DET = {}
for p in PRIORITY:
    ids = [yaml.safe_load(y)["id"] for y in p["sigma"]]
    DET[p["mitre"]] = dict(title=p["title"], ttp=p["ttp"], tel=p["telemetry"], rules=ids, why=p["why"], kql=p["extra_kql"], spl=p["extra_spl"], gaps=p["gaps"])

# ------------------------------------------------------------------ entidades compactas
SRC_LIST = sorted({s for e in ents for s in e["sources"]})
TOOL_KEYS = sorted(TOOLS)
tool_ix = {k: i for i, k in enumerate(TOOL_KEYS)}
E = []
for i, e in enumerate(ents):
    vic_iso, vic_other = [], []
    for v in e["victims"]:
        iso = to_iso(v)
        if iso:
            reg_country(iso)
            if iso not in vic_iso: vic_iso.append(iso)
        elif v not in vic_other: vic_other.append(v)
    reg_country(e["iso"])
    raw_sec = list(e["sectors"])
    if e.get("gcp"): raw_sec_extra = [e["gcp"]["sectors"]]
    else: raw_sec_extra = []
    sec = norm_sectors(raw_sec + raw_sec_extra + [e.get("targets") or ""])
    E.append(dict(
        n=e["name"], a=[x for x in e["aliases"] if not re.fullmatch(r"G\d{4}(/G\d{4})?", x)][:40], c=e["country"], iso=e["iso"], m=e["mitre"] or "", s=[SRC_LIST.index(s) for s in e["sources"]],
        sec=sec, sr=raw_sec[:20], v=vic_iso, vo=vic_other[:15], mo=norm_motiv(e), mr=e["motivation"][:6], fs=str(e["first_seen"] or "")[:10],
        sp=(e["sponsor"] or "")[:200], d=re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", e["desc"] or "")[:700], t=e["techniques"],
        p=e["proc"], tl=[tool_ix[k] for k in e["tl"] if k in tool_ix], ops=e["ops"][:15], lk=e["links"][:25], mal=e["malpedia"] or "",
        etda=e["etda"] or "", am=1 if e["aptmap"] else 0, ac=e["attr_conf"], xy=e["xy"], rel=e["am_rel"], sim=e["sim"], gcp=e["gcp"],
        ty=e.get("etype") or "", vn=e.get("vendor_names") or {}, shq=e.get("sigmahq") or [], bd=e.get("brandefense") or "",
        aptm=e.get("aptmalware") or 0, camp=e.get("campaigns") or [], tg=(e.get("targets") or "")[:400], mod=(e.get("modus") or "")[:300],
        cm=(e.get("comment") or "")[:300], tools_raw=(e.get("tools") or "")[:300]))
TOOLS_OUT = [dict(k=k, n=TOOLS[k]["n"], s=TOOLS[k]["s"], ty=TOOLS[k]["ty"], d=(TOOLS[k]["d"] or "")[:220], t=TOOLS[k]["t"],
                  p={tt: soft[k]["t"][tt] for tt in TOOLS[k]["t"]} if TOOLS[k]["s"] else {}, g=tool_groups.get(k, 0)) for k in TOOL_KEYS]
for iso in list(COUNTRIES): pass
CONVSTATS = {}
for f in FMTS:
    ok = sum(1 for r in RULES.values() if isinstance(r["f"].get(f), str)); fb = sum(1 for r in RULES.values() if isinstance(r["f"].get(f), dict) and "q" in r["f"][f])
    CONVSTATS[f] = dict(ok=ok, fb=fb, err=len(RULES) - ok - fb)
KB = dict(DC2MDE=DC2MDE, CONVSTATS=CONVSTATS, E=E, SRC=SRC_LIST, TOOLS=TOOLS_OUT, TK=TK, D3=D3, RA=RA, ASR=ASR, MIT=D["mit_names"], RULES=RULES, DET=DET,
          COUNTRIES=COUNTRIES, FACET_PREP=PREP, malware=D["malware"], sources_sheet=D["sources"], aptm_total=D["aptm_total"])
json.dump(KB, open(BUILD + "/kb.json", "w"), ensure_ascii=False, separators=(",", ":"))
print("ents", len(E), "tools", len(TOOLS_OUT), "(MITRE", sum(1 for t in TOOLS_OUT if t["s"]), ") techniques", len(TK), "D3", len(D3), "RA", len(RA),
      "rules", len(RULES), "countries", len(COUNTRIES), "kb MB", round(os.path.getsize(BUILD + "/kb.json") / 1e6, 2))
print("sim pairs", sum(len(e["sim"]) for e in E), "| ents com setor canônico", sum(1 for e in E if e["sec"]), "| com vítimas ISO", sum(1 for e in E if e["v"]),
      "| motivação", collections.Counter(m for e in E for m in e["mo"]))
print("TK sem D3FEND", sum(1 for t in TK.values() if not t["d3"]), "| sem regra", sum(1 for t in TK.values() if not t["r"]), "| com ASR", sum(1 for t in TK.values() if t["asr"]))

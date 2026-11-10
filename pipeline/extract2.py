"""Extrai e consolida grupos APT de: planilha 'APT Groups and Operations', MITRE ATT&CK (STIX),
ThaiCERT Threat Group Cards (MISP galaxy), Malpedia (lista de atores) e cyber-research/APTMalware (overview.csv)."""
import json, re, csv, collections, openpyxl, os

def norm(s):
    s = str(s).lower().strip()
    s = re.sub(r"^(the|operation|op\.?)\s+", "", s)
    s = re.sub(r"[\s\-_\.'\"“”‘’()/]+", "", s)
    s = s.replace("group", "") if re.fullmatch(r"(apt|ta|fin|unc|temp)?group\d+", s) else s
    s2 = re.sub(r"(group|team|gang|crew)$", "", s)          # "Equation Group" ≡ "Equation", "Sandworm Team" ≡ "Sandworm"
    return s2 if len(s2) >= 4 else s

GENERIC = {"", "unknown", "na", "n/a", "none", "?", "group", "team", "apt", "various", "many", "multiple"}

def clean_aliases(vals):
    out = []
    for v in vals:
        if v is None: continue
        for p in re.split(r"[,;\n]| / ", str(v)):
            p = p.strip().strip("*").strip()
            if not p or p.startswith("=") or p.startswith("http"): continue
            if len(p) > 60: continue
            n = norm(p)
            if n in GENERIC or len(n) < 3: continue
            if p not in out: out.append(p)
    return out

COUNTRY_SHEET = {"China": "China", "Russia": "Russia", "North Korea": "North Korea", "Iran": "Iran",
                 "Israel": "Israel", "NATO": "NATO / Five Eyes", "Middle East": "Middle East",
                 "Others": "Other", "Unknown": "Unknown"}
ISO = {"CN": "China", "RU": "Russia", "KP": "North Korea", "IR": "Iran", "IL": "Israel", "US": "NATO / Five Eyes",
       "GB": "NATO / Five Eyes", "IN": "India", "PK": "Pakistan", "VN": "Vietnam", "KR": "South Korea",
       "LB": "Middle East", "PS": "Middle East", "AE": "Middle East", "SY": "Middle East", "TR": "Turkey",
       "UA": "Ukraine", "BY": "Belarus", "NG": "Nigeria", "BR": "Brazil", "ES": "Spain", "FR": "NATO / Five Eyes",
       "DE": "NATO / Five Eyes", "KZ": "Kazakhstan", "TN": "Middle East", "EG": "Middle East", "SA": "Middle East",
       "IQ": "Middle East", "QA": "Middle East", "KW": "Middle East", "MA": "Middle East", "DZ": "Middle East",
       "JO": "Middle East", "YE": "Middle East", "SG": "Singapore", "TH": "Thailand", "ID": "Indonesia",
       "MY": "Malaysia", "PH": "Philippines", "CO": "Colombia", "MX": "Mexico", "RO": "Romania", "IT": "Italy"}

# ---------------- 1. Planilha APT Groups and Operations ----------------
wb = openpyxl.load_workbook("/tmp/apt.xlsx", read_only=True)
sheet_groups = []
for sh, country in COUNTRY_SHEET.items():
    rows = list(wb[sh].iter_rows(values_only=True))
    hdr = [str(h).strip() if h else "" for h in rows[1]]
    for r in rows[2:]:
        if not r or not r[0] or not str(r[0]).strip(): continue
        rec = dict(zip(hdr, r))
        name = str(r[0]).strip()
        alias_cols = [h for h in hdr if h and not re.match(r"(Operation|Toolset|Targets|Modus|Comment|Link|Overlaps|Origin|MITRE)", h, re.I) and h != "Common Name"]
        aliases = clean_aliases([rec.get(h) for h in alias_cols])
        mitre = None
        for h in hdr:
            if "MITRE" in h.upper() and rec.get(h):
                m = re.search(r"G\d{4}", str(rec[h]))
                if m: mitre = m.group(0)
        ops = clean_aliases([rec.get(h) for h in hdr if h.startswith("Operation")])
        links = [str(rec[h]).strip() for h in hdr if h.lower().startswith("link") and rec.get(h) and str(rec[h]).startswith("http")]
        def g(k):
            for h in hdr:
                if h.lower().startswith(k.lower()) and rec.get(h): return str(rec[h]).strip()
            return ""
        sheet_groups.append(dict(name=name, aliases=aliases, mitre=mitre, country=country, ops=ops,
                                 tools=g("Toolset"), targets=g("Targets"), modus=g("Modus"), comment=g("Comment"),
                                 origin=g("Origin"), overlaps=g("Overlaps"), links=links, sheet=sh))
print("planilha:", len(sheet_groups))

# malware/tool families sheet
mal = []
rows = list(wb["_Malware"].iter_rows(values_only=True))
for r in rows[3:]:
    if not r or not r[0]: continue
    names = [str(x).strip() for x in r[:8] if x and str(x).strip()]
    links = [str(x) for x in r[11:16] if x and str(x).startswith("http")]
    mal.append(dict(names=names, family=str(r[9] or ""), comment=str(r[10] or ""), links=links))
srcs = []
for r in list(wb["_Sources"].iter_rows(values_only=True))[2:]:
    if r and r[0] and r[1]: srcs.append(dict(name=str(r[0]).strip(), url=str(r[1]).strip()))

# ---------------- 2. MITRE ATT&CK ----------------
ea = json.load(open("/tmp/ea.json"))["objects"]
objs = {o["id"]: o for o in ea if not o.get("revoked") and not o.get("x_mitre_deprecated")}
tech = {}
for o in objs.values():
    if o["type"] == "attack-pattern":
        ext = next((e["external_id"] for e in o.get("external_references", []) if e.get("source_name") == "mitre-attack"), None)
        tac = [k["phase_name"] for k in o.get("kill_chain_phases", []) if k["kill_chain_name"] == "mitre-attack"]
        tech[o["id"]] = dict(id=ext, name=o["name"], tactics=tac, ds=o.get("x_mitre_data_sources", []),
                             sub=o.get("x_mitre_is_subtechnique", False))
soft = {}
for o in objs.values():
    if o["type"] in ("malware", "tool"):
        ext = next((e["external_id"] for e in o.get("external_references", []) if e.get("source_name") == "mitre-attack"), None)
        soft[o["id"]] = dict(id=ext, name=o["name"], type=o["type"])
# ATT&CK v18: técnica <- detects - detection-strategy -> analytics -> log_source_references -> data component
dcname = {o["id"]: o["name"] for o in objs.values() if o["type"] == "x-mitre-data-component"}
analytic = {o["id"]: o for o in objs.values() if o["type"] == "x-mitre-analytic"}
strat = {o["id"]: o for o in objs.values() if o["type"] == "x-mitre-detection-strategy"}
for o in objs.values():
    if o["type"] == "relationship" and o["relationship_type"] == "detects" and o["source_ref"] in strat and o["target_ref"] in tech:
        t = tech[o["target_ref"]]; t.setdefault("ls", [])
        for aid in strat[o["source_ref"]].get("x_mitre_analytic_refs", []):
            a = analytic.get(aid)
            if not a: continue
            for ref in a.get("x_mitre_log_source_references", []):
                dc = dcname.get(ref.get("x_mitre_data_component_ref"))
                if dc and dc not in t["ds"]: t["ds"].append(dc)
                ln = ref.get("name", "")
                if ln and ln not in t["ls"]: t["ls"].append(ln)
mgroups = {}
for o in objs.values():
    if o["type"] == "intrusion-set":
        ext = next((e["external_id"] for e in o.get("external_references", []) if e.get("source_name") == "mitre-attack"), None)
        mgroups[o["id"]] = dict(id=ext, name=o["name"], aliases=o.get("aliases", []),
                                desc=re.sub(r"\(Citation:[^)]*\)", "", o.get("description", ""))[:900],
                                techniques={}, software={})
def clean_desc(s, n=360):
    s = re.sub(r"\(Citation:[^)]*\)", "", s or "")
    s = re.sub(r"\[([^\]]+)\]\(https?://attack\.mitre\.org/[^)]+\)", r"\1", s)
    s = re.sub(r"<code>|</code>", "`", s); s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[:n].rsplit(" ", 1)[0] + "…"
for o in objs.values():
    if o["type"] == "relationship" and o["relationship_type"] == "uses" and o["source_ref"] in mgroups:
        t = o["target_ref"]
        if t in tech and tech[t]["id"]: mgroups[o["source_ref"]]["techniques"][tech[t]["id"]] = clean_desc(o.get("description"))
        elif t in soft: mgroups[o["source_ref"]]["software"][soft[t]["id"]] = soft[t]["name"]
# software -> técnica (procedimentos) e aliases de software
soft_out = {}
for sid, s in soft.items():
    o = objs[sid]
    soft_out[s["id"]] = dict(n=s["name"], ty=s["type"], al=[a for a in o.get("x_mitre_aliases", []) if a != s["name"]][:8],
                             pl=o.get("x_mitre_platforms", []), t={}, d=clean_desc(o.get("description"), 260))
for o in objs.values():
    if o["type"] == "relationship" and o["relationship_type"] == "uses" and o["source_ref"] in soft and o["target_ref"] in tech and tech[o["target_ref"]]["id"]:
        soft_out[soft[o["source_ref"]]["id"]]["t"][tech[o["target_ref"]]["id"]] = clean_desc(o.get("description"), 170)
# mitigações (course-of-action mitigates attack-pattern)
mitig = {}
for o in objs.values():
    if o["type"] == "course-of-action":
        mitig[o["id"]] = (next((e["external_id"] for e in o.get("external_references", []) if e.get("source_name") == "mitre-attack"), None), o["name"])
tech_mit = collections.defaultdict(list)
for o in objs.values():
    if o["type"] == "relationship" and o["relationship_type"] == "mitigates" and o["source_ref"] in mitig and o["target_ref"] in tech:
        mid_, mname = mitig[o["source_ref"]]
        if mid_ and mid_.startswith("M"): tech_mit[tech[o["target_ref"]]["id"]].append(mid_)
mit_names = {v[0]: v[1] for v in mitig.values() if v[0] and v[0].startswith("M")}
for o in objs.values():
    if o["type"] == "attack-pattern":
        t = tech.get(o["id"])
        if t: t["pl"] = o.get("x_mitre_platforms", [])
# campanhas atribuídas a grupos
campaigns = collections.defaultdict(list)
camp = {o["id"]: o for o in objs.values() if o["type"] == "campaign"}
for o in objs.values():
    if o["type"] == "relationship" and o["relationship_type"] == "attributed-to" and o["source_ref"] in camp and o["target_ref"] in mgroups:
        c = camp[o["source_ref"]]
        cid = next((e["external_id"] for e in c.get("external_references", []) if e.get("source_name") == "mitre-attack"), "")
        campaigns[o["target_ref"]].append(dict(id=cid, n=c["name"], fs=(c.get("first_seen") or "")[:7], ls=(c.get("last_seen") or "")[:7]))
# software->technique for coverage of group via its tools (not merged, just info)
techidx = {v["id"]: v for v in tech.values() if v["id"]}
mbyid = {g["id"]: g for g in mgroups.values()}
print("mitre groups:", len(mbyid), "techniques:", len(techidx))

# ---------------- 3. ThaiCERT ----------------
etda = json.load(open("/tmp/etda.json"))["values"]
# ---------------- 4. Malpedia ----------------
mp = json.load(open("/tmp/mp.json"))
# ---------------- 5. APTMalware ----------------
aptm = collections.Counter(); aptm_c = {}
for r in csv.DictReader(open("/tmp/aptm.csv")):
    aptm[r["APT-group"]] += 1; aptm_c[r["APT-group"]] = r["Country"]

# ---------------- Consolidação ----------------
ents = []
alias_index = collections.defaultdict(set)
def add_index(i):
    e = ents[i]
    for a in [e["name"]] + e["aliases"]:
        alias_index[norm(a)].add(i)

def new_ent(name, country):
    ents.append(dict(name=name, aliases=[], country=country, mitre=None, sources=set(), ops=[], tools="",
                     targets="", modus="", comment="", links=[], etda=None, mitre_rec=None, malpedia=None,
                     aptmalware=0, vendor_names={}, sigmahq=[], brandefense=None, etype="", sectors=[], victims=[], motivation=[], first_seen="", sponsor="", desc="",
                     iso="", aptmap=None, xy=None, am_tools=[], am_ttp={}, am_rel=[], attr_conf="", gcp=None, wiki=False))
    return len(ents) - 1

by_mitre = {}
for sg in sheet_groups:
    if sg["mitre"] and sg["mitre"] in by_mitre:
        i = by_mitre[sg["mitre"]]
    else:
        i = new_ent(sg["name"], sg["country"])
    e = ents[i]
    e["sources"].add("Planilha APT Groups & Operations")
    for a in sg["aliases"] + ([sg["name"]] if sg["name"] != e["name"] else []):
        if a not in e["aliases"]: e["aliases"].append(a)
    if sg["mitre"]: e["mitre"] = sg["mitre"]; by_mitre[sg["mitre"]] = i
    e["iso"] = e["iso"] or {"China": "CN", "Russia": "RU", "North Korea": "KP", "Iran": "IR", "Israel": "IL"}.get(sg["country"], "")
    for k in ("tools", "targets", "modus", "comment"):
        if sg[k] and sg[k] not in e[k]: e[k] = (e[k] + " | " + sg[k]).strip(" |")
    e["ops"] += [o for o in sg["ops"] if o not in e["ops"]]
    e["links"] += [l for l in sg["links"] if l not in e["links"]]
    if sg["origin"] and e["country"] in ("Other", "Middle East"): e["origin"] = sg["origin"]
    add_index(i)

def best_match(cands_names, mitre_id=None):
    if mitre_id and mitre_id in by_mitre: return by_mitre[mitre_id]
    score = collections.Counter()
    for k, a in enumerate(cands_names):
        n = norm(a)
        if n in GENERIC or len(n) < 3: continue
        for i in alias_index.get(n, ()):
            score[i] += 3 if k == 0 else 1
    if not score: return None
    (i, s), = score.most_common(1)
    return i

# MITRE
def overlap(i, names):
    na = {norm(a) for a in [ents[i]["name"]] + ents[i]["aliases"]}
    return any(norm(n) in na for n in names)
for g in mbyid.values():
    names = [g["name"]] + g["aliases"]
    i = by_mitre.get(g["id"])
    if i is None or not overlap(i, names):
        i = best_match(names)
    if i is not None and ents[i]["mitre_rec"] and ents[i]["mitre_rec"] != g["id"]:
        i = None
    if i is None:
        i = new_ent(g["name"], "Unknown"); 
    e = ents[i]
    e["sources"].add("MITRE ATT&CK"); e["mitre"] = g["id"]; e["mitre_rec"] = g["id"]; by_mitre[g["id"]] = i
    e["desc"] = e["desc"] or g["desc"]
    for a in [g["name"]] + g["aliases"]:
        if a != e["name"] and a not in e["aliases"]: e["aliases"].append(a)
    add_index(i)

# ThaiCERT
for x in etda:
    syn = [s for s in x["meta"].get("synonyms", []) if not s.lower().startswith("operation")]
    names = [p.strip() for p in x["value"].split(",")] + syn
    mid = next((s for s in syn if re.fullmatch(r"G\d{4}", s)), None)
    i = best_match(names, mid)
    ctry = ISO.get(x["meta"].get("country", ""), x["meta"].get("country") or "Unknown")
    if i is None:
        i = new_ent(names[0], ctry)
    e = ents[i]
    if e["etda"]:  # já casado; evita sobrescrever
        pass
    e["etda"] = x["uuid"]; e["sources"].add("ThaiCERT Threat Group Cards")
    if re.fullmatch(r"[A-Z]{2}", x["meta"].get("country", "") or "") and not e["iso"]: e["iso"] = x["meta"]["country"]
    if e["country"] in ("Unknown", "Other") and ctry not in ("Unknown",): e["country"] = ctry
    for a in names:
        if re.fullmatch(r"G\d{4}", a): continue
        if a != e["name"] and a not in e["aliases"]: e["aliases"].append(a)
    m = x["meta"]
    e["sectors"] = sorted(set(e["sectors"]) | set(m.get("cfr-target-category", [])))
    e["victims"] = sorted(set(e["victims"]) | set(m.get("cfr-suspected-victims", [])))
    e["motivation"] = sorted(set(e["motivation"]) | set(m.get("motivation", [])))
    e["first_seen"] = e["first_seen"] or m.get("date", "")
    e["sponsor"] = e["sponsor"] or m.get("cfr-suspected-state-sponsor", "")
    if not e["desc"]: e["desc"] = x.get("description", "")[:900]
    e["ops"] += [s for s in x["meta"].get("synonyms", []) if s.lower().startswith("operation") and s not in e["ops"]]
    add_index(i)


# ---------------- 6. Fontes descobertas na raspagem ----------------
import glob, yaml, openpyxl as _ox
def attach_or_new(names, country, src, create=True, mid=None):
    i = best_match(names, mid)
    if i is None:
        if not create: return None
        i = new_ent(names[0], country or "Unknown")
    e = ents[i]; e["sources"].add(src)
    if e["country"] in ("Unknown","Other") and country and country not in ("Unknown",""): e["country"] = country
    for a in names:
        if a and not re.fullmatch(r"G\d{4}", a) and a != e["name"] and a not in e["aliases"] and len(a) < 60: e["aliases"].append(a)
    add_index(i); return i
for e in ents: e.setdefault("vendor_names", {}); e.setdefault("sigmahq", []); e.setdefault("brandefense", None); e.setdefault("etype","")
CMAP = {"Russian Federation":"Russia","DPRK":"North Korea","Korea (Democratic People's Republic of)":"North Korea","United States":"NATO / Five Eyes","USA":"NATO / Five Eyes","Iran (Islamic Republic of)":"Iran"}
# EternalLiberty: matriz de nomes por fornecedor
for r in csv.DictReader(open("/tmp/ext/eternal.csv", encoding="utf-8", errors="ignore")):
    off = (r.get("Threat Actor Official Name") or "").strip()
    if not off: continue
    vend = {k: v.strip() for k, v in r.items() if k not in ("Threat Actor Official Name","Confidence","Type","Country") and v and v.strip()}
    names = [off] + [n for v in vend.values() for n in clean_aliases([v])]
    c = (r.get("Country") or "").strip(); c = CMAP.get(c, c)
    i = attach_or_new(names, c, "EternalLiberty", True, (vend.get("MITRE") or "")[:5] if (vend.get("MITRE","").startswith("G")) else None)
    ents[i]["vendor_names"].update(vend); ents[i]["etype"] = ents[i]["etype"] or (r.get("Type") or "")
# MISP threat-actor galaxy
misp_by_uuid = {}; misp_rel_raw = []
for x in json.load(open("/tmp/ext/misp_ta.json"))["values"]:
    m = x.get("meta", {}); names = [x["value"]] + m.get("synonyms", [])
    c = ISO.get(m.get("country",""), m.get("country") or "")
    i = attach_or_new(names, c, "MISP Galaxy", True)
    e = ents[i]; misp_by_uuid[x["uuid"]] = i; misp_rel_raw.append((i, x.get("related") or []))
    if re.fullmatch(r"[A-Z]{2}", m.get("country", "") or "") and not e["iso"]: e["iso"] = m["country"]
    e["sectors"] = sorted(set(e["sectors"]) | set(m.get("cfr-target-category", [])))
    e["victims"] = sorted(set(e["victims"]) | set(m.get("cfr-suspected-victims", [])))
    if not e["desc"]: e["desc"] = (x.get("description") or "")[:900]
# Microsoft taxonomy + mapeamento MSFT<->CrowdStrike
wbm = _ox.load_workbook("/tmp/ext/msft.xlsx", read_only=True)
for r in list(wbm.active.iter_rows(values_only=True))[2:]:
    if not r or not r[1]: continue
    names = [str(r[1]).strip()] + clean_aliases([r[3]])
    i = attach_or_new(names, str(r[2] or "").strip() if str(r[2] or "") in COUNTRY_SHEET.values() else "", "Microsoft Threat Actor Naming", True)
    ents[i]["vendor_names"]["Microsoft"] = str(r[1]).strip()
for r in csv.DictReader(open("/tmp/ext/msft_cs.csv")):
    i = best_match([r["Microsoft"], r["CrowdStrike"]])
    if i is not None:
        ents[i]["vendor_names"]["Microsoft"] = r["Microsoft"]; ents[i]["vendor_names"]["CrowdStrike"] = r["CrowdStrike"]
        ents[i]["sources"].add("MSFT↔CrowdStrike mapping")
        for a in (r["Microsoft"], r["CrowdStrike"]):
            if a not in ents[i]["aliases"]: ents[i]["aliases"].append(a)
# BRANDEFENSE dataset (APT + ransomware, com fontes primárias)
for fn, typ in (("apt-groups","APT"),("ransomware-groups","Ransomware")):
    for it in json.load(open(f"/tmp/ext/threat-actor-dataset-main/data/{fn}.json"))["items"]:
        al = [a["name"] if isinstance(a, dict) else a for a in it.get("aliases", [])]
        mid = it.get("mitre_attack_id") if str(it.get("mitre_attack_id","")).startswith("G") else None
        c = CMAP.get(it.get("suspected_origin",""), it.get("suspected_origin","") or "")
        i = attach_or_new([it["name"]] + al, c, "BRANDEFENSE dataset", True, mid)
        e = ents[i]; e["brandefense"] = it["url"]; e["etype"] = e["etype"] or typ
        e["sectors"] = sorted(set(e["sectors"]) | set(it.get("target_sectors", []) or []))
        if not e["desc"]: e["desc"] = it.get("summary", "")
# SigmaHQ emerging-threats por ator
for d in sorted(glob.glob("/tmp/ext/sigma-master/rules-emerging-threats/*/TA/*")):
    folder = os.path.basename(d); parts = [folder.replace("-", " ")] + folder.split("-")
    OVR = {"Mustang-Panda-Australia-Campaign": "G0129", "Peach-Sandstorm": "G0064", "OilRig": "G0049", "ACTINIUM": "G0047",
           "Axiom": "G0001", "Greenbug": "G0049", "Lazarus": "G0032", "Diamond-Sleet": "G0032", "Onyx-Sleet": "G0138", "DPRK": "G0032", "Turla": "G0010", "APT28": "G0007", "Forest-Blizzard": "G0007", "Cozy-Bear": "G0016", "APT29-CozyBear": "G0016", "FIN7": "G0046", "MuddyWater": "G0069", "MERCURY": "G0069", "Winnti": "G0044", "APT10": "G0045", "Mint-Sandstorm": "G0059"}
    if folder in OVR and OVR[folder] in by_mitre: i = by_mitre[OVR[folder]]
    elif folder.startswith("UNC4841"):
        i = new_ent("UNC4841 (Barracuda ESG)", "China"); ents[i]["sources"] = {"SigmaHQ emerging-threats"}
    else: i = best_match(parts)
    if i is None: continue
    for f in glob.glob(d + "/**/*.yml", recursive=True):
        try: y = yaml.safe_load(open(f))
        except Exception: continue
        rel = f.split("sigma-master/")[1]
        ents[i]["sigmahq"].append(dict(title=y.get("title",""), level=y.get("level",""), status=y.get("status",""),
            url="https://github.com/SigmaHQ/sigma/blob/master/" + rel, tags=[t for t in y.get("tags",[]) if t.startswith("attack.t")]))
    ents[i]["sources"].add("SigmaHQ emerging-threats")

# ---------------- 7. APTmap (andreacristaldi/APTmap) ----------------
import pycountry
def name2iso(n):
    n = (n or "").strip()
    ALI = {"USA": "US", "United States": "US", "UK": "GB", "United Kingdom": "GB", "UAE": "AE", "Russia": "RU", "Russian Federation": "RU",
           "South Korea": "KR", "North Korea": "KP", "DPRK": "KP", "Iran": "IR", "Syria": "SY", "Vietnam": "VN", "Laos": "LA", "Taiwan": "TW",
           "Palestine": "PS", "Gaza": "PS", "Macedonia": "MK", "Swaziland": "SZ", "Ivory Coast": "CI", "Cote d'Ivoire": "CI", "Congo": "CG",
           "Bolivia": "BO", "Venezuela": "VE", "Tanzania": "TZ", "Moldova": "MD", "Brunei": "BN", "Macao": "MO", "Czech": "CZ", "Czech Republic": "CZ",
           "Dubai": "AE", "Lebonon": "LB", "The Philippines": "PH", "Central-African Republic": "CF", "Turkey": "TR", "Kosovo": "XK",
           "Korea": "KR", "Republic of Korea": "KR", "Hong Kong": "HK", "Tibet": "CN", "Chechnya": "RU", "Guam": "GU"}
    if n in ALI: return ALI[n]
    if re.fullmatch(r"[A-Z]{2}", n): return n
    try: return pycountry.countries.lookup(n).alpha_2
    except Exception: return ""
am = json.load(open("/tmp/ext/APTmap-master/apt.json"))["features"]
am_by_uuid = {}
def flat(v):
    out = []
    for x in v or []:
        if isinstance(x, list): out += flat(x)
        elif isinstance(x, str) and x.strip(): out.append(x.strip())
    return out
for f in am:
    p = f["properties"]
    names = [p["name"]] + [a for a in (p.get("other-names") or []) if not str(a).lower().startswith("operation")]
    mid = next((a for a in names if re.fullmatch(r"G\d{4}", str(a))), None)
    iso = p.get("country") or ""
    # correspondência estrita: só pelo nome principal APTmap (ou ID MITRE); other-names apenas como aliases sem conflito
    i = best_match([p["name"]], mid)
    if i is None:
        i = new_ent(p["name"], ISO.get(iso, "") or "Unknown")
    e = ents[i]; am_by_uuid[p["uuid"]] = i; e["sources"].add("APTmap")
    if e["country"] in ("Unknown", "Other") and ISO.get(iso): e["country"] = ISO[iso]
    for a in names[1:]:
        if re.fullmatch(r"G\d{4}", str(a)) or len(str(a)) > 60: continue
        owners = alias_index.get(norm(a), set())
        if owners and i not in owners: continue       # alias já pertence a outra entidade → não fundir
        if a != e["name"] and a not in e["aliases"]: e["aliases"].append(a)
    add_index(i)
    e["aptmap"] = p["uuid"]
    if iso and not e["iso"]: e["iso"] = iso
    if f.get("geometry") and f["geometry"].get("coordinates") and not e["xy"]:
        e["xy"] = [round(c, 3) for c in f["geometry"]["coordinates"]]
    e["victims"] = sorted(set(e["victims"]) | set(flat(p.get("targets"))))
    e["sectors"] = sorted(set(e["sectors"]) | set(flat(p.get("target-category"))))
    e["motivation"] = sorted(set(e["motivation"]) | set(flat(p.get("motivations"))))
    e["sponsor"] = e["sponsor"] or p.get("sponsor", "")
    e["first_seen"] = e["first_seen"] or p.get("first-seen", "")
    e["attr_conf"] = e["attr_conf"] or (p.get("attribution-confidence") or "")
    e["ops"] += [a for a in (p.get("other-names") or []) if str(a).lower().startswith("operation") and a not in e["ops"]]
    for t in p.get("tools") or []:
        v = (t.get("value") or "").strip()
        if v and v not in [x["n"] for x in e["am_tools"]]:
            e["am_tools"].append(dict(n=v, d=clean_desc(t.get("description"), 200)))
    for t in p.get("TTP") or []:
        if t.get("comment") and t.get("techniqueID"): e["am_ttp"][t["techniqueID"]] = clean_desc(t["comment"], 300)
    if not e["desc"]: e["desc"] = clean_desc(p.get("description"), 900)
    for l in (p.get("ext-links") or [])[:40]:
        u = l.get("url") if isinstance(l, dict) else None
        if u and u not in e["links"] and len(e["links"]) < 60: e["links"].append(u)
# relações entre grupos (similar / related-to / overlaps / same-as …) com linguagem estimativa (APTmap + MISP galaxy)
etda_by_uuid = {e["etda"]: k for k, e in enumerate(ents) if e.get("etda")}
rel_items = [(am_by_uuid[f["properties"]["uuid"]], f["properties"].get("related") or []) for f in am] + misp_rel_raw
for i, rels in rel_items:
    for r in rels:
        u = r.get("dest-uuid")
        j = am_by_uuid.get(u, misp_by_uuid.get(u, etda_by_uuid.get(u)))
        if j is None or j == i: continue
        lk = ""
        for tg in r.get("tags") or []:
            m = re.search(r'probability="([^"]+)"', tg)
            if m: lk = m.group(1)
        if r.get("type") in ("uses", "used-by", "user-of", "revoked-by"): continue
        if [j, r.get("type")] not in [x[:2] for x in ents[i]["am_rel"]]:
            ents[i]["am_rel"].append([j, r.get("type"), lk])

# ---------------- 8. Google Cloud (Mandiant) APT groups ----------------
for k, g in json.load(open("/tmp/ext/gcp.json")).items():
    c = g.get("suspected attribution", "") or ""
    i = attach_or_new([g["name"]], {"China": "China", "Russia": "Russia", "Iran": "Iran", "North Korea": "North Korea"}.get(c.strip(), ""), "Google Cloud (Mandiant) APT Groups", True)
    ents[i]["gcp"] = dict(attr=c, sectors=clean_desc(g.get("target sectors"), 500), overview=clean_desc(g.get("overview"), 500),
                          malware=clean_desc(g.get("associated malware"), 400), vectors=clean_desc(g.get("attack vectors"), 500))
    if not ents[i]["iso"] and name2iso(c.strip()): ents[i]["iso"] = name2iso(c.strip())
# ---------------- 9. Wikipedia – List of advanced persistent threats ----------------
WC = {"China": "China", "Russia": "Russia", "North Korea": "North Korea", "Iran": "Iran", "Israel": "Israel", "United States": "NATO / Five Eyes",
      "United Kingdom": "NATO / Five Eyes", "Pakistan": "Pakistan", "India": "India", "Vietnam": "Vietnam", "South Korea": "South Korea",
      "Turkey": "Turkey", "Uzbekistan": "Other", "Belarus": "Belarus", "Lebanon": "Middle East", "United Arab Emirates": "Middle East", "Spain": "Spain", "Ukraine": "Ukraine"}
for w in json.load(open("/tmp/ext/wiki_apt.json")):
    names = [n for n in w.get("names", []) if n]
    if not names: continue
    i = attach_or_new(names, WC.get(w.get("country", ""), ""), "Wikipedia APT list", True)
    ents[i]["wiki"] = True
    if not ents[i]["iso"] and name2iso(w.get("country", "")): ents[i]["iso"] = name2iso(w.get("country", ""))

# Malpedia (lista de ids: 'apt28', 'sofacy'...)
mp_norm = {norm(a.replace("_", " ")): a for a in mp}
for e in ents:
    for a in [e["name"]] + e["aliases"]:
        n = norm(a)
        if n in mp_norm:
            e["malpedia"] = mp_norm[n]; e["sources"].add("Malpedia"); break

# APTMalware
for gname, cnt in aptm.items():
    i = best_match([gname])
    if i is not None:
        ents[i]["aptmalware"] += cnt; ents[i]["sources"].add("cyber-research/APTMalware")

# nome canônico = nome MITRE quando houver ID (o nome da planilha vira alias)
for e in ents:
    g = mbyid.get(e["mitre"]) if e["mitre"] else None
    if g and g["name"] != e["name"]:
        e["aliases"].insert(0, e["name"]); e["name"] = g["name"]
# MITRE technique enrichment
gid2stix = {g["id"]: sid for sid, g in mgroups.items()}
LBL2ISO = {"China": "CN", "Russia": "RU", "North Korea": "KP", "Iran": "IR", "Israel": "IL", "India": "IN", "Pakistan": "PK", "Vietnam": "VN",
           "South Korea": "KR", "Turkey": "TR", "Ukraine": "UA", "Belarus": "BY", "Nigeria": "NG", "Brazil": "BR", "Spain": "ES", "Kazakhstan": "KZ",
           "Singapore": "SG", "Thailand": "TH", "Indonesia": "ID", "Malaysia": "MY", "Philippines": "PH", "Colombia": "CO", "Mexico": "MX",
           "Romania": "RO", "Italy": "IT"}
for e in ents:
    g = mbyid.get(e["mitre"]) if e["mitre"] else None
    e["techniques"] = sorted(g["techniques"]) if g else []
    e["proc"] = dict(g["techniques"]) if g else {}
    for t, txt in e["am_ttp"].items():          # procedimentos APTmap só onde MITRE não tem texto
        if t in techidx and not e["proc"].get(t): e["proc"][t] = txt
    e["software"] = sorted(set(g["software"].values())) if g else []
    e["sw_ids"] = sorted(g["software"].keys()) if g else []
    e["campaigns"] = campaigns.get(gid2stix.get(e["mitre"]), []) if g else []
    e["sources"] = sorted(e["sources"])
    e["aliases"] = [a for a in e["aliases"] if norm(a) != norm(e["name"])][:60]
    if not e["iso"]: e["iso"] = LBL2ISO.get(e["country"], "")
    if e["iso"] in ("", None): e["iso"] = ""
    e.pop("am_ttp", None)

print("entidades consolidadas:", len(ents), "| com ISO:", sum(1 for e in ents if e["iso"]), "| APTmap:", sum(1 for e in ents if e["aptmap"]),
      "| GCP:", sum(1 for e in ents if e["gcp"]), "| wiki:", sum(1 for e in ents if e["wiki"]))
for t in techidx.values(): t["mit"] = sorted(set(tech_mit.get(t["id"], [])))
json.dump(dict(ents=ents, tech=techidx, malware=mal, sources=srcs, soft=soft_out, mit_names=mit_names,
               aptm_total=sum(aptm.values())), open("/tmp/build/data2.json", "w"), default=list)

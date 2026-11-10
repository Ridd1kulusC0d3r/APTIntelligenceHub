"""Seleciona regras Sigma por técnica ATT&CK (SigmaHQ + regras próprias do hub) e grava índice para conversão multi-backend.
Critérios: tag exata attack.tXXXX, status (stable>test>experimental), nível (critical>high>medium>low),
pasta (rules > rules-threat-hunting > rules-emerging-threats), evita regras 'deprecated'/'unsupported' e logsources exóticos."""
import json, glob, os, re, yaml, collections, sys
sys.path.insert(0, "/tmp/build")
from detections import PRIORITY

D = json.load(open("/tmp/build/data2.json"))
used = set()
for e in D["ents"]:
    used |= set(e["techniques"])
for s in D["soft"].values():
    used |= set(s["t"])
used |= {t.split(".")[0] for t in used}
print("técnicas em uso por grupos/software:", len(used))

ST = {"stable": 3, "test": 2, "experimental": 1}
LV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
FOLDER = {"rules": 2, "rules-threat-hunting": 1, "rules-emerging-threats": 0}
idx = {}
by_tech = collections.defaultdict(list)
root = "/tmp/ext/sigma-master/"
for f in glob.glob(root + "rules*/**/*.yml", recursive=True):
    folder = f[len(root):].split("/")[0]
    if folder not in FOLDER: continue
    try:
        y = yaml.safe_load(open(f, encoding="utf-8"))
    except Exception:
        continue
    if not isinstance(y, dict) or y.get("status") in ("deprecated", "unsupported") or "correlation" in y: continue
    tags = [t.lower() for t in y.get("tags", []) or []]
    techs = sorted({t.replace("attack.", "").upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})
    if not techs: continue
    rid = y.get("id") or os.path.basename(f)
    ls = y.get("logsource", {}) or {}
    score = ST.get(y.get("status"), 0) * 10 + LV.get(y.get("level"), 0) * 3 + FOLDER[folder] * 4
    rel = f[len(root):]
    idx[rid] = dict(path=f, title=y.get("title", ""), level=y.get("level", ""), status=y.get("status", ""), tags=techs,
                    ls="/".join(str(ls.get(k)) for k in ("product", "category", "service") if ls.get(k)), src="SigmaHQ",
                    url="https://github.com/SigmaHQ/sigma/blob/master/" + rel, score=score, folder=folder,
                    desc=(y.get("description") or "").strip()[:300], fp=[str(x) for x in (y.get("falsepositives") or [])][:3])
    for t in techs: by_tech[t].append(rid)

# seleção: até 3 regras por técnica usada (prioriza diversidade de logsource)
sel = {}
tech_rules = {}
for t in sorted(used):
    cands = sorted(by_tech.get(t, []), key=lambda r: -idx[r]["score"])
    pick, seen_ls = [], set()
    for r in cands:
        if idx[r]["score"] < 26: continue          # exige pelo menos test+medium ou equivalente
        if idx[r]["ls"] in seen_ls and len(cands) > 3: continue
        pick.append(r); seen_ls.add(idx[r]["ls"])
        if len(pick) == 3: break
    if len(pick) < 3:
        for r in cands:
            if r not in pick and idx[r]["score"] >= 26: pick.append(r)
            if len(pick) == 3: break
    if pick:
        tech_rules[t] = pick
        for r in pick: sel[r] = idx[r]
# regras emerging-threats específicas de atores (já ligadas a grupos no hub)
for e in D["ents"]:
    for r in e.get("sigmahq", []):
        rel = r["url"].split("/blob/master/")[1]
        for rid, v in idx.items():
            if v["path"].endswith(rel):
                sel[rid] = v
# regras próprias do hub (detections.py)
os.makedirs("/tmp/build/hub_rules", exist_ok=True)
for p in PRIORITY:
    for y in p["sigma"]:
        d = yaml.safe_load(y); rid = d["id"]
        fn = f"/tmp/build/hub_rules/{rid}.yml"; open(fn, "w").write(y)
        techs = sorted({t.replace("attack.", "").upper() for t in d.get("tags", []) if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})
        ls = d.get("logsource", {})
        sel[rid] = dict(path=fn, title=d["title"], level=d.get("level", ""), status=d.get("status", ""), tags=techs,
                        ls="/".join(str(ls.get(k)) for k in ("product", "category", "service") if ls.get(k)), src="Hub",
                        url="", score=99, folder="hub", desc=(d.get("description") or "")[:300], fp=[str(x) for x in d.get("falsepositives", [])][:3],
                        group=p["mitre"])
        for t in techs:
            tech_rules.setdefault(t, [])
            if rid not in tech_rules[t]: tech_rules[t].insert(0, rid)
json.dump(dict(rules=sel, tech_rules=tech_rules), open("/tmp/build/rules_index.json", "w"))
print("regras SigmaHQ indexadas:", len(idx), "| selecionadas:", len(sel), "| técnicas com regra:", len(tech_rules),
      "| técnicas usadas sem regra:", len([t for t in used if t not in tech_rules]))
print(collections.Counter(v["ls"] for v in sel.values()).most_common(15))

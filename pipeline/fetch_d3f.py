import json, os, time, concurrent.futures as cf, urllib.request
ea = json.load(open("/tmp/ea.json"))["objects"]
objs = {o["id"]: o for o in ea if not o.get("revoked") and not o.get("x_mitre_deprecated")}
def ext(o): return next((e["external_id"] for e in o.get("external_references", []) if e.get("source_name") == "mitre-attack"), None)
tech = {i: ext(o) for i, o in objs.items() if o["type"] == "attack-pattern"}
groups = {i for i, o in objs.items() if o["type"] == "intrusion-set"}
soft = {i for i, o in objs.items() if o["type"] in ("malware", "tool")}
gs = set(); used = set()
for o in objs.values():
    if o["type"] == "relationship" and o["relationship_type"] == "uses" and o["source_ref"] in groups:
        if o["target_ref"] in tech: used.add(tech[o["target_ref"]])
        if o["target_ref"] in soft: gs.add(o["target_ref"])
for o in objs.values():
    if o["type"] == "relationship" and o["relationship_type"] == "uses" and o["source_ref"] in gs and o["target_ref"] in tech:
        used.add(tech[o["target_ref"]])
# add parents
used |= {t.split(".")[0] for t in used if t}
used = sorted(t for t in used if t)
print("techniques to fetch:", len(used))
def get(t):
    fn = f"/tmp/ext/d3f/{t}.json"
    if os.path.exists(fn) and os.path.getsize(fn) > 50: return t, "cached"
    for a in range(3):
        try:
            req = urllib.request.Request(f"https://d3fend.mitre.org/api/offensive-technique/attack/{t}.json", headers={"User-Agent": "cti-research/1.0"})
            data = urllib.request.urlopen(req, timeout=40).read()
            open(fn, "wb").write(data); time.sleep(0.2); return t, "ok"
        except Exception as e:
            err = str(e); time.sleep(2 * (a + 1))
    return t, "fail " + err
with cf.ThreadPoolExecutor(6) as ex:
    res = list(ex.map(get, used))
import collections; print(collections.Counter(r[1].split()[0] for r in res)); print([r for r in res if r[1].startswith("fail")][:10])

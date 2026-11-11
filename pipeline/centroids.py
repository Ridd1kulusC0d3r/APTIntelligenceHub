"""Centróides (lon/lat) de países a partir do world-atlas 50m (TopoJSON) – usados para posicionar grupos/arcos, inclusive países pequenos ausentes no 110m."""
from paths import BUILD, EXT, OUT, RAW, REPO  # diretórios configuráveis: ver pipeline/paths.py
import json, math
t = json.load(open(BUILD + "/vendor/countries-50m.json"))
sc, tr = t["transform"]["scale"], t["transform"]["translate"]
arcs = []
for a in t["arcs"]:
    x = y = 0; pts = []
    for dx, dy in a:
        x += dx; y += dy; pts.append((x * sc[0] + tr[0], y * sc[1] + tr[1]))
    arcs.append(pts)
def ring(idx):
    pts = []
    for i in idx:
        seg = arcs[i] if i >= 0 else arcs[~i][::-1]
        pts += seg[1:] if pts else seg
    return pts
def area_centroid(r):
    xs = [x for x, _ in r]
    if max(xs) - min(xs) > 180: r = [((x + 360) if x < 0 else x, y) for x, y in r]
    A = cx = cy = 0
    for (x0, y0), (x1, y1) in zip(r, r[1:] + r[:1]):
        f = x0 * y1 - x1 * y0; A += f; cx += (x0 + x1) * f; cy += (y0 + y1) * f
    if abs(A) < 1e-12: return 0, r[0]
    return abs(A / 2), (cx / (3 * A), cy / (3 * A))
out = {}
for g in t["objects"]["countries"]["geometries"]:
    polys = [g["arcs"]] if g["type"] == "Polygon" else g.get("arcs", [])
    best = None
    for p in polys:
        if not p: continue
        a, c = area_centroid(ring(p[0]))
        if best is None or a > best[0]: best = (a, c)
    if best:
        lon = best[1][0]; lon = lon - 360 if lon > 180 else lon; best = (best[0], (lon, best[1][1]))
    if best and g.get("id"):
        out[g["id"]] = [round(best[1][0], 2), round(best[1][1], 2)]
    elif best:
        out["name:" + g["properties"]["name"]] = [round(best[1][0], 2), round(best[1][1], 2)]
json.dump(out, open(BUILD + "/centroids.json", "w"))
print(len(out), out.get("076"), out.get("643"), out.get("840"), out.get("702"), out.get("250"))

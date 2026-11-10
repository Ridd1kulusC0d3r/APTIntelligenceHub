// =====================================================================================
// MAPA 2D (D3 geoNaturalEarth1 + TopoJSON world-atlas 110m; centróides do 50m)
// =====================================================================================
const MAP = {init: false, k: 1, selG: null, selC: null};
const NUM2ISO = {}; for (const [iso, v] of Object.entries(ALLC)) NUM2ISO[v[0]] = iso;
function cxy(iso) { const a = ALLC[iso]; if (!a) return null; const c = CENT[a[0]]; return c ? MAP.proj(c) : null; }
function initMap() {
  const el = $("#map"), box = $("#mapbox"); const W = box.clientWidth || 1100, H = box.clientHeight || 620;
  MAP.W = W; MAP.H = H;
  const svg = d3.select(el).attr("viewBox", `0 0 ${W} ${H}`);
  MAP.proj = d3.geoNaturalEarth1().fitExtent([[6, 6], [W - 6, H - 6]], {type: "Sphere"});
  MAP.path = d3.geoPath(MAP.proj);
  const root = svg.append("g"); MAP.root = root;
  root.append("path").datum({type: "Sphere"}).attr("class", "sphere").attr("d", MAP.path);
  root.append("path").datum(d3.geoGraticule10()).attr("class", "grat").attr("d", MAP.path);
  MAP.feats = topojson.feature(WORLD, WORLD.objects.countries).features;
  MAP.byNum = {}; MAP.feats.forEach(f => MAP.byNum[f.id] = f);
  MAP.cg = root.append("g").selectAll("path").data(MAP.feats).join("path").attr("class", "cty").attr("d", MAP.path)
    .on("mousemove", (ev, f) => tipCountry(ev, f)).on("mouseleave", hideTip)
    .on("click", (ev, f) => { const iso = NUM2ISO[f.id]; countryPanel(iso || null, f); });
  MAP.ag = root.append("g").attr("class", "arcs"); MAP.mg = root.append("g").attr("class", "mks");
  MAP.zoom = d3.zoom().scaleExtent([1, 16]).on("zoom", ev => {
    root.attr("transform", ev.transform); MAP.k = ev.transform.k;
    MAP.mg.selectAll("circle").attr("r", d => d.r / Math.pow(MAP.k, .75)).attr("stroke-width", 1 / MAP.k);
    MAP.ag.selectAll("path").attr("stroke-width", d => d.w / Math.pow(MAP.k, .8));
  });
  svg.call(MAP.zoom).on("dblclick.zoom", null);
  $("#mZin").onclick = () => svg.transition().call(MAP.zoom.scaleBy, 1.6);
  $("#mZout").onclick = () => svg.transition().call(MAP.zoom.scaleBy, 1 / 1.6);
  $("#mReset").onclick = () => { MAP.selG = null; MAP.selC = null; svg.transition().call(MAP.zoom.transform, d3.zoomIdentity); renderMap(); };
  ["#mMode", "#mArcs", "#mMk"].forEach(s => $(s).onchange = renderMap);
  $("#mTop").oninput = () => { $("#mTopV").textContent = $("#mTop").value; renderMap(); };
  // posição APTmap válida? (ponto dentro do polígono do país atribuído)
  E.forEach(e => { e._xyok = false; if (e.xy && e.iso && ALLC[e.iso]) { const f = MAP.byNum[ALLC[e.iso][0]]; if (f && d3.geoContains(f, e.xy)) e._xyok = true; } });
  MAP.init = true;
}
function tipCountry(ev, f) {
  const iso = NUM2ISO[f.id]; const o = (MAP.orig || {})[iso] || 0, v = (MAP.vict || {})[iso] || 0;
  tip(ev, `<b>${flag(iso)} ${esc(iso ? cname(iso) : f.properties.name)}</b><br><span class="muted">no recorte atual:</span><br>🎯 visado por <b>${v}</b> grupos<br>🏴 origem de <b>${o}</b> grupos`);
}
function groupTip(e) {
  return `<b>${esc(e.n)}</b> ${e.m ? `<span class="tag m">${e.m}</span>` : ""}<br>${flag(e.iso)} ${esc(cname(e.iso) || e.c)} · ${e.mo.map(m => `<span class="tag" style="border-color:${MCOL[m]}">${m}</span>`).join("") || "<span class=muted>motivação n/i</span>"}<br>
  <span class="muted">${e.nt} técnicas · ${e.ntl} ferramentas · ${e.nv} países-alvo · ${e.ns} fontes</span>${e.sec.length ? "<br>" + e.sec.slice(0, 5).map(s => `<span class="tag c">${esc(s)}</span>`).join("") : ""}`;
}
function arcPath(a, b, bend) { const dx = b[0] - a[0], dy = b[1] - a[1], d = Math.hypot(dx, dy) || 1; const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2 - d * bend; return `M${a[0]},${a[1]}Q${mx},${my} ${b[0]},${b[1]}`; }
function renderMap() {
  if (!MAP.init) initMap();
  const mode = $("#mMode").value, showArcs = $("#mArcs").checked, topN = +$("#mTop").value, showMk = $("#mMk").checked;
  const orig = {}, vict = {};
  FILT.forEach(e => { if (e.iso) orig[e.iso] = (orig[e.iso] || 0) + 1; e.v.forEach(v => vict[v] = (vict[v] || 0) + 1); });
  MAP.orig = orig; MAP.vict = vict;
  const val = mode === "orig" ? orig : mode === "vict" ? vict : {};
  const mx = d3.max(Object.values(val)) || 1;
  const sc = d3.scaleSequentialSqrt([0, mx], mode === "orig" ? d3.interpolateRgb("#16294a", "#4da3ff") : d3.interpolateRgb("#2a1a2e", "#ff5d6c"));
  MAP.cg.attr("fill", f => { const iso = NUM2ISO[f.id]; const v = iso && val[iso]; return v ? sc(v) : "#111a2b"; }).classed("sel", f => NUM2ISO[f.id] && NUM2ISO[f.id] === MAP.selC);
  // marcadores
  const pts = [], cnt = {};
  if (showMk) FILT.forEach(e => {
    if (!e.iso) return; const base = cxy(e.iso); if (!base) return;
    let p = null; if (e._xyok) p = MAP.proj(e.xy);
    if (!p) { const k = cnt[e.iso] = (cnt[e.iso] || 0) + 1; const a = k * 2.39996, r = 3 + 2.4 * Math.sqrt(k); p = [base[0] + Math.cos(a) * r, base[1] + Math.sin(a) * r]; }
    pts.push({e, x: p[0], y: p[1], r: 2.3 + Math.min(7, Math.sqrt(e.nt + e.ntl) / 1.5)});
  });
  MAP.pts = pts;
  MAP.mg.selectAll("circle").data(pts, d => d.e.i).join("circle").attr("cx", d => d.x).attr("cy", d => d.y)
    .attr("r", d => d.r / Math.pow(MAP.k, .75)).attr("fill", d => MCOL[d.e.mo0] || MCOL[""]).attr("stroke", d => ocol(d.e.iso)).attr("stroke-width", 1 / MAP.k)
    .attr("class", d => MAP.selG === d.e.i ? "on" : (MAP.selG !== null ? "dim" : ""))
    .on("mousemove", (ev, d) => tip(ev, groupTip(d.e))).on("mouseleave", hideTip)
    .on("click", (ev, d) => { ev.stopPropagation(); selectGroupOnMap(d.e.i); });
  // arcos
  let arcs = [];
  if (showArcs) {
    if (MAP.selG !== null && E[MAP.selG]) {
      const e = E[MAP.selG], pt = pts.find(p => p.e.i === e.i), a = pt ? [pt.x, pt.y] : cxy(e.iso);
      if (a) e.v.forEach(v => { const b = cxy(v); if (b && v !== e.iso) arcs.push({o: e.iso, v, w: 1.6, n: 1, g: [e.i], a, b, anim: true}); });
    } else {
      const pairs = new Map();
      FILT.forEach(e => { if (!e.iso) return; e.v.forEach(v => { if (v === e.iso) return; const k = e.iso + ">" + v; let o = pairs.get(k); if (!o) { o = {o: e.iso, v, n: 0, g: []}; pairs.set(k, o); } o.n++; if (o.g.length < 40) o.g.push(e.i); }); });
      const focusC = F.vic || MAP.selC;   // país-alvo filtrado ou país clicado: mostra só fluxos que o envolvem
      arcs = [...pairs.values()].filter(p => !focusC || (F.vic ? p.v === F.vic : (p.o === focusC || p.v === focusC)))
        .map(p => Object.assign(p, {a: cxy(p.o), b: cxy(p.v)})).filter(p => p.a && p.b).sort((x, y) => y.n - x.n).slice(0, topN);
      arcs.forEach(p => p.w = 0.6 + Math.log2(1 + p.n) * 0.9);
    }
  }
  MAP.ag.selectAll("path").data(arcs, d => d.o + ">" + d.v + (d.anim ? "*" : "")).join("path")
    .attr("d", d => arcPath(d.a, d.b, .22)).attr("stroke", d => ocol(d.o)).attr("stroke-width", d => d.w / Math.pow(MAP.k, .8)).attr("class", d => d.anim ? "anim" : "")
    .on("mousemove", (ev, d) => tip(ev, `<b>${flag(d.o)} ${esc(cname(d.o))} → ${flag(d.v)} ${esc(cname(d.v))}</b><br>${d.n} grupo(s): ${d.g.slice(0, 8).map(i => esc(E[i].n)).join(", ")}${d.g.length > 8 ? "…" : ""}`))
    .on("mouseleave", hideTip).on("click", (ev, d) => arcPanel(d));
  // legenda
  const top = Object.entries(orig).sort((a, b) => b[1] - a[1]).slice(0, 6);
  $("#mleg").innerHTML = `<div><b style="color:#dbe4f3">${mode === "orig" ? "Origem (atribuição)" : mode === "vict" ? "Alvos (vitimologia)" : "Sem coroplético"}</b> ${mode !== "none" ? `<span style="display:inline-block;width:120px;height:8px;border-radius:4px;vertical-align:middle;margin:0 6px;background:linear-gradient(90deg,${sc(0)},${sc(mx)})"></span>0–${mx} grupos` : ""}</div>
   <div style="margin-top:4px">Ponto (motivação): ${MOTIV.map(m => `<span class="sw" style="background:${MCOL[m]}"></span>${m}`).join("")}<span class="sw" style="background:${MCOL[""]}"></span>n/i</div>
   <div style="margin-top:4px">Arco/borda (origem): ${top.map(([i]) => `<span class="sw" style="background:${ocol(i)}"></span>${esc(cname(i))}`).join("")} · ${pts.length} grupos plotados · ${arcs.length} fluxos · ${FILT.filter(e => !e.iso).length} sem origem (não plotados)</div>`;
}
function selectGroupOnMap(i) { MAP.selG = MAP.selG === i ? null : i; renderMap(); if (MAP.selG !== null) groupPanel(E[i]); }
function byScore(a, b) { return b.score - a.score; }
function glist(arr, max = 60) { return arr.slice(0, max).map(e => `<div class="gl" onclick="openD(${e.i})"><span>${flag(e.iso)} ${esc(e.n)} ${e.m ? `<span class="tag m">${e.m}</span>` : ""}</span><span class="sc">${e.nt}T · ${e.ns}F</span></div>`).join("") + (arr.length > max ? `<div class="note">+${arr.length - max}…</div>` : ""); }
function topTech(groups, n = 12) { const c = {}; groups.forEach(e => e.t.forEach(t => c[t] = (c[t] || 0) + 1)); return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, n); }
function techBars(list, total) { const mx = list.length ? list[0][1] : 1; return list.map(([t, n]) => { const cs = covStat(t); return `<div class="bar" style="cursor:pointer" onclick="techModal('${t}')"><span class="l" title="${esc(TK[t] ? TK[t].n : t)}"><span class="stat st-${cs[0]}" title="${esc(cs[2])}">${cs[1]}</span> ${t} ${esc(TK[t] ? TK[t].n : "")}</span><span class="t"><i style="width:${n / mx * 100}%"></i></span><span class="n">${n}${total ? "/" + total : ""}</span></div>`; }).join(""); }
function countryPanel(iso, f) {
  if (CUR !== "map") showTab("map");
  MAP.selC = iso; MAP.selG = null; renderMap();
  const name = iso ? cname(iso) : (f ? f.properties.name : "?");
  const from = FILT.filter(e => e.iso === iso).sort(byScore), to = FILT.filter(e => e.v.includes(iso)).sort(byScore);
  const tt = topTech(to, 14), sec = {}; to.forEach(e => e.sec.forEach(s => sec[s] = (sec[s] || 0) + 1));
  const mo = {}; to.forEach(e => e.mo.forEach(m => mo[m] = (mo[m] || 0) + 1));
  const oc = {}; to.forEach(e => { if (e.iso) oc[e.iso] = (oc[e.iso] || 0) + 1; });
  $("#mside").innerHTML = `<h3>${flag(iso)} ${esc(name)}</h3>
   <div class="row" style="gap:6px;margin:6px 0">${iso ? `<button class="btn sm" onclick="setF('vic','${iso}')">filtrar como alvo</button><button class="btn sm" onclick="setF('orig','${iso}')">filtrar como origem</button><button class="btn sm pri" onclick="prioFor('${iso}')">🎯 priorizar defesa</button>` : ""}</div>
   <div class="sec"><h4>🎯 Visado por ${to.length} grupos (recorte)</h4>
   ${Object.keys(oc).length ? `<div class="note">Origem dos atacantes: ${Object.entries(oc).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([i, n]) => `${flag(i)} ${esc(cname(i))} (${n})`).join(" · ")}</div>` : ""}
   ${Object.keys(mo).length ? `<div class="note">Motivações: ${Object.entries(mo).sort((a, b) => b[1] - a[1]).map(([m, n]) => `<span class="tag" style="border-color:${MCOL[m]}">${m} ${n}</span>`).join("")}</div>` : ""}
   ${glist(to, 40)}</div>
   ${tt.length ? `<div class="sec"><h4>Técnicas mais usadas contra ${esc(name)}</h4>${techBars(tt, to.length)}<div class="note">● regra disponível · ◐ só ASR/D3FEND · ○ lacuna — clique para o detalhe defensivo.</div></div>` : ""}
   ${Object.keys(sec).length ? `<div class="sec"><h4>Setores visados por esses grupos</h4>${Object.entries(sec).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([s, n]) => `<span class="tag c">${esc(s)} ${n}</span>`).join("")}</div>` : ""}
   <div class="sec"><h4>🏴 Grupos atribuídos a ${esc(name)} (${from.length})</h4>${glist(from, 40) || "<span class=note>—</span>"}</div>`;
  $("#mside").scrollTop = 0;
}
function arcPanel(d) {
  const gs = d.g.map(i => E[i]);
  $("#mside").innerHTML = `<h3>${flag(d.o)} ${esc(cname(d.o))} → ${flag(d.v)} ${esc(cname(d.v))}</h3><div class="note">${d.n} grupo(s) no recorte (listados até 40)</div>${glist(gs, 40)}<div class="sec"><h4>Técnicas comuns nesse fluxo</h4>${techBars(topTech(gs, 10), gs.length)}</div>`;
}
function groupPanel(e) {
  const tt = e.t.slice().sort((a, b) => tacIdx(a) - tacIdx(b));
  $("#mside").innerHTML = `<h3>${esc(e.n)} ${e.m ? `<span class="tag m">${e.m}</span>` : ""}</h3><div class="note">${flag(e.iso)} ${esc(cname(e.iso) || e.c)} · ${e.mo.join(", ") || "motivação n/i"} · ${e.ns} fontes</div>
   <div class="row" style="gap:6px;margin:8px 0"><button class="btn sm pri" onclick="openD(${e.i})">dossiê</button><button class="btn sm" onclick="goTrace(${e.i})">🔗 traçar</button><button class="btn sm" onclick="goGraph('g:${e.i}')">🕸️ ego-rede</button></div>
   <div class="sec"><h4>Países-alvo (${e.v.length})</h4>${e.v.map(v => `<span class="tag cl" onclick="countryPanel('${v}')">${flag(v)} ${esc(cname(v))}</span>`).join("") || "<span class=note>—</span>"}${e.vo.length ? `<div class="note">Outros: ${esc(e.vo.join(", "))}</div>` : ""}</div>
   ${e.sec.length ? `<div class="sec"><h4>Setores</h4>${e.sec.map(s => `<span class="tag c">${esc(s)}</span>`).join("")}</div>` : ""}
   ${e.tl.length ? `<div class="sec"><h4>Ferramentas (${e.tl.length})</h4>${e.tl.slice(0, 40).map(k => `<span class="tag w">${esc(TOOLS[k].n)}</span>`).join("")}</div>` : ""}
   ${tt.length ? `<div class="sec"><h4>Técnicas (${tt.length})</h4>${tt.map(t => { const cs = covStat(t); return `<span class="tag m cl" onclick="techModal('${t}',${e.i})" title="${esc(TK[t] ? TK[t].n : "")} – ${esc(cs[2])}">${cs[1]} ${t}</span>`; }).join("")}</div>` : ""}`;
}
function setF(k, v) { F[k] = v; const id = {vic: "#fVic", orig: "#fOrig", sec: "#fSec"}[k]; if (id) $(id).value = v; applyFilters(); }

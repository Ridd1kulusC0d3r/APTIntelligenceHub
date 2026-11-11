// =====================================================================================
// GRAFO DE RELACIONAMENTOS (d3-force + canvas)
// =====================================================================================
const G = {init: false, focus: null, nodes: [], links: [], sel: null, hover: null, frozen: false, transform: d3.zoomIdentity};
function initGraph() {
  const cv = $("#gcv"); G.cv = cv; G.ctx = cv.getContext("2d");
  const rs = () => { const r = $("#gbox").getBoundingClientRect(); G.W = r.width; G.H = r.height; const dpr = devicePixelRatio || 1; cv.width = r.width * dpr; cv.height = r.height * dpr; G.dpr = dpr; drawGraph(); };
  new ResizeObserver(rs).observe($("#gbox")); rs();
  G.sim = d3.forceSimulation().alphaDecay(0.035).velocityDecay(0.35).on("tick", () => { if (!G.fitted && G.sim.alpha() < 0.12) { G.fitted = true; fitGraph(); } drawGraph(); });
  const sel = d3.select(cv);
  sel.call(d3.drag().container(cv).subject(ev => { const [x, y] = G.transform.invert([ev.x, ev.y]); return G.sim.find(x, y, 14 / G.transform.k) || null; })
    .on("start", ev => { if (!ev.active && !G.frozen) G.sim.alphaTarget(0.25).restart(); ev.subject.fx = ev.subject.x; ev.subject.fy = ev.subject.y; })
    .on("drag", ev => { const [x, y] = G.transform.invert([ev.x, ev.y]); ev.subject.fx = x; ev.subject.fy = y; if (G.frozen) { ev.subject.x = x; ev.subject.y = y; drawGraph(); } })
    .on("end", ev => { if (!ev.active) G.sim.alphaTarget(0); if (!ev.sourceEvent.shiftKey) { ev.subject.fx = null; ev.subject.fy = null; } }))
    .call(G.zoom = d3.zoom().scaleExtent([0.08, 8]).on("zoom", ev => { G.transform = ev.transform; drawGraph(); }))
    .on("dblclick.zoom", null)
    .on("mousemove", ev => { const [px, py] = d3.pointer(ev, cv); const [x, y] = G.transform.invert([px, py]); const n = G.sim.find(x, y, 14 / G.transform.k); if (n !== G.hover) { G.hover = n || null; drawGraph(); } if (n) tip(ev, nodeTip(n)); else hideTip(); })
    .on("mouseleave", () => { G.hover = null; hideTip(); drawGraph(); })
    .on("click", ev => { const [px, py] = d3.pointer(ev, cv); const [x, y] = G.transform.invert([px, py]); const n = G.sim.find(x, y, 14 / G.transform.k); G.sel = n || null; drawGraph(); if (n) nodeInfo(n); });
  $$(".gctl input[data-e]").forEach(c => c.onchange = buildGraph);
  ["#gMinTool", "#gMinTech", "#gLbl", "#gUbiq"].forEach(s => $(s).onchange = () => s === "#gLbl" ? drawGraph() : buildGraph());
  $("#gN").oninput = () => { $("#gNv").textContent = $("#gN").value; }; $("#gN").onchange = buildGraph;
  $("#gBuild").onclick = buildGraph;
  $("#gFreeze").onclick = () => { G.frozen = !G.frozen; $("#gFreeze").textContent = G.frozen ? "retomar física" : "pausar física"; if (G.frozen) G.sim.stop(); else G.sim.alpha(0.3).restart(); };
  $("#gPng").onclick = () => { const a = document.createElement("a"); a.href = G.cv.toDataURL("image/png"); a.download = "apt_relacionamentos.png"; a.click(); };
  $("#gJson").onclick = () => dl("apt_relacionamentos.json", JSON.stringify({nodes: G.nodes.map(n => ({id: n.id, type: n.ty, label: n.lb})), edges: G.links.map(l => ({source: l.source.id, target: l.target.id, type: l.ty, weight: l.w || 1, info: l.info || ""}))}, null, 1), "application/json");
  // lista de nós p/ foco
  const opts = []; E.forEach(e => opts.push(`<option value="g:${e.i}">${esc(e.n)} (grupo)</option>`));
  Object.keys(IDX.orig).concat(Object.keys(IDX.vic)).filter((v, i, a) => a.indexOf(v) === i).forEach(c => opts.push(`<option value="c:${c}">${esc(cname(c))} (país)</option>`));
  Object.keys(IDX.sec).forEach(s => opts.push(`<option value="s:${esc(s)}">${esc(s)} (setor)</option>`));
  TOOLS.filter(t => t.g > 1).forEach(t => opts.push(`<option value="t:${t.i}">${esc(t.n)} (ferramenta)</option>`));
  Object.keys(TK).forEach(t => opts.push(`<option value="k:${t}">${t} ${esc(TK[t].n)} (técnica)</option>`));
  $("#dlNodes").innerHTML = opts.join("");
  $("#gGo").onclick = () => { const v = $("#gFocus").value.trim(); if (!v) return; G.focus = resolveNode(v); buildGraph(); };
  $("#gUnfocus").onclick = () => { G.focus = null; $("#gFocus").value = ""; buildGraph(); };
  G.init = true;
}
function resolveNode(v) {
  if (/^[gcstk]:/.test(v)) return v;
  const lv = v.toLowerCase(); const e = E.find(x => x.n.toLowerCase() === lv || x.a.some(a => a.toLowerCase() === lv)); if (e) return "g:" + e.i;
  if (TK[v.toUpperCase()]) return "k:" + v.toUpperCase(); if (TOOLIX[lv] !== undefined) return "t:" + TOOLIX[lv];
  return null;
}
function goGraph(id) { closeD(); showTab("graph"); G.focus = id; $("#gFocus").value = nodeLabel(id).replace(/^\S+ (?=\S)/, m => /^[\u{1F1E6}-\u{1F1FF}]/u.test(m) ? "" : m); buildGraph(); }
function nodeLabel(id) {
  const [ty, k] = [id[0], id.slice(2)];
  if (ty === "g") return E[+k].n; if (ty === "c") return flag(k) + " " + cname(k); if (ty === "s") return k; if (ty === "t") return TOOLS[+k].n; if (ty === "k") return k + " " + (TK[k] ? TK[k].n : ""); return id;
}
function edgeTypes() { const o = {}; $$(".gctl input[data-e]").forEach(c => o[c.dataset.e] = c.checked); return o; }
// vizinhança de um nó (para foco / BFS) respeitando o recorte FILT
function neighbors(id, ET, allowed) {
  const ty = id[0], k = id.slice(2), out = [];
  const okG = i => allowed.has(i);
  if (ty === "g") {
    const e = E[+k];
    if (ET.attr && e.iso) out.push(["c:" + e.iso, "attr"]);
    if (ET.vic) e.v.forEach(v => out.push(["c:" + v, "vic"]));
    if (ET.sec) e.sec.forEach(s => out.push(["s:" + s, "sec"]));
    if (ET.tool) e.tl.forEach(t => out.push(["t:" + t, "tool"]));
    if (ET.tech) e.t.forEach(t => out.push(["k:" + t, "tech"]));
    if (ET.rel) e.rel.forEach(r => okG(r[0]) && out.push(["g:" + r[0], "rel", r[1] + (r[2] ? " (" + r[2] + ")" : "")]));
    if (ET.sim) e.sim.forEach(r => okG(r[0]) && out.push(["g:" + r[0], "sim", "sim " + r[1]]));
  } else if (ty === "c") {
    if (ET.attr) (IDX.orig[k] || []).filter(okG).forEach(i => out.push(["g:" + i, "attr"]));
    if (ET.vic) (IDX.vic[k] || []).filter(okG).forEach(i => out.push(["g:" + i, "vic"]));
  } else if (ty === "s") { if (ET.sec) (IDX.sec[k] || []).filter(okG).forEach(i => out.push(["g:" + i, "sec"])); }
  else if (ty === "t") {
    if (ET.tool) (IDX.tool[+k] || []).filter(okG).forEach(i => out.push(["g:" + i, "tool"]));
    if (ET.impl) TOOLS[+k].t.forEach(t => TK[t] && out.push(["k:" + t, "impl"]));
  } else if (ty === "k") {
    if (ET.tech) (IDX.tech[k] || []).filter(okG).forEach(i => out.push(["g:" + i, "tech"]));
    if (ET.impl) (IDX.toolTech[k] || []).forEach(t => out.push(["t:" + t, "impl"]));
  }
  return out;
}
function buildGraph() {
  if (!G.init) return;
  const ET = edgeTypes(), N = +$("#gN").value, minTool = +$("#gMinTool").value, minTech = +$("#gMinTech").value, ubiq = $("#gUbiq").checked;
  const allowed = new Set(FILT.map(e => e.i));
  const nodes = new Map(), links = [], lkey = new Set();
  const addN = id => { if (!nodes.has(id)) { const old = G.nodes.find(n => n.id === id); nodes.set(id, {id, ty: id[0], lb: nodeLabel(id), x: old ? old.x : undefined, y: old ? old.y : undefined}); } return nodes.get(id); };
  const addL = (a, b, ty, info) => { const k = a < b ? a + "|" + b + "|" + ty : b + "|" + a + "|" + ty; if (lkey.has(k) || a === b) return; lkey.add(k); links.push({source: a, target: b, ty, info}); };
  if (G.focus) {
    const hops = +$("#gHops").value; const maxN = Math.max(N * 3, 150);
    if (G.focus.startsWith("g:")) allowed.add(+G.focus.slice(2));
    addN(G.focus); let frontier = [G.focus];
    for (let h = 0; h < hops && nodes.size < maxN; h++) {
      const next = [];
      for (const id of frontier) for (const [nb, ty, info] of neighbors(id, ET, allowed)) { if (nodes.size >= maxN && !nodes.has(nb)) continue; if (!nodes.has(nb)) { addN(nb); next.push(nb); } addL(id, nb, ty, info); }
      frontier = next;
    }
    // arestas extra entre nós incluídos
    for (const id of [...nodes.keys()]) for (const [nb, ty, info] of neighbors(id, ET, allowed)) if (nodes.has(nb)) addL(id, nb, ty, info);
  } else {
    const gs = FILT.slice().sort(byScore).slice(0, N); const gset = new Set(gs.map(e => e.i));
    gs.forEach(e => addN("g:" + e.i));
    const tc = {}, kc = {};
    gs.forEach(e => { e.tl.forEach(t => tc[t] = (tc[t] || 0) + 1); e.t.forEach(t => kc[t] = (kc[t] || 0) + 1); });
    gs.forEach(e => {
      const g = "g:" + e.i;
      if (ET.attr && e.iso) { addN("c:" + e.iso); addL(g, "c:" + e.iso, "attr"); }
      if (ET.vic) e.v.forEach(v => { addN("c:" + v); addL(g, "c:" + v, "vic"); });
      if (ET.sec) e.sec.forEach(s => { addN("s:" + s); addL(g, "s:" + s, "sec"); });
      if (ET.tool) e.tl.forEach(t => { if (tc[t] >= minTool && !(ubiq && tc[t] > gs.length * 0.12)) { addN("t:" + t); addL(g, "t:" + t, "tool"); } });
      if (ET.tech) e.t.forEach(t => { if (kc[t] >= minTech) { addN("k:" + t); addL(g, "k:" + t, "tech"); } });
      if (ET.rel) e.rel.forEach(r => { if (gset.has(r[0])) addL(g, "g:" + r[0], "rel", r[1] + (r[2] ? " (" + r[2] + ")" : "")); });
      if (ET.sim) e.sim.forEach(r => { if (gset.has(r[0])) addL(g, "g:" + r[0], "sim", "similaridade " + r[1]); });
    });
    if (ET.impl) for (const id of [...nodes.keys()]) if (id[0] === "t") TOOLS[+id.slice(2)].t.forEach(t => { if (nodes.has("k:" + t)) addL(id, "k:" + t, "impl"); });
  }
  G.nodes = [...nodes.values()]; G.links = links;
  const deg = {}; links.forEach(l => { deg[l.source] = (deg[l.source] || 0) + 1; deg[l.target] = (deg[l.target] || 0) + 1; });
  G.nodes.forEach(n => { n.deg = deg[n.id] || 0; n.r = n.ty === "g" ? 4 + Math.min(10, Math.sqrt(n.deg) * 1.4) : n.ty === "k" ? 2.5 + Math.min(6, Math.sqrt(n.deg)) : 3 + Math.min(9, Math.sqrt(n.deg) * 1.2); if (n.x === undefined) { n.x = G.W / 2 + (Math.random() - .5) * 300; n.y = G.H / 2 + (Math.random() - .5) * 300; } });
  const LD = {attr: 60, vic: 90, sec: 70, tool: 55, tech: 80, impl: 60, rel: 45, sim: 50};
  G.sim.nodes(G.nodes).force("link", d3.forceLink(G.links).id(d => d.id).distance(l => LD[l.ty] || 60).strength(l => l.ty === "vic" || l.ty === "tech" ? 0.08 : 0.25))
    .force("charge", d3.forceManyBody().strength(n => n.ty === "g" ? -150 : n.ty === "k" ? -35 : -60).distanceMax(650)).force("collide", d3.forceCollide(n => n.r + 4))
    .force("x", d3.forceX(G.W / 2).strength(0.03)).force("y", d3.forceY(G.H / 2).strength(0.03));
  G.lblRank = G.nodes.filter(n => n.ty === "g" || n.ty === "t").sort((a, b) => b.deg - a.deg).map(n => n.id);
  G.fitted = false;
  G.focusNode = G.focus ? G.nodes.find(n => n.id === G.focus) || null : null; G.sel = null;
  if (G.focusNode) { G.focusNode.fx = null; G.focusNode.fy = null; }
  if (!G.frozen) G.sim.alpha(1).restart(); else drawGraph();
  const byT = {}; G.nodes.forEach(n => byT[n.ty] = (byT[n.ty] || 0) + 1); const byE = {}; links.forEach(l => byE[l.ty] = (byE[l.ty] || 0) + 1);
  const TN = {g: "grupos", c: "países", s: "setores", t: "ferramentas", k: "técnicas"};
  $("#gstat").innerHTML = `${G.focus ? "🎯 ego-rede de <b>" + esc(nodeLabel(G.focus)) + "</b> · " : ""}${G.nodes.length} nós (${Object.entries(byT).map(([k, v]) => v + " " + TN[k]).join(", ")}) · ${links.length} arestas (${Object.entries(byE).map(([k, v]) => k + ":" + v).join(", ")})${links.length > 6000 ? " · ⚠ denso: reduza escopo" : ""}`;
  if (G.focusNode) nodeInfo(G.focusNode);
}
function nColor(n) { if (n.ty === "g") { const e = E[+n.id.slice(2)]; return ocol(e.iso); } return NCOL[n.ty]; }
function drawGraph() {
  const c = G.ctx; if (!c) return; const t = G.transform, dpr = G.dpr || 1;
  c.setTransform(dpr, 0, 0, dpr, 0, 0); c.clearRect(0, 0, G.W, G.H); c.save(); c.translate(t.x, t.y); c.scale(t.k, t.k);
  const focusN = G.hover || G.sel; let nb = null;
  if (focusN) { nb = new Set([focusN.id]); G.links.forEach(l => { if (l.source.id === focusN.id) nb.add(l.target.id); if (l.target.id === focusN.id) nb.add(l.source.id); }); }
  for (const l of G.links) {
    const on = nb && (l.source.id === focusN.id || l.target.id === focusN.id);
    c.globalAlpha = nb ? (on ? .85 : .04) : (l.ty === "tech" || l.ty === "vic" ? .10 : .28);
    c.strokeStyle = ECOL[l.ty]; c.lineWidth = (on ? 1.8 : (l.ty === "sim" || l.ty === "rel" ? 1.4 : .8)) / Math.sqrt(t.k);
    if (l.ty === "sim" || l.ty === "rel") c.setLineDash([4 / t.k, 3 / t.k]); else c.setLineDash([]);
    c.beginPath(); c.moveTo(l.source.x, l.source.y); c.lineTo(l.target.x, l.target.y); c.stroke();
  }
  c.setLineDash([]);
  const lblMode = +($("#gLbl") ? $("#gLbl").value : 1);
  for (const n of G.nodes) {
    const dim = nb && !nb.has(n.id); c.globalAlpha = dim ? .15 : 1; c.fillStyle = nColor(n);
    c.beginPath();
    if (n.ty === "g") c.arc(n.x, n.y, n.r, 0, 6.2832);
    else if (n.ty === "c") { c.rect(n.x - n.r, n.y - n.r, n.r * 2, n.r * 2); }
    else if (n.ty === "s") { c.moveTo(n.x, n.y - n.r * 1.2); c.lineTo(n.x + n.r * 1.1, n.y); c.lineTo(n.x, n.y + n.r * 1.2); c.lineTo(n.x - n.r * 1.1, n.y); c.closePath(); }
    else if (n.ty === "t") { c.moveTo(n.x, n.y - n.r * 1.2); c.lineTo(n.x + n.r * 1.1, n.y + n.r * .9); c.lineTo(n.x - n.r * 1.1, n.y + n.r * .9); c.closePath(); }
    else c.arc(n.x, n.y, n.r, 0, 6.2832);
    c.fill();
    if (n === G.sel || n === G.hover) { c.lineWidth = 2 / t.k; c.strokeStyle = "#fff"; c.stroke(); }
    if (n === G.focusNode) { c.beginPath(); c.arc(n.x, n.y, n.r + 5 / t.k, 0, 6.2832); c.lineWidth = 2 / t.k; c.strokeStyle = "#e8c25a"; c.stroke(); }
    else if (n.ty === "g") { c.lineWidth = 1 / t.k; c.strokeStyle = MCOL[E[+n.id.slice(2)].mo0] || "#0008"; c.stroke(); }
  }
  c.font = `${11 / Math.sqrt(t.k)}px Segoe UI, sans-serif`; c.textAlign = "center";
  const topK = Math.round(18 * t.k * t.k), lblSet = G.lblRank ? new Set(G.lblRank.slice(0, topK)) : new Set();
  for (const n of G.nodes) {
    const show = lblMode === 2 || (lblMode === 1 && ((nb && nb.has(n.id)) || lblSet.has(n.id) || n.ty === "s" || (n.ty === "c" && n.deg > 2)));
    if (!show || (nb && !nb.has(n.id) && lblMode !== 2)) continue;
    c.globalAlpha = 1; c.fillStyle = n.ty === "g" ? "#eeebe2" : n.ty === "k" ? "#d9cfee" : n.ty === "t" ? "#f6d3a8" : n.ty === "s" ? "#a8e3c4" : "#f3dc9a";
    const lb = n.ty === "k" ? n.id.slice(2) : n.lb; c.fillText(lb.length > 28 ? lb.slice(0, 27) + "…" : lb, n.x, n.y - n.r - 3);
  }
  c.restore();
}
function nodeTip(n) {
  const ty = n.id[0], k = n.id.slice(2);
  if (ty === "g") return groupTip(E[+k]);
  if (ty === "k") { const cs = covStat(k); return `<b>${k}</b> ${esc(TK[k] ? TK[k].n : "")}<br><span class="muted">${(TK[k] ? TK[k].ta : []).map(x => TACPT[x]).join(", ")}</span><br>${TK[k] ? TK[k].ng : 0} grupos · cobertura: ${cs[1]} ${esc(cs[2])}`; }
  if (ty === "t") { const t = TOOLS[+k]; return `<b>${esc(t.n)}</b> ${t.s ? `<span class="tag m">${t.s}</span>` : ""}<br><span class="muted">${esc(t.ty)} · ${t.g} grupos · ${t.t.length} técnicas</span><br>${esc((t.d || "").slice(0, 200))}`; }
  return `<b>${esc(n.lb)}</b><br>${n.deg} conexões`;
}
function nodeInfo(n) {
  const ty = n.id[0], k = n.id.slice(2);
  const nbs = G.links.filter(l => l.source.id === n.id || l.target.id === n.id).map(l => ({o: l.source.id === n.id ? l.target : l.source, ty: l.ty, info: l.info}));
  const grp = {}; nbs.forEach(x => (grp[x.ty] = grp[x.ty] || []).push(x));
  const EN = {attr: "atribuição", vic: "ataca país", sec: "ataca setor", tool: "usa ferramenta", tech: "usa técnica", impl: "implementa técnica", rel: "relação declarada", sim: "similaridade"};
  let h = `<h3 style="margin:0 0 4px">${esc(n.lb)}</h3><div class="note">${{g: "Grupo", c: "País", s: "Setor", t: "Ferramenta/malware", k: "Técnica ATT&CK"}[ty]} · ${n.deg} conexões no grafo</div><div class="row" style="gap:6px;margin:8px 0">
   <button class="btn sm" onclick="G.focus='${esc(n.id)}';buildGraph()">🎯 focar</button>`;
  if (ty === "g") h += `<button class="btn sm pri" onclick="openD(${k})">dossiê</button><button class="btn sm" onclick="goTrace(${k})">🔗 traçar</button>`;
  if (ty === "k") h += `<button class="btn sm pri" onclick="techModal('${k}')">detalhe defensivo</button><button class="btn sm" onclick="setF('tech','${k}');$('#fTech').value='${k}'">filtrar</button>`;
  if (ty === "c") h += `<button class="btn sm" onclick="countryPanel('${k}')">no mapa</button>`;
  if (ty === "t") h += `<button class="btn sm" onclick="setTool(${k})">filtrar grupos</button>`;
  h += `</div>`;
  if (ty === "t") { const t = TOOLS[+k]; h += `<div class="note">${esc(t.d || "")}</div>${t.s ? `<a target="_blank" rel="noopener noreferrer" href="https://attack.mitre.org/software/${t.s}/">ATT&CK ${t.s} ↗</a>` : ""}`; }
  if (ty === "g") { const e = E[+k]; h += `<div class="note">${esc((e.d || "").slice(0, 320))}</div>`; }
  for (const [t, arr] of Object.entries(grp)) {
    h += `<div class="sec"><h4><span class="sw" style="display:inline-block;width:12px;height:3px;background:${ECOL[t]};vertical-align:middle;margin-right:4px"></span>${EN[t]} (${arr.length})</h4>${arr.slice(0, 80).map(x => `<div class="gl" onclick="G.sel=G.nodes.find(n=>n.id==='${esc(x.o.id)}');drawGraph();nodeInfo(G.sel)"><span>${esc(x.o.lb)}</span><span class="sc">${esc(x.info || "")}</span></div>`).join("")}</div>`;
  }
  $("#ginfo").innerHTML = h;
}
function setTool(k) { F.tool = TOOLS[k].n.toLowerCase(); $("#fTool").value = TOOLS[k].n; applyFilters(); }
function fitGraph() {
  if (!G.nodes.length) return; const xs = G.nodes.map(n => n.x), ys = G.nodes.map(n => n.y);
  const x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys);
  const k = Math.min(2.2, 0.92 * Math.min(G.W / Math.max(40, x1 - x0), G.H / Math.max(40, y1 - y0)));
  const tr = d3.zoomIdentity.translate(G.W / 2 - k * (x0 + x1) / 2, G.H / 2 - k * (y0 + y1) / 2).scale(k);
  d3.select(G.cv).transition().duration(600).call(G.zoom.transform, tr);
}

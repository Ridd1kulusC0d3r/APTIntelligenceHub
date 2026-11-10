// =====================================================================================
// TRAÇAGEM: grupo → ferramenta/artefato → técnica → Defender → D3FEND → DeTT&CT → RE&CT
// =====================================================================================
const TR = {e: null, sel: null, links: [], items: {}};
function initTraceUI() {
  $("#trTac").insertAdjacentHTML("beforeend", TAC.map(t => `<option value="${t}">${TACPT[t]}</option>`).join(""));
  $("#trFmt").innerHTML = FMT.map(([k, l]) => `<option value="${k}">${l}</option>`).join("");
  const def = E.find(e => e.m === "G0007") || E.slice().sort(byScore)[0];
  TR.e = def; fillTraceSel();
  $("#trQ2").addEventListener("input", fillTraceSel);
  $("#trG").addEventListener("change", () => { const e = E[+$("#trG").value]; if (e) { TR.e = e; TR.sel = null; renderTrace(); } });
  const step = d => { const o = [...$("#trG").options].filter(x => x.value !== ""); const k = o.findIndex(x => +x.value === TR.e.i); const n = o[(k + d + o.length) % o.length]; if (n) { $("#trG").value = n.value; TR.e = E[+n.value]; TR.sel = null; renderTrace(); } };
  $("#trPrev").onclick = () => step(-1); $("#trNext").onclick = () => step(1);
  ["#trVia", "#trTac", "#trTop"].forEach(s => $(s).onchange = () => { TR.sel = null; renderTrace(); });
  window.addEventListener("resize", () => { if (CUR === "trace") drawTraceLinks(); });
  $("#trNav").onclick = () => { const e = TR.e; const ts = techSet(e, $("#trVia").checked); const sc = {}, cm = {}; ts.forEach((o, t) => { sc[t] = o.d ? 2 : 1; cm[t] = (o.d ? (e.p[t] || "uso direto") : "") + (o.tools.length ? " | via: " + o.tools.map(k => TOOLS[k].n).join(", ") : ""); }); dl(`navigator_${slug(e.n)}.json`, JSON.stringify(navLayer(`${e.n} – APT Threat Map`, sc, cm, `Técnicas de ${e.n} (2=procedimento direto, 1=via ferramenta)`), null, 1), "application/json"); };
  $("#trDG").onclick = () => dl(`dettect_group_${slug(TR.e.n)}.yaml`, dettectGroup([TR.e], TR.e.n, $("#trVia").checked));
  $("#trDS").onclick = () => { const t = [...techSet(TR.e, $("#trVia").checked).keys()]; dl(`dettect_datasources_${slug(TR.e.n)}.yaml`, dettectDS(t, `${TR.e.n} – data sources necessários`)); };
  $("#trDT").onclick = () => { const t = [...techSet(TR.e, $("#trVia").checked).keys()]; dl(`dettect_techniques_${slug(TR.e.n)}.yaml`, dettectTech(t, `${TR.e.n} – administração de técnicas`)); };
  $("#trRP").onclick = () => { const t = [...techSet(TR.e, $("#trVia").checked).keys()]; dl(`react_playbook_${slug(TR.e.n)}.yml`, reactPlaybook(t, TR.e.n)); };
  $("#trSig").onclick = () => { const t = [...techSet(TR.e, $("#trVia").checked).keys()]; dl(`sigma_${slug(TR.e.n)}.yml`, sigmaBundle(t)); };
  $("#trQ").onclick = () => { const t = [...techSet(TR.e, $("#trVia").checked).keys()]; const f = $("#trFmt").value; dl(`queries_${f}_${slug(TR.e.n)}.txt`, queriesBundle(t, f, TR.e.n)); };
  $("#trCsv").onclick = () => dl(`tracagem_${slug(TR.e.n)}.csv`, traceCsv(TR.e, $("#trVia").checked), "text/csv;charset=utf-8");
}
function findGroup(v) { const lv = v.trim().toLowerCase(); return E.find(x => x.n.toLowerCase() === lv) || E.find(x => x.m.toLowerCase() === lv) || E.find(x => x.a.some(a => a.toLowerCase() === lv)) || E.find(x => x.n.toLowerCase().includes(lv)); }
function goTrace(i) { closeD(); closeM(); TR.e = E[i]; TR.sel = null; $("#trQ2").value = ""; fillTraceSel(); showTab("trace"); }
function fillTraceSel() {
  // lista agrupada por origem; só grupos com técnicas ou ferramentas (traçáveis); respeita o texto de filtro
  const q = ($("#trQ2").value || "").toLowerCase().trim();
  const L = E.filter(e => (e.nt || e.ntl) && (!q || q.split(/\s+/).every(w => e._s.includes(w) || (cname(e.iso) || "").toLowerCase().includes(w))));
  const by = {}; L.forEach(e => (by[e.iso ? cname(e.iso) : "Sem origem atribuída"] = by[e.iso ? cname(e.iso) : "Sem origem atribuída"] || []).push(e));
  const keys = Object.keys(by).sort((a, b) => by[b].length - by[a].length);
  if (TR.e && !L.includes(TR.e) && L.length) TR.e = L.slice().sort(byScore)[0];
  $("#trG").innerHTML = keys.map(k => `<optgroup label="${esc(k)} (${by[k].length})">${by[k].sort((a, b) => b.nt - a.nt || a.n.localeCompare(b.n)).map(e => `<option value="${e.i}">${esc(e.n)}${e.m ? " · " + e.m : ""} — ${e.nt}T/${e.ntl}F</option>`).join("")}</optgroup>`).join("") || `<option value="">nenhum grupo</option>`;
  if (TR.e) $("#trG").value = TR.e.i;
  $("#trGn").textContent = L.length + " grupos traçáveis";
  if (CUR === "trace" && q) renderTrace();
}
function agg(techs, fn) { const m = new Map(); techs.forEach(t => fn(t).forEach(([key, label, sub, extra]) => { let o = m.get(key); if (!o) { o = {key, label, sub, extra, techs: []}; m.set(key, o); } if (!o.techs.includes(t)) o.techs.push(t); })); return [...m.values()].sort((a, b) => b.techs.length - a.techs.length || String(a.label).localeCompare(b.label)); }
function renderTrace() {
  const e = TR.e; if (!e) return;
  const via = $("#trVia").checked, tac = $("#trTac").value, topN = +$("#trTop").value;
  let ts = techSet(e, via);
  if (!e.t.length && !via && e.tl.some(k => TOOLS[k].t.length)) { $("#trVia").checked = true; ts = techSet(e, true); }
  const techs = [...ts.keys()].filter(t => TK[t] && (!tac || TK[t].ta.includes(tac))).sort((a, b) => tacIdx(a) - tacIdx(b) || a.localeCompare(b));
  const tset = new Set(techs);
  const tools = e.tl.map(k => ({k, n: TOOLS[k].n, s: TOOLS[k].s, techs: TOOLS[k].t.filter(t => tset.has(t))})).sort((a, b) => b.techs.length - a.techs.length || a.n.localeCompare(b.n));
  const mde = agg(techs, t => [...TK[t].asr.map(a => ["asr:" + a, "🛡 ASR: " + ASR[a][1], ASR[a][0].slice(0, 8) + "… · " + (ASR[a][2] || "sem ActionType AH")]), ...TK[t].mde.map(tb => ["mde:" + tb, "🗄 " + tb, mdeProd(tb.split(":")[0].split(" ")[0])])])
    .sort((a, b) => (b.key.startsWith("asr:") - a.key.startsWith("asr:")) || b.techs.length - a.techs.length);
  const d3f = agg(techs, t => [...new Set(TK[t].d3.map(r => r[0]))].map(id => ["d3:" + id, D3[id][0], D3[id][1] + " · " + id])).sort((a, b) => b.techs.length - a.techs.length || D3ORD.indexOf(D3[a.key.slice(3)][1]) - D3ORD.indexOf(D3[b.key.slice(3)][1]));
  const dcs = agg(techs, t => TK[t].dc.map(dc => ["dc:" + dc, dc, ""]));
  const ras = agg(techs, t => TK[t].ra.map(r => ["ra:" + r, RA[r][0], STGPT[RA[r][1]] || RA[r][1]]));
  const raBy = {}; ras.forEach(r => { const st = RA[r.key.slice(3)][1]; (raBy[st] = raBy[st] || []).push(r); });
  const per = Math.max(3, Math.round(topN / 4));
  // itens "fixados": relacionados à seleção atual aparecem mesmo fora do top-N
  const pin = new Set(); const pinT = TR.sel && TR.sel.startsWith("k:") ? [TR.sel.slice(2)] : TR.sel && TR.sel.startsWith("t:") ? (tools.find(t => "t:" + t.k === TR.sel) || {techs: []}).techs : [];
  pinT.forEach(t => { if (!TK[t]) return; TK[t].asr.forEach(a => pin.add("asr:" + a)); TK[t].mde.forEach(x => pin.add("mde:" + x)); TK[t].d3.forEach(r => pin.add("d3:" + r[0])); TK[t].dc.forEach(x => pin.add("dc:" + x)); TK[t].ra.forEach(x => pin.add("ra:" + x)); });
  TR.items = {}; const links = [];
  const item = (key, label, sub, count, cls = "", color = "") => { TR.items[key] = 1; return `<div class="ti ${cls}" data-k="${esc(key)}" style="${color ? "border-left-color:" + color : ""}">${count !== undefined ? `<span class="c">${count}</span>` : ""}${esc(label)}${sub ? `<small>${esc(sub)}</small>` : ""}</div>`; };
  let h = "";
  h += `<div class="tcol"><h4>Grupo</h4>${item("g:" + e.i, e.n, (e.m ? e.m + " · " : "") + (cname(e.iso) || e.c), undefined, "", ocol(e.iso))}
        <div class="note" style="margin-top:6px">${e.mo.map(m => `<span class="tag" style="border-color:${MCOL[m]}">${m}</span>`).join("")}<br>${e.ns} fontes · ${e.nv} países-alvo<br>${e.sec.slice(0, 4).map(s => `<span class="tag c">${esc(s)}</span>`).join("")}</div>
        <div class="row" style="gap:4px;margin-top:6px"><button class="btn sm" onclick="openD(${e.i})">dossiê</button><button class="btn sm" onclick="goGraph('g:${e.i}')">ego-rede</button></div></div>`;
  h += `<div class="tcol"><h4><span>Artefatos / ferramentas</span><span>${tools.length}</span></h4>${tools.length ? tools.slice(0, Math.max(topN, 25)).map(t => item("t:" + t.k, t.n, (t.s ? t.s + " · " : "") + (t.techs.length ? t.techs.length + " técnicas no recorte" : TOOLS[t.k].ty), undefined, "", t.s ? "#ff9f43" : "#7a5a32")).join("") : `<div class="note">Sem ferramentas mapeadas.</div>`}${tools.length > Math.max(topN, 25) ? `<div class="note">+${tools.length - Math.max(topN, 25)} ferramentas</div>` : ""}</div>`;
  let lastTac = ""; let th = "";
  techs.forEach(t => {
    const ta = TAC[tacIdx(t)] || ""; if (ta !== lastTac) { th += `<div class="tacsep">${TACPT[ta] || ta}</div>`; lastTac = ta; }
    const o = ts.get(t), cs = covStat(t);
    th += item("k:" + t, `${cs[1]} ${t} ${TK[t].n}`, o.d ? (e.p[t] ? "procedimento documentado" : "uso direto") : "via " + o.tools.map(k => TOOLS[k].n).slice(0, 3).join(", "), undefined, "", cs[0] === "ok" ? "#2ecc8f" : cs[0] === "pa" ? "#ffb347" : "#ff5d6c");
    if (o.d) links.push(["g:" + e.i, "k:" + t]);
    o.tools.forEach(k => links.push(["t:" + k, "k:" + t]));
  });
  tools.forEach(t => links.push(["g:" + e.i, "t:" + t.k]));
  h += `<div class="tcol"><h4><span>Técnicas ATT&CK</span><span>${techs.length}</span></h4>${th || `<div class="note">Sem técnicas ATT&CK documentadas para este grupo${e.tl.length ? " (tente incluir técnicas via ferramentas)" : ""}.</div>`}</div>`;
  const col = (title, arr, n, color) => { const shown = arr.filter((x, i) => i < n || pin.has(x.key)); return `<div class="tcol"><h4><span>${title}</span><span>${arr.length}</span></h4>${shown.map(x => item(x.key, x.label, x.sub, x.techs.length, "", typeof color === "function" ? color(x) : color)).join("")}${arr.length > shown.length ? `<div class="note">+${arr.length - shown.length} (aumente “top/coluna” ou selecione uma técnica)</div>` : ""}</div>`; };
  h += col("Microsoft Defender", mde, topN, x => x.key.startsWith("asr") ? "#2ecc8f" : "#4da3ff");
  h += col("MITRE D3FEND", d3f, topN, x => D3COL[D3[x.key.slice(3)][1]] || "#888");
  h += col("DeTT&CT · data sources", dcs, topN, "#f5c542");
  h += `<div class="tcol"><h4><span>RE&CT · resposta</span><span>${ras.length}</span></h4>${STG.map(st => raBy[st] ? `<div class="tacsep">${STGPT[st]}</div>` + raBy[st].filter((x, i) => i < per || pin.has(x.key)).map(x => item(x.key, x.label, x.key.slice(3), x.techs.length, "", "#c084fc")).join("") : "").join("")}</div>`;
  [mde, d3f, dcs, ras].forEach(arr => arr.forEach(x => x.techs.forEach(t => links.push(["k:" + t, x.key]))));
  $("#trcols").innerHTML = h; TR.links = links.filter(([a, b]) => TR.items[a] && TR.items[b]);
  TR.agg = {mde, d3f, dcs, ras, techs, tools, ts};
  $$("#trcols .ti").forEach(el => { el.onmouseenter = () => hlTrace(el.dataset.k, false); el.onmouseleave = () => hlTrace(TR.sel, false); el.onclick = () => { const k = el.dataset.k; const sc = [...$$("#trcols .tcol")].map(c => c.scrollTop); TR.sel = k; if (/^[kt]:/.test(k)) { renderTrace(); $$("#trcols .tcol").forEach((c, i) => c.scrollTop = sc[i] || 0); } hlTrace(TR.sel, true); revealTrace(); traceDetail(TR.sel); }; });
  $$("#trcols .tcol").forEach(c => c.addEventListener("scroll", () => { if (!TR.raf) TR.raf = requestAnimationFrame(() => { TR.raf = 0; drawTraceLinks(); hlTrace(TR.sel); }); }, {passive: true}));
  requestAnimationFrame(() => { drawTraceLinks(); if (TR.sel) hlTrace(TR.sel); });
  if (!TR.sel) $("#trdet").innerHTML = traceSummary();
}
function drawTraceLinks() {
  const wrap = $("#trcols"), svg = $("#trsvg"); if (!wrap) return;
  const wr = wrap.getBoundingClientRect(); svg.setAttribute("width", wrap.scrollWidth); svg.setAttribute("height", wrap.scrollHeight);
  svg.style.left = wrap.offsetLeft + "px"; svg.style.top = wrap.offsetTop + "px";
  const pos = {}; $$("#trcols .ti").forEach(el => { const r = el.getBoundingClientRect(), col = el.closest(".tcol").getBoundingClientRect(); let yc = r.top + r.height / 2; const vis = yc >= col.top + 20 && yc <= col.bottom - 2; yc = Math.max(col.top + 20, Math.min(col.bottom - 2, yc)); pos[el.dataset.k] = [r.left - wr.left, r.right - wr.left, yc - wr.top, vis]; });
  svg.innerHTML = TR.links.map(([a, b], i) => { const p = pos[a], q = pos[b]; if (!p || !q || (!p[3] && !q[3])) return ""; const x1 = p[1], y1 = p[2], x2 = q[0], y2 = q[2], mx = (x1 + x2) / 2; const rc = /^(asr|mde|d3|dc|ra):/.test(b) ? ' class="r"' : ""; return `<path${rc} data-i="${i}" data-a="${esc(a)}" data-b="${esc(b)}" d="M${x1},${y1}C${mx},${y1} ${mx},${y2} ${x2},${y2}"/>`; }).join("");
}
function hlTrace(key) {
  const paths = $$("#trsvg path"), items = $$("#trcols .ti");
  if (!key) { paths.forEach(p => p.classList.remove("hl")); items.forEach(el => el.classList.remove("hl", "dim", "sel")); return; }
  const on = new Set([key]), lk = new Set();
  const adj = {}; TR.links.forEach(([a, b], i) => { (adj[a] = adj[a] || []).push([b, i, 1]); (adj[b] = adj[b] || []).push([a, i, -1]); });
  const order = ["g", "t", "k", "asr", "mde", "d3", "dc", "ra"];
  const rank = k => { const p = k.split(":")[0]; return p === "g" ? 0 : p === "t" ? 1 : p === "k" ? 2 : 3; };
  // propaga para a esquerda e para a direita a partir do item (sem "voltar")
  const walk = (start, dir) => { const st = [start]; const seen = new Set([start]); while (st.length) { const x = st.pop(); (adj[x] || []).forEach(([y, i]) => { if ((dir > 0 && rank(y) > rank(x)) || (dir < 0 && rank(y) < rank(x))) { lk.add(i); on.add(y); if (!seen.has(y)) { seen.add(y); if (rank(y) < 3 || dir < 0) st.push(y); } } }); } };
  walk(key, 1); walk(key, -1);
  if (rank(key) === 3) { // item defensivo → técnicas → ferramentas/grupo
    (adj[key] || []).forEach(([y, i]) => { lk.add(i); on.add(y); walk(y, -1); });
  }
  paths.forEach(p => p.classList.toggle("hl", lk.has(+p.dataset.i)));
  items.forEach(el => { const k = el.dataset.k; el.classList.toggle("hl", on.has(k) && k !== key); el.classList.toggle("dim", !on.has(k)); el.classList.toggle("sel", k === TR.sel); });
}
function traceSummary() {
  const a = TR.agg, e = TR.e; if (!a) return "";
  const cov = {ok: 0, pa: 0, gap: 0}; a.techs.forEach(t => cov[covStat(t)[0]]++);
  const gaps = a.techs.filter(t => covStat(t)[0] === "gap");
  return `<div class="grid">
   <div class="card"><h3>Cobertura do grupo ${esc(e.n)}</h3><div class="row" style="gap:16px;font-size:13px"><span class="stat st-ok">● ${cov.ok} com regra</span><span class="stat st-pa">◐ ${cov.pa} parcial</span><span class="stat st-gap">○ ${cov.gap} lacunas</span></div>
   <div class="bar" style="margin-top:8px"><span class="l">cobertura por regra</span><span class="t"><i style="width:${a.techs.length ? cov.ok / a.techs.length * 100 : 0}%"></i></span><span class="n">${a.techs.length ? Math.round(cov.ok / a.techs.length * 100) : 0}%</span></div>
   ${gaps.length ? `<div class="note" style="margin-top:6px">Lacunas (backlog de engenharia de detecção): ${gaps.slice(0, 30).map(t => `<span class="tag r cl" onclick="techModal('${t}',${e.i})">${t}</span>`).join("")}</div>` : ""}</div>
   <div class="card"><h3>Contramedidas D3FEND de maior alavancagem</h3>${a.d3f.slice(0, 10).map(x => `<div class="bar"><span class="l"><span class="d3t" style="background:${D3COL[D3[x.key.slice(3)][1]]}"></span>${esc(x.label)}</span><span class="t"><i style="width:${x.techs.length / (a.d3f[0] ? a.d3f[0].techs.length : 1) * 100}%"></i></span><span class="n">${x.techs.length}</span></div>`).join("") || "<span class=note>—</span>"}<p class="note">Nº de técnicas do grupo cobertas por cada contramedida.</p></div>
   <div class="card"><h3>Telemetria prioritária (DeTT&CT)</h3>${a.dcs.slice(0, 10).map(x => `<div class="bar"><span class="l">${esc(x.label)}</span><span class="t"><i style="width:${x.techs.length / (a.dcs[0] ? a.dcs[0].techs.length : 1) * 100}%"></i></span><span class="n">${x.techs.length}</span></div>`).join("") || "<span class=note>—</span>"}<p class="note">Data components ATT&CK exigidos pelas técnicas (use o YAML DeTT&CT para pontuar qualidade).</p></div>
   <div class="card"><h3>Defender – ASR e tabelas</h3>${a.mde.slice(0, 10).map(x => `<div class="bar"><span class="l" title="${esc(x.label)}">${esc(x.label)}</span><span class="t"><i style="width:${x.techs.length / (a.mde[0] ? a.mde[0].techs.length : 1) * 100}%"></i></span><span class="n">${x.techs.length}</span></div>`).join("") || "<span class=note>—</span>"}</div>
  </div>`;
}
function traceDetail(key) {
  const [p, k] = [key.split(":")[0], key.slice(key.indexOf(":") + 1)]; const e = TR.e; let h = "";
  if (p === "k") h = techDetail(k, e.i);
  else if (p === "g") h = traceSummary();
  else {
    const it = [...TR.agg.mde, ...TR.agg.d3f, ...TR.agg.dcs, ...TR.agg.ras].find(x => x.key === key);
    const list = it ? it.techs : (p === "t" ? TR.agg.tools.find(t => "t:" + t.k === key).techs : []);
    let head = "";
    if (p === "t") { const t = TOOLS[+k]; head = `<h3>${esc(t.n)} ${t.s ? `<a class="tag m" target=_blank href="https://attack.mitre.org/software/${t.s}/">${t.s} ↗</a>` : ""}</h3><div class="note">${esc(t.ty)} · usado por ${t.g} grupos</div><p>${esc(t.d || "")}</p>`; }
    if (p === "asr") { const a = ASR[+k]; head = `<h3>🛡 ASR – ${esc(a[1])}</h3><div class="note">GUID <code>${a[0]}</code> · mapeamento ASR→ATT&CK curado a partir da descrição oficial da regra</div>${a[2] ? code("Advanced hunting (Defender XDR) – eventos desta regra", `DeviceEvents\n| where Timestamp > ago(30d)\n| where ActionType in ("${a[2]}Blocked", "${a[2]}Audited")\n| summarize Eventos=count(), Hosts=dcount(DeviceId) by ActionType, FileName, InitiatingProcessFileName\n| order by Eventos desc`) : `<div class="note">Esta regra não expõe ActionType específico no advanced hunting.</div>`}${code("Habilitar em modo auditoria (PowerShell)", `Add-MpPreference -AttackSurfaceReductionRules_Ids ${a[0]} -AttackSurfaceReductionRules_Actions AuditMode`)}`; }
    if (p === "mde") head = `<h3>🗄 ${esc(k)}</h3><div class="note">Produto: ${mdeProd(k)} · tabela/ActionType de advanced hunting relevante para os data components das técnicas abaixo.</div>${code("KQL base (ajuste filtros)", mdeSkeleton(k))}`;
    if (p === "d3") { const d = D3[k]; head = `<h3><span class="d3t" style="background:${D3COL[d[1]]}"></span>${esc(d[0])} <span class="tag">${k}</span> <span class="tag">${d[1]}</span></h3><div class="note">Pai: ${esc(d[2] || "—")} · <a target=_blank href="${d3Url(k)}">d3fend.mitre.org ↗</a></div>${d[1] === "Deceive" ? `<div class="info">Engano/decoys: implantar iscas (contas, credenciais, compartilhamentos, PLC/HMI falsos em OT) e <i>breadcrumbs</i> gera alertas de altíssima fidelidade para reconhecimento e movimento lateral (abordagem usada p.ex. por plataformas de deception como CounterCraft).</div>` : ""}`; }
    if (p === "dc") head = `<h3>📡 ${esc(k)}</h3><div class="note">Data component ATT&CK – use como <code>data_source_name</code> no DeTT&CT.</div>${code("DeTT&CT – trecho data-source-administration", dsYaml([k], {}))}<div class="note">Tabelas Defender sugeridas: ${(KB.DC2MDE && KB.DC2MDE[k] || []).map(x => `<span class="tag c">${esc(x)}</span>`).join("") || "—"}</div>`;
    if (p === "ra") { const r = RA[k]; head = `<h3>🧯 ${k} – ${esc(r[0])}</h3><div class="note">Estágio: ${STGPT[r[1]] || r[1]} · <a target=_blank href="${raUrl(k)}">RE&CT ↗</a></div><p>${esc(r[3])}</p>`; }
    h = `<div class="card">${head}<div class="sec"><h4>Técnicas do grupo relacionadas (${list.length})</h4>${list.map(t => { const cs = covStat(t); return `<span class="tag m cl" onclick="TR.sel='k:${t}';hlTrace('k:${t}');traceDetail('k:${t}')">${cs[1]} ${t} ${esc(TK[t].n)}</span>`; }).join("")}</div></div>`;
  }
  $("#trdet").innerHTML = h; bindFtabs($("#trdet"));
}
function mdeSkeleton(tb) {
  const [t, at] = tb.split(" ")[0].split(":");
  if (at) { const op = at.startsWith("*") ? `endswith "${at.slice(1)}"` : at.endsWith("*") ? `startswith "${at.slice(0, -1)}"` : `== "${at}"`; return `${t}\n| where Timestamp > ago(7d)\n| where ActionType ${op}\n| take 100`; }
  return `${t}\n| where Timestamp > ago(7d)\n| take 100`;
}
function revealTrace() { // rola cada coluna para mostrar o primeiro item relacionado (sem mover a página)
  $$("#trcols .tcol").forEach(col => { const el = col.querySelector(".ti.hl, .ti.sel"); if (!el) return; const cr = col.getBoundingClientRect(), r = el.getBoundingClientRect(); if (r.top < cr.top + 20 || r.bottom > cr.bottom) col.scrollTop += r.top - cr.top - 60; });
  requestAnimationFrame(() => { drawTraceLinks(); hlTrace(TR.sel); });
}

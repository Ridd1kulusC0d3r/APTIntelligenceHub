// =====================================================================================
// PRIORIZAÇÃO (Threat-Informed Defense)
// =====================================================================================
const PR = {sec: new Set(), mot: new Set(MOTIV), done: false};
function initPrioUI() {
  const sc = {}; E.forEach(e => e.sec.forEach(s => sc[s] = (sc[s] || 0) + 1));
  $("#pSec").innerHTML = Object.entries(sc).sort((a, b) => b[1] - a[1]).map(([s, n]) => `<span class="chip" data-s="${esc(s)}">${esc(s)} <span class="muted">${n}</span></span>`).join("");
  $$("#pSec .chip").forEach(c => c.onclick = () => { c.classList.toggle("on"); c.classList.contains("on") ? PR.sec.add(c.dataset.s) : PR.sec.delete(c.dataset.s); });
  $("#pMot").innerHTML = MOTIV.map(m => `<span class="chip on" data-m="${m}">${m}</span>`).join("");
  $$("#pMot .chip").forEach(c => c.onclick = () => { c.classList.toggle("on"); c.classList.contains("on") ? PR.mot.add(c.dataset.m) : PR.mot.delete(c.dataset.m); });
  const vc = {}; E.forEach(e => e.v.forEach(v => vc[v] = (vc[v] || 0) + 1));
  $("#pCty").innerHTML = `<option value="">(sem país)</option>` + Object.entries(vc).sort((a, b) => cname(a[0]).localeCompare(cname(b[0]))).map(([i, n]) => `<option value="${i}" ${i === "BR" ? "selected" : ""}>${flag(i)} ${esc(cname(i))} (${n})</option>`).join("");
  $("#pRun").onclick = runPrio;
}
function prioFor(iso) { $("#pCty").value = iso; showTab("prio"); runPrio(); }
function runPrio() {
  PR.done = true;
  const cty = $("#pCty").value, ws = +$("#pWs").value, wc = +$("#pWc").value, via = $("#pVia").checked, mn = +$("#pMin").value;
  const secs = PR.sec, mots = PR.mot;
  const rel = [];
  E.forEach(e => {
    if (e.ns < mn || (!e.nt && !(via && e.tl.some(k => TOOLS[k].t.length)))) return;
    if (e.mo.length && !e.mo.some(m => mots.has(m))) return;
    const ms = e.sec.filter(s => secs.has(s)), mc = cty && e.v.includes(cty);
    let R = (ms.length ? ws : 0) + (mc ? wc : 0);
    if (!secs.size && !cty) R = 1;
    if (R <= 0) return;
    const C = 0.5 + 0.5 * Math.min(1, e.ns / 8) + (e.m ? 0.15 : 0);
    rel.push({e, W: R * C, R, C, why: [...ms.map(s => "setor: " + s), ...(mc ? ["país: " + cname(cty)] : [])]});
  });
  rel.sort((a, b) => b.W - a.W);
  const P = {}, PG = {};
  rel.forEach(r => techSet(r.e, via).forEach((o, t) => { if (!TK[t]) return; P[t] = (P[t] || 0) + r.W; (PG[t] = PG[t] || []).push(r.e.i); }));
  const mx = Math.max(1e-9, ...Object.values(P));
  const ranked = Object.entries(P).map(([t, v]) => ({t, s: Math.round(v / mx * 100), g: PG[t].length})).sort((a, b) => b.s - a.s || b.g - a.g);
  PR.ranked = ranked; PR.rel = rel; PR.label = `Perfil ${[...secs].join("+") || "todos setores"} / ${cty ? cname(cty) : "global"}`;
  const cov = {ok: 0, pa: 0, gap: 0}; ranked.forEach(r => cov[covStat(r.t)[0]]++);
  const PRE = t => TK[t].ta.every(x => x === "reconnaissance" || x === "resource-development");
  const top = ranked.slice(0, 60), gaps = ranked.filter(r => covStat(r.t)[0] === "gap" && !PRE(r.t)).slice(0, 20), pre = ranked.filter(r => PRE(r.t)).slice(0, 12);
  const dcw = {}, d3w = {}, asrw = {}; ranked.forEach(r => { const k = TK[r.t]; k.dc.forEach(d => dcw[d] = (dcw[d] || 0) + r.s); new Set(k.d3.map(x => x[0])).forEach(d => d3w[d] = (d3w[d] || 0) + r.s); k.asr.forEach(a => asrw[a] = (asrw[a] || 0) + r.s); });
  const bars = (obj, lab, n = 12) => { const arr = Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n); const m = arr.length ? arr[0][1] : 1; return arr.map(([k, v]) => `<div class="bar"><span class="l" title="${esc(lab(k))}">${lab(k)}</span><span class="t"><i style="width:${v / m * 100}%"></i></span><span class="n">${Math.round(v)}</span></div>`).join(""); };
  $("#pOut").innerHTML = `
  <div class="row" style="gap:6px;margin-bottom:10px"><b>${esc(PR.label)}</b> · ${rel.length} grupos relevantes · ${ranked.length} técnicas
   <span style="flex:1"></span><button class="btn sm" onclick="prioExport('nav')">⬇ Navigator</button><button class="btn sm" onclick="prioExport('dg')">⬇ DeTT&CT group</button><button class="btn sm" onclick="prioExport('ds')">⬇ DeTT&CT data sources</button><button class="btn sm" onclick="prioExport('dt')">⬇ DeTT&CT techniques</button><button class="btn sm" onclick="prioExport('rp')">⬇ RE&CT playbook</button><button class="btn sm" onclick="prioExport('sig')">⬇ Sigma (top 40)</button><button class="btn sm" onclick="prioExport('csv')">⬇ CSV</button></div>
  <div class="grid">
   <div class="card"><h3>Cobertura das técnicas priorizadas</h3><div class="row" style="gap:12px"><span class="stat st-ok">● ${cov.ok} com regra</span><span class="stat st-pa">◐ ${cov.pa} parcial</span><span class="stat st-gap">○ ${cov.gap} lacuna</span></div>
    <div class="bar" style="margin-top:8px"><span class="l">top-40 cobertas por regra</span><span class="t"><i style="width:${ranked.slice(0, 40).filter(r => covStat(r.t)[0] === "ok").length / Math.max(1, Math.min(40, ranked.length)) * 100}%"></i></span><span class="n">${ranked.slice(0, 40).filter(r => covStat(r.t)[0] === "ok").length}/${Math.min(40, ranked.length)}</span></div>
    <h3 style="margin-top:12px">Backlog de engenharia de detecção (lacunas mais prioritárias)</h3>${gaps.map(r => `<span class="tag r cl" onclick="techModal('${r.t}')">${r.t} ${esc(TK[r.t].n)} · ${r.s}</span>`).join("") || "<span class=note>Sem lacunas no topo 🎉</span>"}
    ${pre.length ? `<h3 style="margin-top:12px">Pré-ataque (fora da telemetria interna)</h3><div class="note">Reconhecimento/Desenvolvimento de recursos: tratar com monitoramento externo (CT logs, typosquatting/brand protection, exposição de credenciais, TI de infraestrutura) – não com regras de SIEM.</div>${pre.map(r => `<span class="tag w cl" onclick="techModal('${r.t}')">${r.t} ${esc(TK[r.t].n)} · ${r.s}</span>`).join("")}` : ""}</div>
   <div class="card"><h3>📡 Onde investir em telemetria (DeTT&CT)</h3>${bars(dcw, k => esc(k))}<p class="note">Σ prioridade das técnicas que exigem cada data component.</p></div>
   <div class="card"><h3>🧱 Contramedidas D3FEND de maior alavancagem</h3>${bars(d3w, k => `<span class="d3t" style="background:${D3COL[D3[k][1]]}"></span>${esc(D3[k][0])}`)}</div>
   <div class="card"><h3>🛡 Regras ASR (Defender) mais relevantes</h3>${bars(asrw, k => esc(ASR[k][1]), 10) || "<span class=note>—</span>"}<p class="note">Habilite em <i>audit</i> primeiro; monitore via DeviceEvents (ActionType Asr*).</p></div>
   <div class="card"><h3>🧑‍💻 Exposição de credenciais (infostealers)</h3><div class="note">Técnicas T1078/T1555/T1539 são frequentemente viabilizadas por logs de infostealers. Consulte o seu domínio no endpoint OSINT gratuito da Hudson Rock (abre nova aba; não verificado a partir do ambiente de geração).</div><div class="row" style="gap:6px;margin-top:6px"><input id="hrDom" placeholder="empresa.com.br"><button class="btn sm" onclick="if($('#hrDom').value)window.open('https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain='+encodeURIComponent($('#hrDom').value.trim()),'_blank','noopener')">consultar</button></div></div>
  </div>
  <div class="grid" style="margin-top:12px;grid-template-columns:1.1fr 1.6fr">
   <div class="card"><h3>Grupos relevantes (${rel.length})</h3><table style="font-size:12px"><tr><th style="position:static">Grupo</th><th style="position:static">W</th><th style="position:static">Por quê</th></tr>${rel.slice(0, 60).map(r => `<tr class="r" onclick="openD(${r.e.i})"><td>${flag(r.e.iso)} ${esc(r.e.n)} ${r.e.m ? `<span class="tag m">${r.e.m}</span>` : ""}</td><td>${r.W.toFixed(2)}</td><td>${r.why.map(w => `<span class="tag c">${esc(w)}</span>`).join("")} <span class="note">C=${r.C.toFixed(2)}</span></td></tr>`).join("")}</table></div>
   <div class="card"><h3>Técnicas priorizadas (top 60)</h3><table style="font-size:12px"><tr><th style="position:static">#</th><th style="position:static">Técnica</th><th style="position:static">Tática</th><th style="position:static">P</th><th style="position:static">Grupos</th><th style="position:static">Cobertura</th><th style="position:static">Defender</th><th style="position:static">D3FEND</th></tr>
    ${top.map((r, i) => { const k = TK[r.t], cs = covStat(r.t); return `<tr class="r" onclick="techModal('${r.t}')"><td>${i + 1}</td><td><b>${r.t}</b> ${esc(k.n)}</td><td class="note">${k.ta.map(x => TACPT[x]).join(", ")}</td><td><b>${r.s}</b></td><td>${r.g}</td><td><span class="stat st-${cs[0]}">${cs[1]} ${esc(cs[2])}</span></td><td class="note">${k.asr.length ? "🛡" + k.asr.length + " " : ""}${k.mde.slice(0, 2).map(x => esc(x.split(":")[0])).join(", ")}</td><td>${new Set(k.d3.map(x => x[0])).size}</td></tr>`; }).join("")}</table></div>
  </div>`;
}
function prioExport(kind) {
  if (!PR.ranked) return; const techs = PR.ranked.map(r => r.t), name = PR.label, sl = slug(name);
  if (kind === "nav") { const sc = {}, cm = {}; PR.ranked.forEach(r => { sc[r.t] = r.s; cm[r.t] = `P=${r.s}; ${r.g} grupos; cobertura: ${covStat(r.t)[2]}`; }); dl(`navigator_${sl}.json`, JSON.stringify(navLayer(name, sc, cm, "Prioridade Threat-Informed Defense (0–100)"), null, 1), "application/json"); }
  if (kind === "dg") dl(`dettect_group_${sl}.yaml`, dettectProfile(name, techs.slice().sort()));
  if (kind === "ds") dl(`dettect_datasources_${sl}.yaml`, dettectDS(techs, name + " – data sources"));
  if (kind === "dt") dl(`dettect_techniques_${sl}.yaml`, dettectTech(techs, name + " – técnicas"));
  if (kind === "rp") dl(`react_playbook_${sl}.yml`, reactPlaybook(techs.slice(0, 60), name));
  if (kind === "sig") dl(`sigma_${sl}.yml`, sigmaBundle(techs.slice(0, 40)));
  if (kind === "csv") { const rows = [["rank", "tecnica", "nome", "taticas", "prioridade", "n_grupos", "cobertura", "regras", "asr", "d3fend", "data_components", "defender_tabelas"]]; PR.ranked.forEach((r, i) => { const k = TK[r.t]; rows.push([i + 1, r.t, k.n, k.ta.join("|"), r.s, r.g, covStat(r.t)[2], techRules(r.t)[0].map(x => RULES[x].t).join("|"), k.asr.map(a => ASR[a][1]).join("|"), [...new Set(k.d3.map(x => D3[x[0]][0]))].join("|"), k.dc.join("|"), k.mde.join("|")]); }); dl(`prioridades_${sl}.csv`, "\ufeff" + rows.map(r => r.map(csvq).join(",")).join("\n"), "text/csv;charset=utf-8"); }
}
// =====================================================================================
// DETECÇÕES (catálogo multi-formato)
// =====================================================================================
let DLIST = [];
function initDetUI() {
  $("#dFmt").insertAdjacentHTML("beforeend", FMT.slice(1).map(([k, l]) => `<option value="${k}">${l}</option>`).join(""));
  const st = KB.CONVSTATS; const tot = Object.keys(RULES).length;
  $("#dStats").innerHTML = `<div class="card" style="grid-column:1/-1"><h3>Matriz de compatibilidade da conversão (${tot} regras)</h3>${FMT.slice(1).map(([k, l]) => `<div class="bar"><span class="l">${l}</span><span class="t"><i style="width:${(st[k] ? st[k].ok + st[k].fb : 0) / tot * 100}%"></i></span><span class="n" style="width:150px">${st[k] ? st[k].ok : 0} ok${st[k] && st[k].fb ? " + " + st[k].fb + " fallback" : ""}</span></div>`).join("")}<p class="note">“fallback” = convertido com pipeline alternativo (QRadar: busca em payload; Splunk: sem mapeamento Sysmon). Não suportado ≈ logsource sem equivalente no backend (ex.: Defender XDR não tem Script Block 4104/Security EID).</p></div>`;
  const LVO = {critical: 4, high: 3, medium: 2, low: 1};
  DLIST = Object.entries(RULES).map(([id, r]) => { const gs = new Set(); r.tg.forEach(t => (IDX.tech[t] || []).forEach(i => gs.add(i))); return {id, r, ng: gs.size, s: (r.t + " " + r.tg.join(" ") + " " + r.ls + " " + (r.g || "")).toLowerCase(), folder: r.src === "Hub" ? "Hub" : (r.u.split("/blob/master/")[1] || "").split("/")[0]}; })
    .sort((a, b) => (b.r.src === "Hub") - (a.r.src === "Hub") || b.ng - a.ng || (LVO[b.r.lv] || 0) - (LVO[a.r.lv] || 0));
  ["#dq", "#dSrc", "#dLv", "#dFmt"].forEach(s => $(s).addEventListener("input", renderDet));
  $("#dPri").innerHTML = Object.entries(DET).map(([m, d]) => { const e = E.find(x => x.m === m); return `<div class="card" style="margin:10px 0;border-left:3px solid var(--ok)"><div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(d.title)}</b><span>${e ? `<button class="btn sm" onclick="openD(${e.i})">dossiê</button> <button class="btn sm" onclick="goTrace(${e.i})">traçar</button>` : ""}</span></div>
    <div class="note" style="margin:4px 0">${esc(d.ttp)}</div><div>${d.tel.map(t => `<span class="tag c">${esc(t)}</span>`).join("")}</div><div class="why" style="margin-top:6px">${esc(d.why)}</div>
    <div>${d.rules.map(r => RULES[r] ? `<span class="tag d cl" onclick="ruleModal('${r}')">Σ ${esc(RULES[r].t)}</span>` : "").join("")}</div>${code("KQL manual (Sentinel/Defender – agregação/contexto)", d.kql)}${code("SPL manual", d.spl)}<div class="gap">Gaps/bypasses: ${esc(d.gaps)}</div></div>`; }).join("");
}
function renderDet() {
  const q = $("#dq").value.toLowerCase().trim(), src = $("#dSrc").value, lv = $("#dLv").value, f = $("#dFmt").value;
  const techF = F.tech;
  const r = DLIST.filter(x => (!q || q.split(/\s+/).every(w => x.s.includes(w))) && (!src || x.folder === src) && (!lv || x.r.lv === lv) && (!f || !ruleQuery(x.r, f).err) && (!techF || x.r.tg.some(t => t === techF || t.startsWith(techF + "."))));
  $("#dCnt").textContent = r.length + " regras" + (techF ? ` (filtro global técnica ${techF})` : "");
  $("#dTb").innerHTML = r.slice(0, 400).map(x => {
    return `<tr class="r" onclick="ruleModal('${x.id}')"><td><b>${esc(x.r.t)}</b><div class="note">${x.folder}</div></td><td><span class="pill lv-${esc(x.r.lv)}">${esc(x.r.lv)}</span></td><td class="note">${esc(x.r.ls)}</td><td>${x.r.tg.map(t => `<span class="tag m">${t}</span>`).join("")}</td><td class="note">${x.ng} grupos</td><td style="white-space:nowrap">${FMT.slice(1).map(([k]) => `<span title="${k}" style="display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:2px;background:${ruleQuery(x.r, k).err ? "#3a2230" : ruleQuery(x.r, k).note ? "#e9a94b" : "#5fbf8f"}"></span>`).join("")}</td></tr>`; }).join("") + (r.length > 400 ? `<tr><td colspan=6 class="note">+${r.length - 400} (refine o filtro)</td></tr>` : "");
}
// =====================================================================================
// MATRIZ ATT&CK × cobertura
// =====================================================================================
function initMxUI() {
  $("#mxSel").innerHTML = `<option value="F">Conjunto filtrado (agregado)</option><option value="P">Perfil da aba Priorização</option>` + E.filter(e => e.nt).sort((a, b) => a.n.localeCompare(b.n)).map(e => `<option value="${e.i}">${esc(e.n)} (${e.m})</option>`).join("");
  $("#mxSel").onchange = renderMx; $("#mxSub").onchange = renderMx;
  $("#mxNav").onclick = () => { const f = mxFreq(); const sc = {}, cm = {}; Object.entries(f).forEach(([t, n]) => { sc[t] = n; cm[t] = covStat(t)[2]; }); dl("navigator_matriz.json", JSON.stringify(navLayer("APT Threat Map – matriz", sc, cm, "Frequência no conjunto selecionado"), null, 1), "application/json"); };
}
function mxFreq() {
  const v = $("#mxSel").value, sub = $("#mxSub").checked, f = {};
  if (v === "F") FILT.forEach(e => e.t.forEach(t => f[t] = (f[t] || 0) + 1));
  else if (v === "P") { if (!PR.ranked) runPrio(); PR.ranked.forEach(r => f[r.t] = r.s); }
  else E[+v].t.forEach(t => f[t] = 1);
  if (!sub) Object.keys(f).forEach(t => { if (t.includes(".")) { const p = t.split(".")[0]; f[p] = Math.max(f[p] || 0, f[t]); delete f[t]; } });
  return f;
}
function renderMx() {
  const f = mxFreq(), mx = Math.max(1, ...Object.values(f)), single = !["F", "P"].includes($("#mxSel").value);
  $("#mxBox").innerHTML = TAC.map(ta => { const ts = Object.keys(f).filter(t => TK[t] && TK[t].ta.includes(ta)).sort((a, b) => f[b] - f[a] || a.localeCompare(b)).slice(0, single ? 999 : 40);
    return `<div><h5>${TACPT[ta]} (${ts.length})</h5>${ts.map(t => { const cs = covStat(t); return `<div class="mc cov-${cs[0]}" style="background:color-mix(in srgb,var(--acc) ${Math.round(8 + 47 * f[t] / mx)}%,var(--panel))" title="${t} ${esc(TK[t].n)} — ${f[t]} · ${esc(cs[2])}" onclick="techModal('${t}'${single ? "," + $("#mxSel").value : ""})">${cs[1]} ${t} ${esc(TK[t].n)}</div>`; }).join("")}</div>`; }).join("");
}
// =====================================================================================
// GRUPOS (tabela) + DOSSIÊ
// =====================================================================================
let GS = {k: "score", d: -1};
function initGrpUI() {
  $$("#t-grp th[data-s]").forEach(th => th.onclick = () => { const k = th.dataset.s; GS.d = GS.k === k ? -GS.d : (k === "n" || k === "c" ? 1 : -1); GS.k = k; renderGrp(); });
  $("#gCsv").onclick = () => { const rows = [["nome", "origem_iso", "pais_bloco", "mitre", "motivacao", "setores", "paises_alvo", "n_fontes", "fontes", "n_tecnicas", "tecnicas", "ferramentas", "aliases", "similares"]];
    FILT.forEach(e => rows.push([e.n, e.iso, e.c, e.m, e.mo.join("|"), e.sec.join("|"), e.v.join("|"), e.ns, e.s.map(i => SRC[i]).join("|"), e.nt, e.t.join("|"), e.tl.map(k => TOOLS[k].n).join("|"), e.a.join("|"), e.sim.map(s => E[s[0]].n + ":" + s[1]).join("|")]));
    dl("grupos_filtrados.csv", "\ufeff" + rows.map(r => r.map(csvq).join(",")).join("\n"), "text/csv;charset=utf-8"); };
}
function renderGrp() {
  const r = FILT.slice().sort((a, b) => { const x = a[GS.k] ?? "", y = b[GS.k] ?? ""; return (x > y ? 1 : x < y ? -1 : 0) * GS.d || b.score - a.score; });
  $("#gTb").innerHTML = r.slice(0, 800).map(e => `<tr class="r" onclick="openD(${e.i})"><td><b>${esc(e.n)}</b>${e.ty ? ` <span class="tag">${esc(e.ty)}</span>` : ""}<div class="note">${esc(e.a.slice(0, 5).join(", "))}</div></td><td>${flag(e.iso)} ${esc(cname(e.iso) || e.c)}</td><td>${e.m ? `<span class="tag m">${e.m}</span>` : ""}</td><td>${e.mo.map(m => `<span class="tag" style="border-color:${MCOL[m]}">${m}</span>`).join("")}</td><td>${e.sec.slice(0, 3).map(s => `<span class="tag c">${esc(s)}</span>`).join("")}${e.sec.length > 3 ? " +" + (e.sec.length - 3) : ""}</td><td>${e.nv}</td><td>${e.ns}</td><td>${e.nt || ""}</td><td>${e.ntl || ""}</td><td class="note">${e.sim.slice(0, 3).map(s => esc(E[s[0]].n)).join(", ")}</td></tr>`).join("") + (r.length > 800 ? `<tr><td colspan=10 class="note">+${r.length - 800} (refine os filtros)</td></tr>` : "");
}
function openD(i) {
  CB = []; const e = E[i]; history.replaceState(null, "", "#g=" + i);
  $("#dh").innerHTML = `<h2 style="margin:0">${esc(e.n)}</h2><div class="note">${flag(e.iso)} ${esc(cname(e.iso) || e.c)}${e.m ? ` · <a target="_blank" rel="noopener noreferrer" href="https://attack.mitre.org/groups/${e.m}/">${e.m} ↗</a>` : ""}${e.mal ? ` · <a target="_blank" rel="noopener noreferrer" href="https://malpedia.caad.fkie.fraunhofer.de/actor/${esc(e.mal)}">Malpedia ↗</a>` : ""}${e.etda ? ` · <a target="_blank" rel="noopener noreferrer" href="https://apt.etda.or.th/cgi-bin/showcard.cgi?u=${esc(e.etda)}">ThaiCERT ↗</a>` : ""}${e.bd ? ` · <a target="_blank" rel="noopener noreferrer" href="${esc(safeUrl(e.bd))}">BRANDEFENSE ↗</a>` : ""}${e.am ? ` · <a target="_blank" rel="noopener noreferrer" href="https://andreacristaldi.github.io/APTmap/">APTmap ↗</a>` : ""}</div>
   <div class="row" style="gap:6px;margin-top:8px"><button class="btn sm pri" onclick="goTrace(${i})">🔗 traçar cadeia</button><button class="btn sm" onclick="closeD();showTab('map');selectGroupOnMap(${i})">🗺️ no mapa</button><button class="btn sm" onclick="goGraph('g:${i}')">🕸️ ego-rede</button></div>`;
  const conf = Math.min(100, Math.round(e.ns / 10 * 60 + (e.m ? 25 : 0) + (e.ac ? +e.ac * 0.15 : 0)));
  let h = `<div class="sec"><h4>Confiança do registro consolidado</h4><div class="bar"><span class="l">corroboração ${e.ns} fontes${e.ac ? " · atrib. APTmap " + e.ac + "%" : ""}</span><span class="t"><i style="width:${conf}%"></i></span><span class="n">${conf}</span></div>
   <div>${SRC.map((s, k) => `<span class="tag ${e.s.includes(k) ? "d" : ""}">${e.s.includes(k) ? "✔" : "✘"} ${esc(s)}</span>`).join("")}</div>
   ${e.aptm ? `<div class="warn">APTMalware: ${e.aptm} amostras catalogadas (apenas metadados; zips com senha 'infected' – manipular só em laboratório isolado).</div>` : ""}</div>`;
  if (e.d) h += `<div class="sec"><h4>Resumo</h4><div>${esc(e.d)}</div></div>`;
  if (e.gcp) h += `<div class="sec"><h4>Google Cloud / Mandiant</h4><div class="note"><b>Atribuição suspeita:</b> ${esc(e.gcp.attr)}<br><b>Visão geral:</b> ${esc(e.gcp.overview)}<br><b>Setores:</b> ${esc(e.gcp.sectors)}<br><b>Malware:</b> ${esc(e.gcp.malware)}<br><b>Vetores:</b> ${esc(e.gcp.vectors)}</div></div>`;
  h += `<div class="sec row" style="gap:28px"><div><h4>Motivação</h4>${e.mo.map(m => `<span class="tag" style="border-color:${MCOL[m]}">${m}</span>`).join("") || "—"}<div class="note">${esc(e.mr.join("; "))}</div></div><div><h4>Patrocínio suspeito</h4>${esc(e.sp) || "—"}</div><div><h4>Ativo desde</h4>${esc(e.fs) || "—"}</div><div><h4>Tipo</h4>${esc(e.ty) || "—"}</div></div>`;
  if (e.sim.length) h += `<div class="sec"><h4>Grupos similares (TTP + ferramentas)</h4>${e.sim.map(s => `<span class="tag cl" style="border-color:#f472b6" onclick="openD(${s[0]})">${esc(E[s[0]].n)} · ${s[1]}</span>`).join("")}<div class="note">Cosseno TF-IDF – sinaliza sobreposição de tradecraft, possível duplicidade de nomenclatura ou compartilhamento de ferramentas; não é atribuição.</div></div>`;
  if (e.rel.length) h += `<div class="sec"><h4>Relações declaradas (MISP/APTmap)</h4>${e.rel.map(r => `<span class="tag cl" style="border-color:#22d3ee" onclick="openD(${r[0]})">${esc(r[1])} → ${esc(E[r[0]].n)}${r[2] ? " (" + esc(r[2]) + ")" : ""}</span>`).join("")}</div>`;
  h += `<div class="sec"><h4>Aliases (${e.a.length})</h4>${e.a.map(a => `<span class="tag">${esc(a)}</span>`).join("")}</div>`;
  if (Object.keys(e.vn).length) h += `<div class="sec"><h4>Nomes por fornecedor</h4><table style="font-size:12px">${Object.entries(e.vn).map(([k, v]) => `<tr><td class="muted" style="width:200px">${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")}</table></div>`;
  if (e.sec.length || e.sr.length) h += `<div class="sec"><h4>Setores-alvo</h4>${e.sec.map(s => `<span class="tag c">${esc(s)}</span>`).join("")}<div class="note">Original: ${esc(e.sr.join(", "))}</div></div>`;
  if (e.v.length || e.vo.length) h += `<div class="sec"><h4>Países/entidades-alvo (${e.v.length + e.vo.length})</h4>${e.v.map(v => `<span class="tag">${flag(v)} ${esc(cname(v))}</span>`).join("")}${e.vo.length ? `<div class="note">${esc(e.vo.join(", "))}</div>` : ""}</div>`;
  if (e.camp.length) h += `<div class="sec"><h4>Campanhas ATT&CK</h4>${e.camp.map(c => `<div><a target="_blank" rel="noopener noreferrer" href="https://attack.mitre.org/campaigns/${c.id}/" class="tag m">${c.id}</a> ${esc(c.n)} <span class="note">${c.fs}–${c.ls}</span></div>`).join("")}</div>`;
  if (e.tl.length) h += `<div class="sec"><h4>Ferramentas / malware (${e.tl.length})</h4>${e.tl.map(k => `<span class="tag w" title="${esc(TOOLS[k].d || "")}">${esc(TOOLS[k].n)}${TOOLS[k].s ? " · " + TOOLS[k].s : ""}</span>`).join("")}</div>`;
  if (e.t.length) { const by = {}; e.t.forEach(t => (TK[t] ? TK[t].ta : ["?"]).forEach(ta => (by[ta] = by[ta] || []).push(t)));
    h += `<div class="sec"><h4>Técnicas ATT&CK (${e.t.length}) – clique para a cadeia defensiva</h4>${TAC.filter(t => by[t]).map(ta => `<div style="margin:3px 0"><span class="muted" style="display:inline-block;width:170px">${TACPT[ta]}</span>${by[ta].sort().map(t => { const cs = covStat(t); return `<span class="tag m cl" onclick="techModal('${t}',${i})" title="${esc(TK[t] ? TK[t].n : "")} – ${esc(cs[2])}">${cs[1]} ${t}</span>`; }).join("")}</div>`).join("")}</div>`; }
  const d = DET[e.m]; if (d) h += `<div class="sec"><h4>🛡 Detecções dedicadas (hub)</h4><div class="why">${esc(d.why)}</div>${d.rules.map(r => ruleBlock(r)).join("")}${code("KQL manual", d.kql)}${code("SPL manual", d.spl)}<div class="gap">Gaps/bypasses: ${esc(d.gaps)}</div></div>`;
  if (e.shq.length) h += `<div class="sec"><h4>Σ SigmaHQ emerging-threats deste ator (${e.shq.length})</h4>${e.shq.map(r => `<div><a target="_blank" rel="noopener noreferrer" href="${esc(safeUrl(r.url))}">${esc(r.title)}</a> <span class="pill lv-${esc(r.level)}">${esc(r.level)}</span></div>`).join("")}</div>`;
  if (e.ops.length) h += `<div class="sec"><h4>Operações</h4>${e.ops.map(o => `<span class="tag">${esc(o)}</span>`).join("")}</div>`;
  if (e.tg || e.mod || e.cm) h += `<div class="sec"><h4>Planilha – alvos / modus / comentários</h4><div class="note">${esc(e.tg)}<br>${esc(e.mod)}<br>${esc(e.cm)}</div></div>`;
  if (e.lk.length) h += `<div class="sec"><h4>Referências (${e.lk.length})</h4>${e.lk.map(l => `<div><a target="_blank" rel="noopener noreferrer" href="${esc(safeUrl(l))}">${esc(l.slice(0, 110))}</a></div>`).join("")}</div>`;
  $("#db").innerHTML = h; bindFtabs($("#db")); $("#drawer").classList.add("on"); $("#drawer").scrollTop = 0;
}
function closeD() { $("#drawer").classList.remove("on"); if (location.hash.startsWith("#g=")) history.replaceState(null, "", location.pathname); }
// =====================================================================================
// FONTES & METODOLOGIA
// =====================================================================================
function renderSources() {
  const M = META; const sc = {}; E.forEach(e => e.s.forEach(k => sc[k] = (sc[k] || 0) + 1));
  $("#srcBox").innerHTML = `<div class="card"><h3>Fontes integradas e referenciadas</h3><table style="font-size:12.5px"><tr><th style="position:static">Fonte</th><th style="position:static">Tipo</th><th style="position:static">Como foi usada</th><th style="position:static">Entidades</th><th style="position:static">Observações</th></tr>
   ${M.sources.map(s => `<tr><td><a target="_blank" rel="noopener noreferrer" href="${esc(safeUrl(s.u))}">${esc(s.n)}</a></td><td class="note">${esc(s.t)}</td><td>${esc(s.used)}</td><td>${s.key !== undefined && SRC.indexOf(s.key) >= 0 ? sc[SRC.indexOf(s.key)] || 0 : "—"}</td><td class="note">${esc(s.note)}</td></tr>`).join("")}</table></div>
  <div class="card" style="margin-top:12px"><h3>Metodologia, lógica de TI e limitações</h3>${M.method}</div>
  <div class="card" style="margin-top:12px"><h3>Ferramentas de IR / análise (planilha “Malware, IR – Tools & Resources”) – ${M.ir.length}</h3><div class="warn">Itens “Malware Samples” contêm binários vivos — somente em laboratório isolado.</div><input type="search" id="irq" placeholder="filtrar…" oninput="renderIR()"><div id="irBox" style="max-height:420px;overflow:auto;margin-top:6px"></div></div>
  <div class="card" style="margin-top:12px"><h3>Materiais descobertos na raspagem (${M.disc.length})</h3><table style="font-size:12px">${M.disc.map(d => `<tr><td><a target="_blank" rel="noopener noreferrer" href="${esc(safeUrl(d.u))}">${esc(d.n)}</a></td><td class="note">${esc(d.c)}</td><td class="note">${esc(d.f)}</td><td>${esc(d.v)}</td><td>${esc(d.i)}</td><td class="note">${esc(d.s)}</td></tr>`).join("")}</table></div>
  <div class="card" style="margin-top:12px"><h3>Famílias de malware (planilha) – ${KB.malware.length}</h3><div style="columns:3 260px;font-size:12px">${KB.malware.map(m => `<div><b>${esc(m.names[0])}</b> <span class="note">${esc(m.names.slice(1).join(", "))}</span></div>`).join("")}</div></div>`;
  renderIR();
}
function renderIR() { const q = ($("#irq") ? $("#irq").value : "").toLowerCase(); $("#irBox").innerHTML = `<table style="font-size:12px">${META.ir.filter(r => !q || (r.cat + r.name + r.info).toLowerCase().includes(q)).slice(0, 500).map(r => `<tr><td class="note">${esc(r.cat)}</td><td><b>${esc(r.name)}</b></td><td class="note">${esc((r.info || "").slice(0, 200))}</td><td>${r.link ? `<a target="_blank" rel="noopener noreferrer" href="${esc(safeUrl(r.link))}">link</a>` : ""}</td></tr>`).join("")}</table>`; }

// =====================================================================================
// DETALHE DE TÉCNICA (procedimento, detecção multi-formato, Defender, D3FEND, mitigações, DeTT&CT, RE&CT)
// =====================================================================================
function ruleQuery(r, f) {
  if (f === "sigma") return {q: r.y};
  const v = r.f[f]; if (v === undefined || v === null) return {err: "não convertido"};
  if (typeof v === "string") return {q: v};
  if (v.err) return {err: v.err};
  return {q: v.q, note: v.note};
}
function stellarDsl(lucene) { return JSON.stringify({query: {bool: {must: [{query_string: {query: lucene, analyze_wildcard: true}}]}}}, null, 2); }
const FNOTE = {
  splunk: "pySigma splunk + pipelines sysmon/splunk_windows. Ajuste index/sourcetype (ex.: index=wineventlog).",
  elastic: "pySigma Lucene + pipeline ecs_windows (Elastic Defend/Winlogbeat ECS). Use em Discover/Detection rule (query).",
  eql: "pySigma EQL + ecs_windows. Para regras EQL do Elastic Security.",
  esql: "pySigma ES|QL + ecs_windows. Substitua 'from *' pelo índice/data stream adequado.",
  opensearch: "pySigma OpenSearch Lucene + ecs_windows (Security Analytics / Dashboards).",
  qradar: "pySigma QRadar AQL + QRadarAQL_fields_pipeline (propriedades DSM). Valide nomes de campos personalizados.",
  stellar: "Sem backend oficial: Lucene com campos nativos Sysmon/Windows para Content Search/Threat Hunting + DSL para Query Builder. Mapeie as chaves para o Interflow do tenant.",
  defender: "pySigma Kusto + pipeline microsoft_xdr (tabelas Device*). Advanced hunting / custom detection.",
  sigma: "Regra Sigma original (YAML)."
};
function ruleBlock(rid, open = false) {
  const r = RULES[rid]; if (!r) return "";
  const id = "rb" + Math.random().toString(36).slice(2, 9);
  const okf = FMT.map(([f]) => [f, !ruleQuery(r, f).err]);
  const src = r.src === "Hub" ? `<span class="tag d">Hub ${r.g ? "· " + r.g : ""}</span>` : `<a class="tag" target=_blank href="${esc(r.u)}">SigmaHQ ↗</a>`;
  return `<div class="card" style="margin:8px 0;padding:10px" data-rule="${esc(rid)}" id="${id}">
   <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap"><b>${esc(r.t)}</b><span><span class="pill lv-${esc(r.lv)}">${esc(r.lv)}</span> <span class="tag">${esc(r.st)}</span> <span class="tag c">${esc(r.ls)}</span> ${src}</span></div>
   ${r.d ? `<div class="note" style="margin:3px 0">${esc(r.d)}</div>` : ""}${r.fp && r.fp.length ? `<div class="note">Falsos positivos: ${esc(r.fp.join("; "))}</div>` : ""}
   <div class="ftabs">${okf.map(([f, ok], i) => `<button data-f="${f}" class="${i === 0 ? "on" : ""} ${ok ? "" : "x"}" title="${ok ? "" : "não suportado pelo backend/pipeline"}">${FMT.find(x => x[0] === f)[1]}</button>`).join("")}</div>
   <div class="fbody">${fmtBody(rid, "sigma")}</div></div>`;
}
function fmtBody(rid, f) {
  const r = RULES[rid], o = ruleQuery(r, f); const lbl = FMT.find(x => x[0] === f)[1];
  if (o.err) return `<div class="gap">${lbl}: não suportado – <code>${esc(o.err)}</code>${f === "defender" ? "<br>Logsource fora das tabelas Device*/Identity* (ex.: Script Block 4104, Security EID, nuvem, proxy). Use o SIEM correspondente ou Sentinel." : ""}</div>`;
  let h = code(lbl + (o.note ? " ⚠ " + o.note : ""), o.q);
  if (f === "stellar") h += code("Stellar Cyber – Query Builder (JSON DSL)", stellarDsl(o.q));
  return h + `<div class="note">${esc(FNOTE[f] || "")}</div>`;
}
function bindFtabs(root) {
  root.querySelectorAll("[data-rule]").forEach(card => {
    const rid = card.dataset.rule;
    card.querySelectorAll(".ftabs button").forEach(b => b.onclick = () => { card.querySelectorAll(".ftabs button").forEach(x => x.classList.remove("on")); b.classList.add("on"); card.querySelector(".fbody").innerHTML = fmtBody(rid, b.dataset.f); });
  });
  root.querySelectorAll(".stabs").forEach(st => {
    const host = st.parentElement;
    st.querySelectorAll("button").forEach(b => b.onclick = () => { st.querySelectorAll("button").forEach(x => x.classList.remove("on")); b.classList.add("on"); host.querySelectorAll(":scope > .spane").forEach(p => p.style.display = p.dataset.p === b.dataset.p ? "block" : "none"); });
  });
}
function techRules(t) { const k = TK[t]; let r = k ? k.r.slice() : []; let inh = false; if (!r.length && t.includes(".") && TK[t.split(".")[0]]) { r = TK[t.split(".")[0]].r.slice(); inh = r.length > 0; } return [r, inh]; }
function techDetail(t, gi) {
  const k = TK[t]; if (!k) return `<div class="card">Técnica ${esc(t)} sem dados.</div>`;
  const e = gi !== undefined && gi !== null ? E[gi] : null; const cs = covStat(t);
  const [rules, inh] = techRules(t);
  const users = (IDX.tech[t] || []).map(i => E[i]).sort(byScore);
  const viaTools = e ? e.tl.filter(x => TOOLS[x].t.includes(t)) : [];
  const d3m = new Map(); k.d3.forEach(r => { const o = d3m.get(r[0]) || [r[0], new Set(), new Set()]; o[1].add(r[1]); o[2].add(r[2]); d3m.set(r[0], o); });
  const d3by = {}; [...d3m.values()].forEach(r => (d3by[D3[r[0]][1]] = d3by[D3[r[0]][1]] || []).push([r[0], [...r[1]].join(" · "), [...r[2]].join(" · ")]));
  const raBy = {}; k.ra.forEach(r => (raBy[RA[r][1]] = raBy[RA[r][1]] || []).push(r));
  const P = (id, lbl) => `<button data-p="${id}" class="${id === "pr" ? "on" : ""}">${lbl}</button>`;
  let h = `<div class="card"><div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap"><h3 style="margin:0">${t} · ${esc(k.n)} <a target=_blank href="${attackUrl(t)}" class="tag m">ATT&CK ↗</a></h3>
   <span><span class="stat st-${cs[0]}">${cs[1]} ${esc(cs[2])}</span> ${k.ta.map(x => `<span class="tag">${TACPT[x] || x}</span>`).join("")}</span></div>
   <div class="note">Plataformas: ${esc(k.pl.join(", ") || "—")} · usada por ${k.ng} grupos · facetas de resposta: ${k.fa.map(x => `<span class="tag">${x}</span>`).join("") || "—"}</div>
   <div class="stabs">${P("pr", "📝 Procedimento")}${P("dt", `🛡️ Detecção (${rules.length})`)}${P("md", "🪟 Microsoft Defender")}${P("d3", `🧱 D3FEND (${new Set(k.d3.map(r => r[0])).size})`)}${P("mi", `🩹 Mitigações (${k.mit.length})`)}${P("dd", "📡 DeTT&CT")}${P("re", `🧯 RE&CT (${k.ra.length})`)}</div>`;
  // procedimento
  h += `<div class="spane" data-p="pr">${e ? `<div class="sec"><h4>${esc(e.n)} – procedimento</h4>${e.p[t] ? `<div class="why">${esc(e.p[t])}</div>` : `<div class="note">Sem texto de procedimento específico (${e.tset.has(t) ? "uso direto documentado" : "técnica herdada via ferramenta"}).</div>`}</div>` : ""}
   ${viaTools.length ? `<div class="sec"><h4>Via ferramentas do grupo</h4>${viaTools.map(x => `<div><b>${esc(TOOLS[x].n)}</b>${TOOLS[x].s ? ` <span class="tag m">${TOOLS[x].s}</span>` : ""}: <span class="note">${esc((TOOLS[x].p || {})[t] || "")}</span></div>`).join("")}</div>` : ""}
   <div class="sec"><h4>Grupos que usam (${users.length})</h4>${users.slice(0, 60).map(u => `<span class="tag cl" onclick="openD(${u.i})">${flag(u.iso)} ${esc(u.n)}</span>`).join("")}</div>
   <div class="sec"><h4>Ferramentas que implementam (${(IDX.toolTech[t] || []).length})</h4>${(IDX.toolTech[t] || []).slice(0, 60).map(x => `<span class="tag w">${esc(TOOLS[x].n)}</span>`).join("")}</div></div>`;
  // detecção
  h += `<div class="spane" data-p="dt" style="display:none">${inh ? `<div class="info">Sem regra específica para a sub-técnica; exibindo regras da técnica-pai ${t.split(".")[0]}.</div>` : ""}${rules.length ? rules.map(r => ruleBlock(r)).join("") : `<div class="gap">Lacuna: nenhuma regra Sigma (stable/test, ≥ medium) mapeada. Sugestão: usar os data components da aba DeTT&CT e as contramedidas D3FEND-Detect para criar analytics próprias; priorize se a técnica tiver alta pontuação na aba Priorização.</div>`}</div>`;
  // defender
  const asr = k.asr.map(a => ASR[a]);
  h += `<div class="spane" data-p="md" style="display:none"><div class="sec"><h4>Tabelas de advanced hunting (derivadas dos data components)</h4>${k.mde.map(tb => `<span class="tag c">${esc(tb)} · ${mdeProd(tb)}</span>`).join("") || "<span class=note>Sem telemetria Defender direta (técnica pré-ataque/externa).</span>"}</div>
   <div class="sec"><h4>Regras ASR relevantes (${asr.length})</h4>${asr.map(a => `<div class="card" style="padding:8px;margin:6px 0"><b>${esc(a[1])}</b><div class="note">GUID <code>${a[0]}</code>${a[2] ? ` · ActionType <code>${a[2]}Blocked/Audited</code>` : ""}</div></div>`).join("") || "<span class=note>Nenhuma regra ASR diretamente aplicável.</span>"}
   ${asr.filter(a => a[2]).length ? code("KQL – eventos ASR desta técnica", `DeviceEvents\n| where Timestamp > ago(30d)\n| where ActionType in (${asr.filter(a => a[2]).flatMap(a => [`"${a[2]}Blocked"`, `"${a[2]}Audited"`]).join(", ")})\n| summarize count() by ActionType, DeviceName, InitiatingProcessFileName, FileName`) : ""}</div>
   <div class="sec"><h4>Regras convertidas para Defender XDR</h4>${rules.filter(r => !ruleQuery(RULES[r], "defender").err).map(r => code(esc(RULES[r].t), ruleQuery(RULES[r], "defender").q)).join("") || "<span class=note>Nenhuma regra desta técnica é convertível para tabelas Device* (ver aba Detecção para outros SIEMs).</span>"}</div></div>`;
  // d3fend
  h += `<div class="spane" data-p="d3" style="display:none">${k.d3i ? `<div class="info">Mapeamento herdado da técnica-pai (${t.split(".")[0]}).</div>` : ""}${k.d3.length ? D3ORD.filter(x => d3by[x]).map(x => `<div class="sec"><h4><span class="d3t" style="background:${D3COL[x]}"></span>${x} (${d3by[x].length})</h4><table style="font-size:12px"><tr><th style="position:static">Contramedida</th><th style="position:static">Artefato ofensivo (ATT&CK)</th><th style="position:static">Artefato defensivo (D3FEND)</th></tr>${d3by[x].map(r => `<tr><td><a target=_blank href="${d3Url(r[0])}">${esc(D3[r[0]][0])}</a> <span class="tag">${r[0]}</span></td><td>${esc(t)} <i>${esc(r[1])}</i></td><td><i>${esc(r[2])}</i></td></tr>`).join("")}</table>${x === "Deceive" ? `<div class="info">Deception: iscas/honeytokens e ativos-isca (incl. OT: PLC/HMI falsos) detectam recon e movimento lateral com baixíssimo falso-positivo (ex.: abordagem CounterCraft).</div>` : ""}</div>`).join("") : `<div class="note">D3FEND não mapeia contramedidas para esta técnica (comum em técnicas pré-ataque ou novas). Use mitigações ATT&CK.</div>`}</div>`;
  // mitigações
  h += `<div class="spane" data-p="mi" style="display:none">${k.mit.map(m => `<div><a target=_blank href="https://attack.mitre.org/mitigations/${m}/" class="tag m">${m}</a> ${esc(MIT[m] || "")}</div>`).join("") || "<span class=note>Sem mitigações ATT&CK.</span>"}</div>`;
  // dettect
  h += `<div class="spane" data-p="dd" style="display:none"><div class="sec"><h4>Data components necessários (visibilidade)</h4>${k.dc.map(d => `<span class="tag c">${esc(d)}</span>`).join("") || "—"}</div>
   <div class="sec"><h4>Log sources (analytics ATT&CK)</h4>${k.ls.map(d => `<span class="tag">${esc(d)}</span>`).join("") || "—"}</div>
   ${code("DeTT&CT – technique-administration (trecho)", techYaml([t]))}${code("DeTT&CT – data-source-administration (trecho)", dsYaml(k.dc, {[t]: 1}))}
   <div class="note">Pontue <i>visibility</i> (0–4) e <i>detection</i> (-1–5) conforme a qualidade real dos dados/analytics; depois gere camadas com <code>python dettect.py v -ft techniques.yaml -fd data-sources.yaml -l</code> e <code>python dettect.py d -ft techniques.yaml -l</code>.</div></div>`;
  // react
  h += `<div class="spane" data-p="re" style="display:none"><div class="note">Seleção heurística por facetas da técnica (rede, e-mail, arquivo, processo, registro/serviço, identidade, vulnerabilidade, destrutivo), derivadas de data components ATT&CK e artefatos D3FEND.</div>${["identification", "containment", "eradication", "recovery"].filter(s => raBy[s]).map(s => `<div class="sec"><h4>${STGPT[s]}</h4>${raBy[s].map(r => `<div><a target=_blank href="${raUrl(r)}" class="tag">${r}</a> ${esc(RA[r][0])} <span class="note">– ${esc(RA[r][3])}</span></div>`).join("")}</div>`).join("")}</div>`;
  return h + `</div>`;
}
function techModal(t, gi) { CB = []; $("#mh").innerHTML = `<h3 style="margin:0">🧩 ${esc(t)} ${esc(TK[t] ? TK[t].n : "")}</h3><div class="note">Cadeia defensiva completa${gi !== undefined ? " · contexto: " + esc(E[gi].n) : ""}</div>`; $("#mb").innerHTML = techDetail(t, gi); bindFtabs($("#mb")); $("#modal").classList.add("on"); $("#modal").scrollTop = 0; }
function ruleModal(rid) { CB = []; const r = RULES[rid]; $("#mh").innerHTML = `<h3 style="margin:0">Σ ${esc(r.t)}</h3><div class="note">${r.tg.map(t => `<span class="tag m cl" onclick="techModal('${t}')">${t}</span>`).join("")}</div>`; $("#mb").innerHTML = ruleBlock(rid); bindFtabs($("#mb")); $("#modal").classList.add("on"); }
function closeM() { $("#modal").classList.remove("on"); }
document.addEventListener("keydown", k => { if (k.key === "Escape") { closeM(); closeD(); } });

// =====================================================================================
// EXPORTAÇÕES (Navigator, DeTT&CT, RE&CT, Sigma, consultas, CSV)
// =====================================================================================
function navLayer(name, scores, comments, desc) {
  const mx = Math.max(1, ...Object.values(scores));
  return {name, versions: {layer: "4.5", navigator: "5.1.0"}, domain: "enterprise-attack", description: desc,
    techniques: Object.entries(scores).map(([t, s]) => ({techniqueID: t, score: s, comment: (comments[t] || "").slice(0, 900), enabled: true, showSubtechniques: false})),
    gradient: {colors: ["#ffe9a8", "#ff8a3d", "#d7263d"], minValue: 0, maxValue: mx}, legendItems: [], metadata: [{name: "gerado_por", value: "APT Threat Map"}, {name: "data", value: today()}],
    showTacticRowBackground: true, tacticRowBackground: "#205b8f", selectTechniquesAcrossTactics: true, selectSubtechniquesWithParent: false, hideDisabled: false, layout: {layout: "side", showName: true, showID: true}};
}
const yq = s => "'" + String(s).replace(/'/g, "''") + "'";
function dettectGroup(groups, title, via) {
  let y = `version: 1.0\nfile_type: group-administration\ndomain: enterprise-attack\nplatform:\n  - all\ngroups:\n`;
  groups.forEach(e => {
    const ts = [...techSet(e, via).keys()].sort(); const sw = e.tl.map(k => TOOLS[k].s).filter(Boolean);
    y += `  - group_name: ${yq(e.n)}\n    campaign: ${yq("APT Threat Map " + today() + (via ? " (técnicas diretas + via software)" : " (técnicas diretas)"))}\n    technique_id:\n${ts.map(t => "      - " + t).join("\n") || "      []"}\n    software_id:\n${[...new Set(sw)].sort().map(s => "      - " + s).join("\n") || "      []"}\n    enabled: true\n`;
  });
  return y.replace(/:\n      \[\]/g, ": []");
}
function dettectProfile(name, techs) { return `version: 1.0\nfile_type: group-administration\ndomain: enterprise-attack\nplatform:\n  - all\ngroups:\n  - group_name: ${yq(name)}\n    campaign: ${yq("Perfil TID " + today())}\n    technique_id:\n${techs.map(t => "      - " + t).join("\n")}\n    software_id: []\n    enabled: true\n`; }
function dsYaml(dcs, techW) {
  return dcs.map(dc => {
    const ts = Object.keys(techW).filter(t => TK[t] && TK[t].dc.includes(dc));
    const prods = (KB.DC2MDE[dc] || []).slice(0, 3).map(x => "Microsoft Defender XDR – " + x);
    return `  - data_source_name: ${dc}\n    data_source:\n      - applicable_to:\n          - all\n        date_registered:\n        date_connected:\n        products:\n${(prods.length ? prods : ["<preencher: produto/log>"]).map(p => "          - " + yq(p)).join("\n")}\n        available_for_data_analytics: false\n        comment: ${yq((ts.length ? "Necessário p/ " + ts.length + " técnica(s): " + ts.slice(0, 25).join(", ") : "") + " | template – ajuste produtos e qualidade")}\n        data_quality:\n          device_completeness: 0\n          data_field_completeness: 0\n          timeliness: 0\n          consistency: 0\n          retention: 0`;
  }).join("\n");
}
function dettectDS(techs, name) {
  const c = {}; techs.forEach(t => (TK[t] ? TK[t].dc : []).forEach(d => c[d] = (c[d] || 0) + 1));
  const dcs = Object.entries(c).sort((a, b) => b[1] - a[1]).map(x => x[0]); const tw = {}; techs.forEach(t => tw[t] = 1);
  return `version: 1.1\nfile_type: data-source-administration\nname: ${yq(name)}\ndomain: enterprise-attack\nsystems:\n  - applicable_to: all\n    platform:\n      - all\ndata_sources:\n${dsYaml(dcs, tw)}\n`;
}
function techYaml(techs) {
  return techs.filter(t => TK[t]).map(t => { const [r] = techRules(t); const cm = r.length ? `${r.length} regra(s) no catálogo: ` + r.slice(0, 6).map(x => RULES[x].t).join(" | ") : "sem regra no catálogo (lacuna)";
    return `- technique_id: ${t}\n  technique_name: ${yq(TK[t].n)}\n  detection:\n  - applicable_to:\n    - all\n    location: []\n    comment: ${yq(cm)}\n    score_logbook:\n    - date:\n      score: -1\n      comment: ${yq("template APT Threat Map – avaliar")}\n  visibility:\n  - applicable_to:\n    - all\n    comment: ${yq("data components: " + TK[t].dc.join(", "))}\n    score_logbook:\n    - date:\n      score: 0\n      comment: ${yq("template – pontuar 0..4")}\n      auto_generated: true`; }).join("\n");
}
function dettectTech(techs, name) { return `version: 1.2\nfile_type: technique-administration\nname: ${yq(name)}\ndomain: enterprise-attack\nplatform:\n- all\ntechniques:\n${techYaml(techs.slice().sort())}\n`; }
function reactPlaybook(techs, name) {
  const by = {}; const fa = new Set(); techs.forEach(t => (TK[t] ? TK[t].ra : []).forEach(r => { (by[RA[r][1]] = by[RA[r][1]] || new Set()).add(r); })); techs.forEach(t => (TK[t] ? TK[t].fa : []).forEach(f => fa.add(f)));
  const prepCats = new Set([...fa].map(f => KB.FACET_PREP[f]).filter(x => x !== undefined)); prepCats.add(0);
  const prep = Object.keys(RA).filter(r => RA[r][1] === "preparation" && prepCats.has(RA[r][2])).sort();
  const list = st => [...(by[st] || [])].sort().map(r => `  - ${r}  # ${RA[r][0]}`).join("\n") || "  []";
  return `title: RP_custom_${slug(name)}\nid: RP9${String(hash(name) % 1000).padStart(3, "0")}\ndescription: >\n  Playbook de resposta gerado pelo APT Threat Map para ${name}. Ações selecionadas heuristicamente\n  a partir das técnicas ATT&CK do ator (facetas: ${[...fa].sort().join(", ")}). Revisar antes do uso.\nauthor: APT Threat Map\ncreation_date: ${today().replace(/-/g, "/")}\nseverity: H\ntlp: AMBER\npap: AMBER\ntags:\n${techs.slice().sort().map(t => "  - attack." + t.toLowerCase()).join("\n")}\nreferences:\n  - https://github.com/atc-project/atc-react\npreparation:\n${prep.map(r => `  - ${r}  # ${RA[r][0]}`).join("\n")}\nidentification:\n${list("identification")}\ncontainment:\n${list("containment")}\neradication:\n${list("eradication")}\nrecovery:\n${list("recovery")}\nlessons_learned:\n  - RA6001  # Develop incident report\n  - RA6002  # Conduct lessons learned exercise\n`;
}
function sigmaBundle(techs) { const ids = new Set(); techs.forEach(t => techRules(t)[0].forEach(r => ids.add(r))); return [...ids].map(r => `# ${RULES[r].src === "Hub" ? "Hub" : RULES[r].u}\n` + RULES[r].y.trim()).join("\n---\n") + "\n"; }
function queriesBundle(techs, f, name) {
  const ids = new Set(); techs.forEach(t => techRules(t)[0].forEach(r => ids.add(r))); const lbl = FMT.find(x => x[0] === f)[1];
  let out = `# ${lbl} – consultas para ${name} (${ids.size} regras; geradas ${today()} por pySigma)\n# ${FNOTE[f]}\n\n`;
  [...ids].forEach(r => { const o = ruleQuery(RULES[r], f); out += `## ${RULES[r].t} [${RULES[r].tg.join(", ")}] (${RULES[r].lv})\n${o.err ? "# não suportado: " + o.err : (o.note ? "# nota: " + o.note + "\n" : "") + o.q + (f === "stellar" ? "\n# DSL:\n" + stellarDsl(o.q) : "")}\n\n`; });
  return out;
}
const csvq = v => `"${String(v ?? "").replace(/"/g, '""')}"`;
function traceCsv(e, via) {
  const rows = [["grupo", "mitre_id", "tecnica", "nome_tecnica", "taticas", "proveniencia", "ferramentas", "procedimento", "cobertura", "regras_sigma", "defender_tabelas", "asr", "d3fend", "data_components_dettect", "react"]];
  techSet(e, via).forEach((o, t) => { const k = TK[t]; if (!k) return; const [r] = techRules(t);
    rows.push([e.n, e.m, t, k.n, k.ta.join("|"), o.d ? "direta" : "via ferramenta", o.tools.map(x => TOOLS[x].n).join("|"), e.p[t] || "", covStat(t)[2], r.map(x => RULES[x].t).join("|"), k.mde.join("|"), k.asr.map(a => ASR[a][1]).join("|"), [...new Set(k.d3.map(x => x[0] + " " + D3[x[0]][0]))].join("|"), k.dc.join("|"), k.ra.map(x => x + " " + RA[x][0]).join("|")]); });
  return "\ufeff" + rows.map(r => r.map(csvq).join(",")).join("\n");
}

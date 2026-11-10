// =====================================================================================
// APT Threat Map – app (vanilla JS + D3 v7). Dados: KB (gzip+base64) descompactado no boot.
// =====================================================================================
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const TAC = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "stealth", "defense-impairment", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"];
const TACPT = {"reconnaissance": "Reconhecimento", "resource-development": "Desenv. de recursos", "initial-access": "Acesso inicial", "execution": "Execução", "persistence": "Persistência", "privilege-escalation": "Escalada de privilégio", "stealth": "Furtividade (Stealth)", "defense-impairment": "Enfraquecimento de defesas", "credential-access": "Acesso a credenciais", "discovery": "Descoberta", "lateral-movement": "Movimento lateral", "collection": "Coleta", "command-and-control": "Comando e controle", "exfiltration": "Exfiltração", "impact": "Impacto"};
const MOTIV = ["Espionagem", "Financeiro", "Sabotagem/Destrutivo", "Hacktivismo/Influência"];
const MCOL = {"Espionagem": "#4da3ff", "Financeiro": "#ffb347", "Sabotagem/Destrutivo": "#ff5d6c", "Hacktivismo/Influência": "#c084fc", "": "#7d8aa5"};
const OCOL = {CN: "#ff5d6c", RU: "#4da3ff", KP: "#ffb347", IR: "#2ecc8f"};
const PAL = ["#22d3ee", "#f472b6", "#a3e635", "#f59e0b", "#818cf8", "#fb7185", "#34d399", "#e879f9", "#fde047", "#60a5fa"];
const D3COL = {Model: "#94a3b8", Harden: "#2ecc8f", Detect: "#4da3ff", Isolate: "#ffb347", Deceive: "#c084fc", Evict: "#ff5d6c", Restore: "#22d3ee"};
const D3ORD = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"];
const STG = ["identification", "containment", "eradication", "recovery"];
const STGPT = {preparation: "Preparação", identification: "Identificação", containment: "Contenção", eradication: "Erradicação", recovery: "Recuperação", lessons_learned: "Lições aprendidas"};
const FMT = [["sigma", "Sigma"], ["splunk", "Splunk SPL"], ["elastic", "Elastic Lucene (ECS)"], ["eql", "Elastic EQL"], ["esql", "Elastic ES|QL"], ["opensearch", "OpenSearch Lucene"], ["qradar", "QRadar AQL"], ["stellar", "Stellar Cyber"], ["defender", "Defender XDR KQL"]];
const ECOL = {attr: "#f5c542", vic: "#ff6b6b", sec: "#2ecc8f", tool: "#ff9f43", tech: "#a78bfa", impl: "#64748b", rel: "#22d3ee", sim: "#f472b6"};
const NCOL = {c: "#f5c542", s: "#2ecc8f", t: "#ff9f43", k: "#a78bfa"};
let KB, E, TK, TOOLS, RULES, D3, RA, ASR, MIT, DET, CTRY, SRC, FILT = [];
const hash = s => [...String(s)].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7);
const ocol = iso => OCOL[iso] || (iso ? PAL[hash(iso) % PAL.length] : "#6b7a96");
const flag = iso => iso && iso.length === 2 && /^[A-Z]{2}$/.test(iso) ? String.fromCodePoint(...[...iso].map(c => 127397 + c.charCodeAt(0))) : "🏳️";
const cname = iso => (CTRY[iso] && CTRY[iso].n) || (ALLC[iso] && ALLC[iso][1]) || iso;
const tacIdx = t => { const ta = (TK[t] && TK[t].ta) || []; return Math.min(...ta.map(x => TAC.indexOf(x)).filter(x => x >= 0), 99); };
const attackUrl = t => `https://attack.mitre.org/techniques/${t.replace(".", "/")}/`;
const d3Url = id => D3[id] ? `https://d3fend.mitre.org/technique/d3f:${D3[id][3]}/` : "https://d3fend.mitre.org/";
const raUrl = id => RA[id] ? `https://atc-project.github.io/atc-react/Response_Actions/${RA[id][4]}/` : "#";
const mdeProd = tb => tb.startsWith("Device") ? "MDE" : tb.startsWith("Identity") ? "MDI" : (tb.startsWith("Email") || tb.startsWith("UrlClick")) ? "MDO" : tb.startsWith("CloudApp") ? "MDA" : tb.startsWith("EntraId") ? "Entra ID" : "XDR";
function dl(name, text, mime = "text/plain;charset=utf-8") { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], {type: mime})); a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 3000); }
const slug = s => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "").slice(0, 60);
const today = () => new Date().toISOString().slice(0, 10);
const tip = (ev, html) => { const t = $("#tip"); t.innerHTML = html; t.style.display = "block"; const x = Math.min(ev.clientX + 14, innerWidth - 360), y = Math.min(ev.clientY + 14, innerHeight - t.offsetHeight - 8); t.style.left = x + "px"; t.style.top = y + "px"; };
const hideTip = () => { $("#tip").style.display = "none"; };
let CB = []; // buffers para copiar
function code(lbl, txt, extra = "") { CB.push(txt); return `<div class="codehead"><span>${lbl}</span><span>${extra}<button class="btn sm" onclick="cp(${CB.length - 1},this)">copiar</button></span></div><pre>${esc(txt)}</pre>`; }
function cp(i, b) { navigator.clipboard.writeText(CB[i]).then(() => { b.textContent = "copiado ✔"; setTimeout(() => b.textContent = "copiar", 1200); }); }

// ------------------------------------------------------------------ boot
(async function boot() {
  try {
    const b64 = document.getElementById("kb").textContent.trim();
    const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const txt = await new Response(new Blob([bin]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
    KB = JSON.parse(txt);
  } catch (err) {
    $("#loading").innerHTML = `<div style="max-width:560px;text-align:center">Falha ao descompactar a base: ${esc(err)}.<br>Use um navegador moderno (Chrome/Edge ≥80, Firefox ≥113, Safari ≥16.4).</div>`; return;
  }
  try { init(); } catch (err) { console.error(err); $("#loading").innerHTML = "Erro na inicialização: " + esc(err.stack || err); return; }
  $("#loading").remove();
})();

let TOOLIX = {}, IDX = {};
function setPH() { const h = ($("#fbar").offsetHeight || 60) + ($("#nav").offsetHeight || 40); document.documentElement.style.setProperty("--ph", Math.max(480, innerHeight - h - 34) + "px"); $("#nav").style.top = ($("#fbar").offsetHeight || 46) + "px"; }
addEventListener("resize", setPH);
function init() {
  setPH();
  ({E, TK, TOOLS, RULES, D3, RA, ASR, MIT, DET, SRC} = KB); CTRY = KB.COUNTRIES;
  E.forEach((e, i) => {
    e.i = i; e.ns = e.s.length; e.nt = e.t.length; e.ntl = e.tl.length; e.nv = e.v.length; e.tset = new Set(e.t); e.mo0 = e.mo[0] || "";
    e.score = e.ns + (e.m ? 3 : 0) + Math.min(e.nt, 80) / 16 + Math.min(e.ntl, 40) / 20 + (e.ac ? (+e.ac) / 50 : 0);
    e._s = [e.n, e.a.join(" "), e.tl.map(k => TOOLS[k].n).join(" "), e.t.join(" "), e.m, e.c, e.sec.join(" "), e.ops.join(" "), e.sr.join(" ")].join(" ").toLowerCase();
  });
  TOOLS.forEach((t, i) => { t.i = i; TOOLIX[t.n.toLowerCase()] = i; });
  // índices reversos p/ grafo
  IDX = {orig: {}, vic: {}, sec: {}, tool: {}, tech: {}, toolTech: {}};
  E.forEach(e => {
    if (e.iso) (IDX.orig[e.iso] = IDX.orig[e.iso] || []).push(e.i);
    e.v.forEach(v => (IDX.vic[v] = IDX.vic[v] || []).push(e.i));
    e.sec.forEach(s => (IDX.sec[s] = IDX.sec[s] || []).push(e.i));
    e.tl.forEach(k => (IDX.tool[k] = IDX.tool[k] || []).push(e.i));
    e.t.forEach(t => (IDX.tech[t] = IDX.tech[t] || []).push(e.i));
  });
  TOOLS.forEach(t => t.t.forEach(k => (IDX.toolTech[k] = IDX.toolTech[k] || []).push(t.i)));
  buildFilters(); buildKpis();
  $$("#nav button").forEach(b => b.onclick = () => showTab(b.dataset.t));
  applyFilters();
  initTraceUI(); initPrioUI(); initDetUI(); initMxUI(); initGrpUI(); renderSources();
  if (location.hash.startsWith("#g=")) { const i = +location.hash.slice(3); if (E[i]) openD(i); }
}
let CUR = "map";
function showTab(t) {
  CUR = t; $$("#nav button").forEach(x => x.classList.toggle("on", x.dataset.t === t)); $$(".tab").forEach(x => x.classList.toggle("on", x.id === "t-" + t));
  refreshActive();
}
function refreshActive() {
  if (CUR === "map") renderMap();
  else if (CUR === "graph") { if (!G.init) initGraph(); buildGraph(); }
  else if (CUR === "trace") renderTrace();
  else if (CUR === "det") renderDet();
  else if (CUR === "mx") renderMx();
  else if (CUR === "grp") renderGrp();
  else if (CUR === "prio") { if (!PR.done) runPrio(); }
}
// ------------------------------------------------------------------ KPIs
function buildKpis() {
  const nT = Object.keys(TK).length, nR = Object.keys(RULES).length;
  const k = [[E.length, "grupos/entidades"], [E.filter(e => e.nt).length, "com TTPs ATT&CK"], [E.filter(e => e.ns >= 3).length, "corroborados (≥3 fontes)"], [E.filter(e => e.iso).length, "com origem geolocalizada"],
    [TOOLS.length, "ferramentas/malware"], [nT, "técnicas mapeadas"], [nR, "regras Sigma (9 formatos)"], [Object.keys(D3).length, "contramedidas D3FEND"], [Object.keys(RA).length, "ações RE&CT"], [ASR.length, "regras ASR Defender"], [SRC.length, "fontes integradas"]];
  $("#kpis").innerHTML = k.map(([v, l]) => `<div class="kpi"><b>${v.toLocaleString("pt-BR")}</b><small>${l}</small></div>`).join("");
}
// ------------------------------------------------------------------ filtros globais
const F = {q: "", orig: "", vic: "", sec: "", mot: "", ty: "", tech: "", tool: "", src: "", min: 1, ttp: false};
function buildFilters() {
  const oc = {}; E.forEach(e => { if (e.iso) oc[e.iso] = (oc[e.iso] || 0) + 1; });
  const unl = E.filter(e => !e.iso).length;
  $("#fOrig").insertAdjacentHTML("beforeend", Object.entries(oc).sort((a, b) => b[1] - a[1]).map(([i, n]) => `<option value="${i}">${flag(i)} ${esc(cname(i))} (${n})</option>`).join("") + `<option value="-">❔ sem origem atribuída (${unl})</option>`);
  const vc = {}; E.forEach(e => e.v.forEach(v => vc[v] = (vc[v] || 0) + 1));
  $("#fVic").insertAdjacentHTML("beforeend", Object.entries(vc).sort((a, b) => b[1] - a[1]).map(([i, n]) => `<option value="${i}">${flag(i)} ${esc(cname(i))} (${n})</option>`).join(""));
  const sc = {}; E.forEach(e => e.sec.forEach(s => sc[s] = (sc[s] || 0) + 1));
  $("#fSec").insertAdjacentHTML("beforeend", Object.entries(sc).sort((a, b) => b[1] - a[1]).map(([s, n]) => `<option value="${esc(s)}">${esc(s)} (${n})</option>`).join(""));
  $("#fMot").insertAdjacentHTML("beforeend", MOTIV.map(m => `<option>${m}</option>`).join("") + `<option value="-">não informada</option>`);
  const tc = {}; E.forEach(e => { const t = e.ty || "—"; tc[t] = (tc[t] || 0) + 1; });
  $("#fTy").insertAdjacentHTML("beforeend", Object.entries(tc).sort((a, b) => b[1] - a[1]).map(([t, n]) => `<option value="${esc(t)}">${esc(t)} (${n})</option>`).join(""));
  $("#fSrc").insertAdjacentHTML("beforeend", SRC.map((s, i) => `<option value="${i}">${esc(s)}</option>`).join(""));
  $("#dlTech").innerHTML = Object.entries(TK).sort((a, b) => b[1].ng - a[1].ng).map(([t, v]) => `<option value="${t}">${esc(v.n)} (${v.ng} grupos)</option>`).join("");
  $("#dlTool").innerHTML = TOOLS.filter(t => t.g > 0).sort((a, b) => b.g - a.g).map(t => `<option value="${esc(t.n)}">${t.s ? t.s + " · " : ""}${t.g} grupos</option>`).join("");
  $("#dlGrp").innerHTML = E.filter(e => e.nt || e.ntl).sort((a, b) => b.score - a.score).map(e => `<option value="${esc(e.n)}">${e.m || ""} ${esc(cname(e.iso) || e.c)}</option>`).join("");
  const on = (id, k, fn = v => v) => $(id).addEventListener("input", () => { F[k] = fn($(id).value); applyFilters(); });
  on("#fq", "q", v => v.toLowerCase().trim()); on("#fOrig", "orig"); on("#fVic", "vic"); on("#fSec", "sec"); on("#fMot", "mot"); on("#fTy", "ty"); on("#fSrc", "src"); on("#fMin", "min", v => +v);
  on("#fTech", "tech", v => v.trim().toUpperCase()); on("#fTool", "tool", v => v.trim().toLowerCase());
  $("#fTTP").onchange = () => { F.ttp = $("#fTTP").checked; applyFilters(); };
  $("#fClr").onclick = () => { Object.assign(F, {q: "", orig: "", vic: "", sec: "", mot: "", ty: "", tech: "", tool: "", src: "", min: 1, ttp: false}); ["#fq", "#fOrig", "#fVic", "#fSec", "#fMot", "#fTy", "#fTech", "#fTool", "#fSrc"].forEach(s => $(s).value = ""); $("#fMin").value = "1"; $("#fTTP").checked = false; MAP.selG = null; MAP.selC = null; applyFilters(); };
  $$("[data-preset]").forEach(b => b.onclick = () => {
    $("#fClr").click(); const p = b.dataset.preset;
    if (p === "br") { F.vic = "BR"; $("#fVic").value = "BR"; }
    if (p === "fin") { F.sec = "Financeiro"; $("#fSec").value = "Financeiro"; }
    if (p === "gov") { F.sec = "Governo"; $("#fSec").value = "Governo"; }
    applyFilters(); if (p === "br" && CUR === "map") countryPanel("BR");
  });
}
let TECHMATCH = null;
function passes(e) {
  if (F.q && !F.q.split(/\s+/).every(w => e._s.includes(w))) return false;
  if (F.orig) { if (F.orig === "-") { if (e.iso) return false; } else if (e.iso !== F.orig) return false; }
  if (F.vic && !e.v.includes(F.vic)) return false;
  if (F.sec && !e.sec.includes(F.sec)) return false;
  if (F.mot) { if (F.mot === "-") { if (e.mo.length) return false; } else if (!e.mo.includes(F.mot)) return false; }
  if (F.ty && (e.ty || "—") !== F.ty) return false;
  if (F.src !== "" && !e.s.includes(+F.src)) return false;
  if (e.ns < F.min) return false;
  if (F.ttp && !e.nt) return false;
  if (F.tech) { if (!(e.tset.has(F.tech) || e.t.some(t => t.startsWith(F.tech + ".")))) return false; }
  if (F.tool) { const ix = TOOLIX[F.tool]; if (ix !== undefined) { if (!e.tl.includes(ix)) return false; } else if (!e.tl.some(k => TOOLS[k].n.toLowerCase().includes(F.tool))) return false; }
  return true;
}
function applyFilters() {
  FILT = E.filter(passes);
  $("#fcount").innerHTML = `<b>${FILT.length.toLocaleString("pt-BR")}</b> de ${E.length.toLocaleString("pt-BR")} grupos no recorte`;
  refreshActive();
}
// ------------------------------------------------------------------ técnicas de um grupo (diretas + via ferramentas)
function techSet(e, via) {
  const m = new Map(); e.t.forEach(t => m.set(t, {d: 1, tools: []}));
  if (via) e.tl.forEach(k => TOOLS[k].t.forEach(t => { if (!TK[t]) return; const o = m.get(t) || {d: 0, tools: []}; o.tools.push(k); m.set(t, o); }));
  return m;
}
function covStat(t) {
  const k = TK[t]; if (!k) return ["gap", "○", "sem dados"];
  const nr = k.r.length || ((t.includes(".") && TK[t.split(".")[0]]) ? TK[t.split(".")[0]].r.length : 0);
  if (nr) return ["ok", "●", nr + " regra(s)" + (k.r.length ? "" : " (via técnica-pai)")];
  const det = k.d3.filter(r => D3[r[0]] && D3[r[0]][1] === "Detect").length;
  if (k.asr.length || det) return ["pa", "◐", (k.asr.length ? k.asr.length + " ASR " : "") + (det ? det + " D3FEND-Detect" : "")];
  return ["gap", "○", "lacuna"];
}

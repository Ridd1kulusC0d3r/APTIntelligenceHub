"""Monta o APT Threat Map (HTML único, offline) + artefatos complementares (CSV, MD, ZIPs, DeTT&CT, Navigator, RE&CT)."""
from paths import BUILD, EXT, OUT, RAW, REPO  # diretórios configuráveis: ver pipeline/paths.py
import sys, json, gzip, base64, os, csv, zipfile, re, io, datetime, collections, html
import pycountry

B = BUILD; os.makedirs(OUT, exist_ok=True)
KB = json.load(open(f"{B}/kb.json"))
IR = json.load(open(f"{B}/ir.json")); DISC = json.load(open(f"{B}/disc.json"))
CENT = json.load(open(f"{B}/centroids.json"))
WORLD = json.load(open(f"{B}/vendor/countries-110m.json"))
ALLC = {c.alpha_2: [c.numeric, getattr(c, "common_name", None) or c.name] for c in pycountry.countries}
ALLC["XK"] = ["-99", "Kosovo"]
GEN = datetime.date.today().strftime("%d/%m/%Y")
E, TK, TOOLS, RULES, D3, RA, ASR = KB["E"], KB["TK"], KB["TOOLS"], KB["RULES"], KB["D3"], KB["RA"], KB["ASR"]
cs = KB["CONVSTATS"]

SOURCES = [
 dict(n="MITRE ATT&CK – Groups / STIX (mitre/cti)", u="https://attack.mitre.org/groups/", t="Base de conhecimento STIX 2.1", key="MITRE ATT&CK",
      used="Grupos, aliases, técnicas + procedimentos (descrição das relações), software→técnica, campanhas, mitigações (M-codes), data components/log sources (detection strategies → analytics)", note="Fonte primária de TTPs; IDs Gxxxx = chave de deduplicação. Dados modificados até 04/11/2026; táticas Stealth/Defense Impairment substituem Defense Evasion."),
 dict(n="APTmap (andreacristaldi) – site + GitHub", u="https://github.com/andreacristaldi/APTmap", t="GeoJSON de 816 atores + relações", key="APTmap",
      used="Coordenadas (validadas por point-in-polygon), países e setores-alvo, motivações, patrocínio, confiança de atribuição, ferramentas com descrição, procedimentos TTP, relações (similar/overlaps/related-to) com linguagem estimativa", note="Casamento estrito pelo nome principal/ID MITRE; aliases do APTmap só são anexados quando não pertencem a outra entidade. Hashes/IOCs/amostras NÃO foram usados."),
 dict(n="ThaiCERT/ETDA – Threat Group Cards (MISP galaxy)", u="https://apt.etda.or.th/cgi-bin/aptgroups.cgi", t="Enciclopédia de atores", key="ThaiCERT Threat Group Cards",
      used="Sinônimos, país (ISO), patrocínio, motivação, setores, vítimas, operações", note="Mesma base dos PDFs Threat Actor Encyclopedia / Threat Group Cards v2.0."),
 dict(n="MISP Galaxy – threat-actor", u="https://github.com/MISP/misp-galaxy", t="Galáxia JSON", key="MISP Galaxy", used="Sinônimos, país, setores/vítimas (CFR), relações entre atores (similar/overlaps…)", note="Alias-heavy: maior cobertura, maior risco de conflito de aliases."),
 dict(n="Google Cloud (Mandiant) – APT groups", u="https://cloud.google.com/security/resources/insights/apt-groups", t="Página do fornecedor", key="Google Cloud (Mandiant) APT Groups", used="APT1–APT45: atribuição suspeita, setores, visão geral, malware associado, vetores de ataque (texto)", note="Antiga página FireEye APT Groups."),
 dict(n="Wikipedia – Advanced persistent threat (lista por país)", u="https://en.wikipedia.org/wiki/Advanced_persistent_threat", t="Enciclopédia", key="Wikipedia APT list", used="Lista país→grupos para corroboração e origem", note="Fonte terciária; usada só como corroboração."),
 dict(n="BRANDEFENSE threat-actor-dataset", u="https://github.com/BRANDEFENSE/threat-actor-dataset", t="Dataset JSON (APT + ransomware)", key="BRANDEFENSE dataset", used="Aliases, origem, setores, link para perfil com fontes primárias", note=""),
 dict(n="EternalLiberty", u="https://github.com/StrangerealIntel/EternalLiberty", t="Matriz de nomes por fornecedor", key="EternalLiberty", used="Nomes por fornecedor, tipo, país", note=""),
 dict(n="Microsoft threat actor naming + MSFT↔CrowdStrike", u="https://learn.microsoft.com/en-us/unified-secops-platform/microsoft-threat-actor-naming", t="Taxonomia do fornecedor", key="Microsoft Threat Actor Naming", used="Nomes Microsoft (Blizzard/Typhoon/Sandstorm…) e equivalência CrowdStrike", note=""),
 dict(n="Malpedia (Fraunhofer FKIE)", u="https://malpedia.caad.fkie.fraunhofer.de/actors", t="Atores e famílias", key="Malpedia", used="IDs de ator para links", note="Amostras exigem conta."),
 dict(n="cyber-research/APTMalware", u="https://github.com/cyber-research/APTMalware", t="~4,4k amostras + overview.csv", key="cyber-research/APTMalware", used="Somente contagem de amostras por grupo (metadados)", note="⚠ Binários vivos (zips senha 'infected'). Nunca baixados/executados aqui; manipular apenas em laboratório isolado."),
 dict(n="Planilhas Google fornecidas (APT Groups & Operations; Malware, IR – Tools & Resources)", u="https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/edit", t="Google Sheets", key="Planilha APT Groups & Operations", used="Base de nomes/operações/toolset por origem; catálogo de ferramentas IR", note=""),
 dict(n="SigmaHQ (rules, threat-hunting, emerging-threats)", u="https://github.com/SigmaHQ/sigma", t="Regras de detecção", key="SigmaHQ emerging-threats", used=f"{len(RULES)} regras selecionadas por técnica (até 3; stable/test ≥ medium) + regras de ator", note="Convertidas com pySigma."),
 dict(n="pySigma backends (Splunk, Elasticsearch, OpenSearch, QRadar AQL, Kusto)", u="https://github.com/SigmaHQ/pySigma", t="Conversores", used="Splunk 3.0 (pySigma 2.x) · Elasticsearch 2.1 / OpenSearch 2.0 / Kusto 1.0 (pySigma 1.5) · QRadar AQL 0.3 (pySigma 0.11) — ambientes isolados por conflito de dependências", note="Stellar Cyber: sem backend oficial → Lucene com campos nativos + DSL."),
 dict(n="MITRE D3FEND (API)", u="https://d3fend.mitre.org/", t="Ontologia de contramedidas", used=f"API offensive-technique/attack/<T>.json para {len(TK)} técnicas: contramedida, tática D3FEND e artefatos digitais (ofensivo↔defensivo)", note="Sub-técnicas sem mapeamento herdam da técnica-pai (sinalizado)."),
 dict(n="MITRE RE&CT (atc-project/atc-react)", u="https://github.com/atc-project/atc-react", t="Framework de resposta a incidentes", used=f"{len(RA)} response actions (estágio/categoria) mapeadas por facetas da técnica; geração de playbook no formato RP", note="RE&CT não mapeia ATT&CK→ações nativamente: o vínculo é heurístico (documentado)."),
 dict(n="DeTT&CT (Rabobank CDC)", u="https://github.com/rabobank-cdc/DeTTECT", t="Framework de visibilidade/detecção", used="Exportação de YAML group-administration (v1.0), data-source-administration (v1.1) e technique-administration (v1.2)", note="Templates: pontuações devem ser preenchidas pela sua equipe."),
 dict(n="Microsoft Defender – ASR rules reference", u="https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference", t="Documentação oficial", used="GUIDs e ActionTypes de advanced hunting das 19 regras ASR (verificados na página oficial)", note="Mapeamento ASR→ATT&CK é curadoria do analista a partir da descrição de cada regra."),
 dict(n="Hudson Rock – Cavalier OSINT (infostealers)", u="https://www.hudsonrock.com/threat-intelligence-cybercrime-tools", t="Inteligência de infostealers", used="Atalho de consulta por domínio na aba Priorização (T1078/T1555/T1539)", note="Não há dados de atribuição APT consumíveis; endpoint não verificado do ambiente de geração."),
 dict(n="Radware – Live Threat Map", u="https://livethreatmap.radware.com/", t="Mapa de ataques em tempo real", used="Referência visual/contexto (não integrado)", note="Telemetria de ataques (DDoS/web) sem atribuição a grupos."),
 dict(n="Nuix", u="https://www.nuix.com/", t="Plataforma de investigação/DFIR", used="Referência (não integrado)", note="Sem dataset aberto de atores."),
 dict(n="CounterCraft – deception (OT)", u="https://www.countercraftsec.com/", t="Blog/whitepaper de deception", used="Embasamento da tática D3FEND Deceive (decoys PLC/HMI, breadcrumbs, detecção de recon e movimento lateral)", note=""),
 dict(n="Medium (aardvark) – artigo indicado", u="https://medium.com/", t="Blog", used="Não consumido", note="Acesso bloqueado (paywall/anti-bot) durante a coleta."),
 dict(n="world-atlas / D3 / topojson-client", u="https://github.com/topojson/world-atlas", t="Geodados e bibliotecas", used="Mapa base 110m embutido; centróides calculados do 50m (inclui países pequenos)", note="Embutidos no HTML (funciona offline)."),
]
METHOD = f"""<ol>
<li><b>Consolidação/deduplicação</b>: planilha base → MITRE (ID Gxxxx precede) → ThaiCERT → EternalLiberty → MISP → Microsoft/CrowdStrike → BRANDEFENSE → SigmaHQ → <b>APTmap</b> (casamento estrito) → <b>Google Cloud</b> → <b>Wikipedia</b>. Aliases normalizados (minúsculas, sem espaços/pontuação; sufixos “group/team/gang/crew” removidos ⇒ “Equation Group” ≡ “Equation”). Nome canônico = nome MITRE quando houver ID. Sem fusão transitiva.</li>
<li><b>Normalização para TI</b>: setores livres → 21 setores canônicos (regex); vitimologia → ISO-3166 (países) + “outros alvos” (organizações/regiões); motivação → Espionagem/Financeiro/Sabotagem/Hacktivismo; origem → ISO (ThaiCERT/MISP/APTmap/planilha).</li>
<li><b>Ferramentas/artefatos</b>: software ATT&CK (Sxxxx) + ferramentas APTmap + toolset da planilha, casados a Sxxxx por nome/alias; demais viram nós próprios (sem técnicas). Técnicas “via ferramenta” = software ATT&CK → técnica (opcional na traçagem/priorização).</li>
<li><b>Similaridade entre grupos</b>: cosseno TF-IDF sobre {{técnicas ∪ ferramentas}} (grupos com ≥8 atributos; atributos presentes em &gt;60% ignorados), mantidos pares ≥0,22 (top-6). Indicador de sobreposição de tradecraft/duplicidade — <i>não</i> é atribuição.</li>
<li><b>Relevância/prioridade (Threat-Informed Defense)</b>: W<sub>g</sub> = (w<sub>setor</sub>·[setor] + w<sub>país</sub>·[país]) × (0,5 + 0,5·min(1, fontes/8) + 0,15·[ATT&CK]); P(t) = Σ W<sub>g</sub> normalizada 0–100. Cobertura: ● regra, ◐ ASR/D3FEND-Detect, ○ lacuna.</li>
<li><b>Microsoft Defender</b>: data components ATT&CK → tabelas/ActionTypes de advanced hunting (MDE/MDI/MDO/MDA/Entra) por tabela de correspondência curada; ASR (19 regras, GUID/ActionType verificados na documentação oficial) → técnicas por curadoria; regras Sigma convertidas para KQL XDR quando o logsource tem equivalente.</li>
<li><b>D3FEND</b>: API oficial por técnica (artefato ofensivo ↔ contramedida ↔ artefato defensivo); sub-técnicas sem mapeamento herdam da técnica-pai. <b>DeTT&CT</b>: data components como <code>data_source_name</code>; YAMLs são templates (scores a preencher). <b>RE&CT</b>: facetas (rede externa/interna, exfiltração, e-mail, arquivo, processo, registro, serviço, identidade, vulnerabilidade, destrutivo) derivadas de data components, artefatos D3FEND, táticas e IDs → ações por estágio; preparação por categoria.</li>
<li><b>Conversão de regras</b> (pySigma, 3 ambientes isolados): Splunk {cs['splunk']['ok']}/{len(RULES)} · Elastic Lucene {cs['elastic']['ok']} · EQL {cs['eql']['ok']} · ES|QL {cs['esql']['ok']} · OpenSearch {cs['opensearch']['ok']} · QRadar {cs['qradar']['ok']} (+{cs['qradar']['fb']} via payload) · Stellar {cs['stellar']['ok']} · Defender XDR {cs['defender']['ok']}.</li>
</ol>
<h4 style="color:var(--acc)">Limitações</h4><ul>
<li>Atribuição é contestável e varia entre fornecedores; aliases conflitantes entre fontes podem gerar fusões frouxas (ex.: a planilha lista UNC4841 como alias de FamousSparrow/GhostEmperor). Valide grupos críticos manualmente.</li>
<li>Vitimologia/setores refletem o que é publicamente reportado (viés de visibilidade dos fornecedores); ausência ≠ não alvo.</li>
<li>Mapeamentos Defender (tabelas/ASR) e RE&CT são heurísticos/curados; D3FEND não cobre técnicas pré-ataque e várias recentes.</li>
<li>Conversões automáticas: campos/índices precisam de ajuste por ambiente; QRadar “payload” é custoso; Stellar Cyber exige mapeamento para chaves Interflow; ES|QL não suporta keywords livres; Defender XDR não cobre logsources de Script Block/Security/cloud/proxy.</li>
<li>Fontes não consumíveis: Hudson Rock (somente lookup por domínio), Radware live map, Nuix e o artigo do Medium (bloqueado) — apenas referenciados.</li>
<li>Nenhuma amostra de malware foi baixada ou executada; APTMalware/APTmap só como metadados.</li></ul>"""
META = dict(sources=SOURCES, method=METHOD, ir=IR, disc=DISC)
json.dump(SOURCES, open(f"{B}/sources.json", "w"), ensure_ascii=False)

# ---------------- HTML
# Grava o payload em src/data/ e delega a montagem a tools/build.py (mesmo montador usado no CI).
raw = json.dumps(KB, ensure_ascii=False, separators=(",", ":")).encode()
b64 = base64.b64encode(gzip.compress(raw, 9)).decode()
static = ("const WORLD=" + json.dumps(WORLD, separators=(",", ":")) + ";\nconst CENT=" + json.dumps(CENT, separators=(",", ":")) +
          ";\nconst ALLC=" + json.dumps(ALLC, ensure_ascii=False, separators=(",", ":")) + ";\nconst META=" + json.dumps(META, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/") + ";\n")
SRC_DATA = REPO / "src" / "data"
(SRC_DATA / "kb.json.gz.b64").write_text(b64, encoding="utf-8")
(SRC_DATA / "static.js").write_text(static, encoding="utf-8")
(SRC_DATA / "meta.json").write_text(json.dumps({"kb_mb": f"{len(raw) / 1e6:.1f}", "generated": GEN}, indent=1), encoding="utf-8")
sys.path.insert(0, str(REPO / "tools"))
import build as site_build  # noqa: E402
HTML = site_build.build()
(REPO / "index.html").write_text(HTML, encoding="utf-8")
open(f"{OUT}/APT_Threat_Map.html", "w", encoding="utf-8").write(HTML)
print("HTML MB", round(len(HTML.encode()) / 1e6, 2), "| KB raw", round(len(raw) / 1e6, 2), "gz+b64", round(len(b64) / 1e6, 2))

# ---------------- CSV grupos
SRC = KB["SRC"]
with open(f"{OUT}/APT_groups_consolidated.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["nome", "origem_iso", "pais_bloco", "mitre_id", "motivacao", "motivacao_original", "setores_canonicos", "setores_originais", "paises_alvo_iso", "outros_alvos",
                "n_fontes", "fontes", "confianca_atribuicao_aptmap", "n_tecnicas", "tecnicas", "ferramentas", "ferramentas_mitre", "similares_ttp", "relacoes_declaradas",
                "campanhas_attack", "aliases", "patrocinio", "ativo_desde", "tipo", "malpedia", "thaicert_uuid", "brandefense", "amostras_aptmalware"])
    for e in sorted(E, key=lambda x: (-len(x["s"]), x["n"])):
        w.writerow([e["n"], e["iso"], e["c"], e["m"], "|".join(e["mo"]), "|".join(e["mr"]), "|".join(e["sec"]), "|".join(e["sr"]), "|".join(e["v"]), "|".join(e["vo"]),
                    len(e["s"]), "|".join(SRC[k] for k in e["s"]), e["ac"], len(e["t"]), "|".join(e["t"]), "|".join(TOOLS[k]["n"] for k in e["tl"]),
                    "|".join(TOOLS[k]["s"] for k in e["tl"] if TOOLS[k]["s"]), "|".join(f"{E[j]['n']}:{s}" for j, s in e["sim"]),
                    "|".join(f"{t}:{E[j]['n']}" + (f" ({l})" if l else "") for j, t, l in e["rel"]), "|".join(c["id"] + " " + c["n"] for c in e["camp"]),
                    "|".join(e["a"]), e["sp"], e["fs"], e["ty"], e["mal"], e["etda"], e["bd"], e["aptm"]])

# ---------------- matriz técnica → defesa
def rules_of(t):
    r = TK[t]["r"]
    if not r and "." in t and t.split(".")[0] in TK: r = TK[t.split(".")[0]]["r"]
    return r
def cov(t):
    k = TK[t]
    if rules_of(t): return "regra"
    if k["asr"] or any(D3[x[0]][1] == "Detect" for x in k["d3"]): return "parcial (ASR/D3FEND)"
    return "lacuna"
with open(f"{OUT}/technique_defense_matrix.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["tecnica", "nome", "taticas", "plataformas", "n_grupos", "cobertura", "regras_sigma", "formatos_ok(splunk/elastic/eql/esql/opensearch/qradar/stellar/defender)",
                "defender_tabelas", "asr_regras", "asr_guids", "d3fend_contramedidas", "d3fend_artefatos_ofensivos", "mitigacoes_attack", "data_components_dettect", "log_sources", "react_acoes", "facetas"])
    for t, k in sorted(TK.items(), key=lambda x: -x[1]["ng"]):
        rr = rules_of(t)
        fm = "/".join(str(sum(1 for r in rr if isinstance(RULES[r]["f"].get(x), str) or (isinstance(RULES[r]["f"].get(x), dict) and "q" in RULES[r]["f"][x])))
                      for x in ["splunk", "elastic", "eql", "esql", "opensearch", "qradar", "stellar", "defender"])
        w.writerow([t, k["n"], "|".join(k["ta"]), "|".join(k["pl"]), k["ng"], cov(t), "|".join(RULES[r]["t"] for r in rr), fm, "|".join(k["mde"]),
                    "|".join(ASR[a][1] for a in k["asr"]), "|".join(ASR[a][0] for a in k["asr"]), "|".join(sorted({f"{x[0]} {D3[x[0]][0]} ({D3[x[0]][1]})" for x in k["d3"]})),
                    "|".join(sorted({x[1] for x in k["d3"]})), "|".join(f"{m} {KB['MIT'].get(m, '')}" for m in k["mit"]), "|".join(k["dc"]), "|".join(k["ls"]),
                    "|".join(f"{r} {RA[r][0]} [{RA[r][1]}]" for r in k["ra"]), "|".join(k["fa"])])
# ---------------- traçagem grupo→ferramenta→técnica→defesa (todos os grupos com TTPs)
with open(f"{OUT}/group_trace_chain.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["grupo", "mitre_id", "origem", "tecnica", "nome_tecnica", "proveniencia", "ferramentas_que_implementam", "procedimento", "cobertura", "regras",
                "defender_tabelas", "asr", "d3fend", "data_components", "react"])
    for e in E:
        if not e["t"]: continue
        for t in e["t"]:
            if t not in TK: continue
            k = TK[t]; tools = [TOOLS[x]["n"] for x in e["tl"] if t in TOOLS[x]["t"]]
            w.writerow([e["n"], e["m"], e["iso"] or e["c"], t, k["n"], "direta", "|".join(tools), e["p"].get(t, ""), cov(t), "|".join(RULES[r]["t"] for r in rules_of(t)),
                        "|".join(k["mde"]), "|".join(ASR[a][1] for a in k["asr"]), "|".join(sorted({D3[x[0]][0] for x in k["d3"]})), "|".join(k["dc"]), "|".join(k["ra"])])

# ---------------- pacote de detecções multi-formato
EXT = dict(sigma="yml", splunk="spl", elastic="lucene", eql="eql", esql="esql", opensearch="lucene", qradar="aql", stellar="lucene", defender="kql")
with zipfile.ZipFile(f"{OUT}/detections_multiformat.zip", "w", zipfile.ZIP_DEFLATED) as z:
    idx = io.StringIO(); wi = csv.writer(idx); wi.writerow(["rule_id", "titulo", "nivel", "status", "origem", "logsource", "tecnicas", "n_grupos_que_usam", "url"] + list(EXT))
    for rid, r in RULES.items():
        base = re.sub(r"[^a-z0-9]+", "_", r["t"].lower()).strip("_")[:70] + "__" + rid[:8]
        z.writestr(f"sigma/{base}.yml", r["y"])
        st = []
        for fmt, ext in EXT.items():
            if fmt == "sigma": st.append("ok"); continue
            v = r["f"].get(fmt)
            if isinstance(v, str): q, note = v, ""
            elif isinstance(v, dict) and "q" in v: q, note = v["q"], v.get("note", "")
            else: st.append("nao_suportado: " + (v or {}).get("err", "")[:80] if isinstance(v, dict) else "nao_convertido"); continue
            hdr = {"splunk": "`comment(\"{}\")`", "kql": "// {}", "aql": "/* {} */", "lucene": "// {}", "eql": "// {}", "esql": "// {}"}
            cmt = f"{r['t']} | {', '.join(r['tg'])} | {r['u'] or 'Hub'}" + (f" | NOTA: {note}" if note else "")
            body = q
            if fmt == "stellar": body = q + "\n\n// Stellar Cyber Query Builder (DSL):\n" + json.dumps({"query": {"bool": {"must": [{"query_string": {"query": q, "analyze_wildcard": True}}]}}}, indent=2)
            prefix = ("// " if ext in ("kql", "lucene", "eql", "esql") else "# " if ext == "spl" else "-- ") + cmt + "\n"
            z.writestr(f"{fmt}/{base}.{ext}", prefix + body + "\n"); st.append("ok" + (" (fallback)" if note else ""))
        ng = len({i for t in r["tg"] for i, e in enumerate(E) if t in e["t"]})
        wi.writerow([rid, r["t"], r["lv"], r["st"], r["src"], r["ls"], "|".join(r["tg"]), ng, r["u"]] + st)
    z.writestr("index.csv", "\ufeff" + idx.getvalue())
    z.writestr("README.txt", "Detecções multi-formato geradas por pySigma a partir de regras SigmaHQ + regras próprias do hub.\n"
               "Pastas: sigma (original), splunk, elastic (Lucene/ECS), eql, esql, opensearch, qradar (AQL), stellar (Lucene + DSL, campos nativos – mapear p/ Interflow), defender (KQL XDR).\n"
               "Validar em homologação; ajustar índices/sourcetypes/campos. index.csv lista status por formato.\n")

# ---------------- DeTT&CT + Navigator + RE&CT (grupos prioritários e todos os grupos ATT&CK)
def yq(s): return "'" + str(s).replace("'", "''") + "'"
PRI = list(KB["DET"].keys())
with zipfile.ZipFile(f"{OUT}/dettect_navigator_react.zip", "w", zipfile.ZIP_DEFLATED) as z:
    y = "version: 1.0\nfile_type: group-administration\ndomain: enterprise-attack\nplatform:\n  - all\ngroups:\n"
    for e in sorted([e for e in E if e["t"]], key=lambda x: x["n"]):
        sw = sorted({TOOLS[k]["s"] for k in e["tl"] if TOOLS[k]["s"]})
        y += f"  - group_name: {yq(e['n'])}\n    campaign: {yq('APT Threat Map ' + GEN)}\n    technique_id:\n" + "".join(f"      - {t}\n" for t in e["t"]) + \
             ("    software_id:\n" + "".join(f"      - {s}\n" for s in sw) if sw else "    software_id: []\n") + "    enabled: true\n"
    z.writestr("dettect/groups_all_attack.yaml", y)
    for m in PRI:
        e = next((x for x in E if x["m"] == m), None)
        if not e: continue
        sl = re.sub(r"[^a-z0-9]+", "_", e["n"].lower())
        # Navigator
        lay = dict(name=f"{e['n']} – APT Threat Map", versions=dict(layer="4.5", navigator="5.1.0"), domain="enterprise-attack",
                   description=f"Técnicas de {e['n']} com cobertura do catálogo (score 3=regra, 2=parcial, 1=lacuna)",
                   techniques=[dict(techniqueID=t, score={"regra": 3, "parcial (ASR/D3FEND)": 2, "lacuna": 1}[cov(t)], comment=(e["p"].get(t, "") + " | cobertura: " + cov(t))[:900], enabled=True)
                               for t in e["t"] if t in TK],
                   gradient=dict(colors=["#ff5d6c", "#ffb347", "#2ecc8f"], minValue=1, maxValue=3), layout=dict(layout="side", showName=True, showID=True))
        z.writestr(f"navigator/{sl}_coverage.json", json.dumps(lay, ensure_ascii=False, indent=1))
        # DeTT&CT data sources
        c = collections.Counter(d for t in e["t"] if t in TK for d in TK[t]["dc"])
        ds = f"version: 1.1\nfile_type: data-source-administration\nname: {yq(e['n'] + ' – data sources')}\ndomain: enterprise-attack\nsystems:\n  - applicable_to: all\n    platform:\n      - all\ndata_sources:\n"
        for dc, n in c.most_common():
            prods = (KB["DC2MDE"].get(dc) or [])[:3] or ["<preencher>"]
            ds += f"  - data_source_name: {dc}\n    data_source:\n      - applicable_to:\n          - all\n        date_registered:\n        date_connected:\n        products:\n" + "".join(f"          - {yq('Microsoft Defender XDR – ' + p if p != '<preencher>' else p)}\n" for p in prods) + \
                  f"        available_for_data_analytics: false\n        comment: {yq(f'Necessário p/ {n} técnica(s) de ' + e['n'] + ' | template')}\n        data_quality:\n          device_completeness: 0\n          data_field_completeness: 0\n          timeliness: 0\n          consistency: 0\n          retention: 0\n"
        z.writestr(f"dettect/{sl}_data_sources.yaml", ds)
        # RE&CT playbook
        by = collections.defaultdict(set)
        for t in e["t"]:
            for r in (TK.get(t) or {}).get("ra", []): by[RA[r][1]].add(r)
        rp = f"title: RP_custom_{sl}\nid: RP9{abs(hash(sl)) % 1000:03d}\ndescription: >\n  Playbook gerado (heurístico) a partir das técnicas ATT&CK de {e['n']}. Revisar antes do uso.\nauthor: APT Threat Map\ncreation_date: {datetime.date.today():%Y/%m/%d}\nseverity: H\ntlp: AMBER\npap: AMBER\ntags:\n" + \
             "".join(f"  - attack.{t.lower()}\n" for t in e["t"]) + "".join(f"{st}:\n" + ("".join(f"  - {r}  # {RA[r][0]}\n" for r in sorted(by[st])) or "  []\n") for st in ["identification", "containment", "eradication", "recovery"]) + \
             "lessons_learned:\n  - RA6001\n  - RA6002\n"
        z.writestr(f"react/{sl}_playbook.yml", rp)
    z.writestr("README.txt", "dettect/groups_all_attack.yaml – group-administration com todos os grupos ATT&CK (técnicas + software). Uso: python dettect.py g -g groups_all_attack.yaml -p all\n"
               "dettect/*_data_sources.yaml – templates data-source-administration por grupo prioritário (preencher produtos e data_quality).\n"
               "navigator/*_coverage.json – camadas ATT&CK Navigator (3=regra no catálogo, 2=parcial, 1=lacuna).\n"
               "react/*_playbook.yml – playbooks RE&CT (formato RP) com ações por estágio (seleção heurística).\n")
print("outputs ok")

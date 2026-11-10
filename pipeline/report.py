"""Relatório Markdown do APT Threat Map (resumo executivo + achados de TI + engenharia de detecção)."""
import json, collections, datetime, os, zipfile, glob
KB = json.load(open("/tmp/build/kb.json")); OUT = "/mnt/session/outputs"
E, TK, TOOLS, RULES, D3, RA, ASR, SRC = KB["E"], KB["TK"], KB["TOOLS"], KB["RULES"], KB["D3"], KB["RA"], KB["ASR"], KB["SRC"]
CT = KB["COUNTRIES"]; cs = KB["CONVSTATS"]
cn = lambda i: CT.get(i, {}).get("n", i)
def rules_of(t):
    r = TK[t]["r"]
    if not r and "." in t and t.split(".")[0] in TK: r = TK[t.split(".")[0]]["r"]
    return r
def cov(t):
    if rules_of(t): return "●"
    if TK[t]["asr"] or any(D3[x[0]][1] == "Detect" for x in TK[t]["d3"]): return "◐"
    return "○"
PRE = lambda t: all(x in ("reconnaissance", "resource-development") for x in TK[t]["ta"])
used = [t for t in TK if TK[t]["ng"] > 0]
c = collections.Counter(cov(t) for t in used)
md = [f"# APT Threat Map – relatório de inteligência e engenharia de detecção",
      f"_Gerado em {datetime.date.today():%d/%m/%Y}. Artefato principal: `APT_Threat_Map.html` (offline, único arquivo)._\n",
      "## 1. Resumo executivo",
      f"- **{len(E):,} grupos/entidades**".replace(",", ".") + f" consolidados de **{len(SRC)} fontes** (MITRE ATT&CK, ThaiCERT/ETDA, MISP, Malpedia, **APTmap**, **Google Cloud/Mandiant**, **Wikipedia**, BRANDEFENSE, EternalLiberty, Microsoft/CrowdStrike, SigmaHQ, APTMalware e as planilhas fornecidas).",
      f"- {sum(1 for e in E if e['t'])} grupos com TTPs ATT&CK documentadas; {sum(1 for e in E if len(e['s']) >= 3)} corroborados por ≥3 fontes; {sum(1 for e in E if e['iso'])} com origem geolocalizada; " + f"{len(TOOLS):,}".replace(",", ".") + f" ferramentas/malware ({sum(1 for t in TOOLS if t['s'])} casadas a software ATT&CK).",
      f"- {len(used)} técnicas usadas por grupos → cobertura do catálogo: **● {c['●']} com regra** (inclui sub-técnicas cobertas por regra da técnica-pai), ◐ {c['◐']} parcial (ASR/D3FEND-Detect), ○ {c['○']} lacunas.",
      f"- {len(RULES)} regras Sigma convertidas para 8 linguagens (Splunk, Elastic Lucene/EQL/ES|QL, OpenSearch, QRadar AQL, Stellar Cyber, Defender XDR KQL).",
      f"- Traçagem completa por técnica: Defender (tabelas + {len(ASR)} regras ASR) → {len(D3)} contramedidas D3FEND → data components DeTT&CT → {len(RA)} ações RE&CT.\n",
      "## 2. Cadeia de traçagem implementada",
      "```mermaid\nflowchart LR\n  G[Grupo APT<br/>origem · vitimologia · setores] --> A[Artefato / ferramenta<br/>software ATT&CK · APTmap · planilha]\n  G --> T\n  A --> T[Técnica ATT&CK<br/>procedimento do grupo]\n  T --> M[Microsoft Defender<br/>tabelas AH · ASR · KQL]\n  T --> D[MITRE D3FEND<br/>contramedida ↔ artefato digital]\n  T --> X[DeTT&CT<br/>data components · YAML]\n  T --> R[RE&CT<br/>ações por estágio · playbook]\n  T --> S[Detecções<br/>Sigma→SPL/Lucene/EQL/ES|QL/AQL/Stellar/KQL]\n```",
      "Cada elo é navegável no HTML (aba **Traçagem**: clique numa técnica, ferramenta ou contramedida para destacar o caminho) e exportável (Navigator, DeTT&CT, RE&CT, Sigma, consultas por SIEM, CSV).\n",
      "## 3. Lógica de Threat Intelligence aplicada",
      "| Elemento | Lógica |", "|---|---|",
      "| Deduplicação | aliases normalizados (sem pontuação/sufixos group/team/gang/crew), ID MITRE com precedência, sem fusão transitiva; APTmap só por nome principal/ID |",
      "| Confiança do registro | corroboração (nº de fontes independentes) + presença no ATT&CK + confiança de atribuição do APTmap |",
      "| Similaridade | cosseno TF-IDF sobre técnicas ∪ ferramentas (≥0,22) → sobreposição de tradecraft/duplicidade de nomenclatura (não é atribuição) |",
      "| Relações declaradas | MISP/APTmap (similar, overlaps, related-to, subgroup…) com linguagem estimativa (likely/very-likely) |",
      "| Relevância (TID) | W = (w_setor·[setor] + w_país·[país]) × (0,5 + 0,5·min(1,fontes/8) + 0,15·[ATT&CK]); P(t) = Σ W normalizado 0–100 |",
      "| Lacunas | técnicas priorizadas sem regra, separando pré-ataque (recon/recursos → monitoramento externo) |\n",
      "## 4. Panorama global"]
oc = collections.Counter(e["iso"] for e in E if e["iso"]); vc = collections.Counter(v for e in E for v in e["v"]); sc = collections.Counter(s for e in E for s in e["sec"])
md += ["| Origem (atribuição) | Grupos | | País mais visado | Grupos | | Setor mais visado | Grupos |", "|---|---|---|---|---|---|---|---|"]
for (a, b), (c1, d), (s1, s2) in zip(oc.most_common(12), vc.most_common(12), sc.most_common(12)):
    md.append(f"| {cn(a)} | {b} | | {cn(c1)} | {d} | | {s1} | {s2} |")
md += ["\n### Técnicas mais usadas (todos os grupos) e cobertura", "| Técnica | Nome | Grupos | Cobertura | Regras | ASR | D3FEND |", "|---|---|---|---|---|---|---|"]
for t in sorted(used, key=lambda x: -TK[x]["ng"])[:25]:
    k = TK[t]; md.append(f"| {t} | {k['n']} | {k['ng']} | {cov(t)} | {len(rules_of(t))} | {len(k['asr'])} | {len({x[0] for x in k['d3']})} |")
md += ["\n### Backlog de engenharia de detecção (lacunas com mais grupos, excluindo pré-ataque)", "| Técnica | Nome | Grupos | Data components necessários | Defender (tabelas) |", "|---|---|---|---|---|"]
for t in sorted([t for t in used if cov(t) == "○" and not PRE(t)], key=lambda x: -TK[x]["ng"])[:20]:
    k = TK[t]; md.append(f"| {t} | {k['n']} | {k['ng']} | {', '.join(k['dc'][:4]) or '—'} | {', '.join(k['mde'][:3]) or '—'} |")
# alavancagem
pairs = [(t, e) for e in E for t in e["t"] if t in TK]
d3w = collections.Counter(); asrw = collections.Counter(); dcw = collections.Counter()
for t, e in pairs:
    for d in {x[0] for x in TK[t]["d3"]}: d3w[d] += 1
    for a in TK[t]["asr"]: asrw[a] += 1
    for d in TK[t]["dc"]: dcw[d] += 1
md += ["\n### Onde investir (peso = nº de pares grupo×técnica cobertos)", "| D3FEND (contramedida) | Tática | Peso | | ASR (Defender) | Peso | | Data component (DeTT&CT) | Peso |", "|---|---|---|---|---|---|---|---|---|"]
for (d, w1), (a, w2), (dc, w3) in zip(d3w.most_common(12), asrw.most_common(12) + [(None, "")] * 12, dcw.most_common(12)):
    md.append(f"| {D3[d][0]} ({d}) | {D3[d][1]} | {w1} | | {ASR[a][1] if a is not None else ''} | {w2} | | {dc} | {w3} |")
# Brasil
br = sorted([e for e in E if "BR" in e["v"]], key=lambda e: (-len(e["s"]), -len(e["t"])))
md += [f"\n## 5. Perfil de ameaça – Brasil ({len(br)} grupos com o Brasil na vitimologia)", "| Grupo | Origem | ATT&CK | Motivação | Fontes | Técnicas |", "|---|---|---|---|---|---|"]
for e in br[:20]: md.append(f"| {e['n']} | {cn(e['iso']) or e['c']} | {e['m']} | {', '.join(e['mo'])} | {len(e['s'])} | {len(e['t'])} |")
tb = collections.Counter(t for e in br for t in e["t"])
md += ["\nTécnicas mais frequentes entre os grupos que visam o Brasil:", "| Técnica | Nome | Grupos | Cobertura |", "|---|---|---|---|"]
for t, n in tb.most_common(15): md.append(f"| {t} | {TK[t]['n'] if t in TK else ''} | {n} | {cov(t) if t in TK else ''} |")
# similaridade
simp = sorted({tuple(sorted((i, j))) + (s,) for i, e in enumerate(E) for j, s in e["sim"]}, key=lambda x: -x[2])[:15]
md += ["\n## 6. Possíveis sobreposições (similaridade TTP+ferramentas)", "| Grupo A | Grupo B | Similaridade |", "|---|---|---|"]
md += [f"| {E[a]['n']} | {E[b]['n']} | {s} |" for a, b, s in simp]
md += ["\n## 7. Matriz de conversão de regras (pySigma)", "| Formato | OK | Fallback | Não suportado | Observação |", "|---|---|---|---|---|"]
OBS = dict(splunk="sysmon + splunk_windows", elastic="Lucene + ecs_windows", eql="EQL + ecs_windows", esql="ES|QL (sem keywords livres)", opensearch="Lucene + ecs_windows",
           qradar="AQL fields; fallback = busca em payload", stellar="Lucene/DSL campos nativos (mapear p/ Interflow)", defender="KQL XDR (Device*/Identity*)")
for f, v in cs.items(): md.append(f"| {f} | {v['ok']} | {v['fb']} | {v['err']} | {OBS[f]} |")
md += ["\n## 8. Detecções dedicadas (grupos prioritários)"]
for m, d in KB["DET"].items():
    md += [f"- **{d['title']}** ({m}) – regras: " + "; ".join(RULES[r]["t"] for r in d["rules"] if r in RULES) + f". Gaps: {d['gaps']}"]
md += ["\n## 9. Arquivos entregues",
       "| Arquivo | Conteúdo |", "|---|---|",
       "| `APT_Threat_Map.html` | Mapa 2D (coroplético origem/alvo, fluxos, painel por país), grafo de relacionamentos com filtros por tipo de relação e ego-rede, traçagem completa, priorização TID, catálogo de detecções em 9 formatos, matriz ATT&CK×cobertura, dossiês, fontes/metodologia |",
       "| `APT_groups_consolidated.csv` | Grupos normalizados (origem ISO, motivação, setores canônicos, vítimas ISO, fontes, técnicas, ferramentas, similares, relações) |",
       "| `technique_defense_matrix.csv` | Por técnica: cobertura, regras, formatos convertidos, Defender (tabelas/ASR+GUID), D3FEND, mitigações, data components, RE&CT |",
       "| `group_trace_chain.csv` | Traçagem grupo → ferramenta → técnica → procedimento → defesas (todos os grupos com TTPs) |",
       "| `detections_multiformat.zip` | 866 regras × {sigma, splunk, elastic, eql, esql, opensearch, qradar, stellar, defender} + index.csv |",
       "| `dettect_navigator_react.zip` | DeTT&CT group-administration (todos os grupos ATT&CK), data sources por grupo prioritário, camadas Navigator de cobertura, playbooks RE&CT |",
       "| `IR_tools_catalog.csv` | Catálogo de ferramentas de IR/análise (planilha) |",
       "| `build_scripts.zip` | Pipeline reprodutível (extração, enriquecimento, conversão multi-backend, build) |",
       "\n## 10. Fontes e limitações", "| Fonte | Uso |", "|---|---|"]
SOURCES = json.load(open("/tmp/build/sources.json"))
md += [f"| [{s['n']}]({s['u']}) | {s['used']} |" for s in SOURCES]
md += ["\n**Limitações:** atribuição contestável e aliases conflitantes entre fontes (fusões frouxas possíveis); vitimologia reflete viés de reporte; mapeamentos Defender/ASR e RE&CT são curados/heurísticos; D3FEND não cobre técnicas pré-ataque e várias recentes; conversões exigem ajuste de campos/índices (Stellar Cyber sem backend oficial; QRadar fallback por payload; Defender XDR sem Script Block/Security/cloud); Hudson Rock, Radware, Nuix e o artigo do Medium (bloqueado) foram apenas referenciados. Nenhuma amostra de malware foi baixada ou executada."]
open(f"{OUT}/APT_Threat_Map_Report.md", "w").write("\n".join(md))
print("report ok", len(md))

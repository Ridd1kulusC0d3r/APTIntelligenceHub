# Pipeline – APT Threat Map

Ordem de execução (Python 3.11):
1. `extract2.py` – consolida grupos (planilhas, MITRE STIX, ThaiCERT, MISP, EternalLiberty, Microsoft, BRANDEFENSE, SigmaHQ TA, APTmap, Google Cloud, Wikipedia, Malpedia, APTMalware) → `data2.json`
2. `fetch_d3f.py` – baixa mapeamentos D3FEND por técnica (API oficial) → `/tmp/ext/d3f/*.json`
3. `sigma_select.py` – seleciona até 3 regras SigmaHQ por técnica (+ regras do hub em `detections.py`) → `rules_index.json`
4. `convert_worker.py <env>` – conversão pySigma em 3 ambientes isolados (conflito de dependências):
   - `sys`    : pysigma 2.x + pysigma-backend-splunk 3.0 + pipelines sysmon/windows → Splunk
   - `kusto`  : venv com pysigma 1.5.1 + backend-kusto 1.0.1 + backend-elasticsearch 2.1.1 + backend-opensearch 2.0.3 → Defender XDR, Elastic (Lucene/EQL/ES|QL), OpenSearch, Stellar (Lucene nativo)
   - `qradar` : venv com pysigma 0.11.23 + pysigma-backend-qradar-aql 0.3.2 + pyparsing<3.1 → QRadar AQL
5. `centroids.py` – centróides de países (world-atlas 50m)
6. `enrich.py` – normalização TI (setores, vitimologia ISO, motivação), ferramentas unificadas, similaridade TF-IDF, D3FEND, RE&CT (facetas), Defender (tabelas/ASR), regras multi-formato → `kb.json`
7. `build_map.py` – gera `APT_Threat_Map.html` (template em `tpl/`, D3 v7 + topojson embutidos, KB gzip+base64) e CSV/ZIPs
8. `report.py` – relatório Markdown
9. `pw_test*.py` – validação Playwright (erros JS, screenshots, downloads)

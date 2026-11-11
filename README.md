# 🛰️ APT Intelligence Hub — APT Threat Map

**CTI → Detecção → Defesa → Resposta.** Mapa 2D interativo de grupos APT com grafo de relacionamentos, traçagem
**grupo → artefato/ferramenta → técnica MITRE ATT&CK → Microsoft Defender → MITRE D3FEND → DeTT&CT → RE&CT**
e detecções em **Sigma, Splunk, Elastic (Lucene/EQL/ES|QL), OpenSearch, QRadar, Stellar Cyber e Defender XDR**.

🔗 **Demo (GitHub Pages):** https://ridd1kulusc0d3r.github.io/APTIntelligenceHub/  
📄 Relatório: [`docs/REPORT.md`](docs/REPORT.md)

[![QA e deploy](https://github.com/Ridd1kulusC0d3r/APTIntelligenceHub/actions/workflows/pages.yml/badge.svg)](https://github.com/Ridd1kulusC0d3r/APTIntelligenceHub/actions/workflows/pages.yml)
![Licença MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-b43c0e)

| Métrica | Valor |
|---|---|
| Grupos/entidades consolidados | 1.451 (14 fontes) |
| Grupos com TTPs ATT&CK | 174 |
| Ferramentas/malware | 2.445 (695 casadas a software ATT&CK) |
| Regras Sigma × formatos | 866 × 9 |
| Contramedidas D3FEND / ações RE&CT / regras ASR | 146 / 216 / 19 |

## Demonstração
Gravações reais da aplicação (tema escuro) — vídeos MP4 em [`assets/media/`](assets/media/).

🎬 **Tour completo (≈56 s):** [`assets/media/apt-threat-map-tour.mp4`](assets/media/apt-threat-map-tour.mp4)

| 🗺️ Mapa 2D — “Ameaças ao Brasil” | 🕸️ Grafo de relacionamentos |
|---|---|
| ![Mapa 2D](assets/media/map.gif) | ![Grafo](assets/media/graph.gif) |
| **🔗 Traçagem grupo → defesa** | **🛡️ Detecções e 🧩 cobertura ATT&CK** |
| ![Traçagem](assets/media/trace.gif) | ![Detecções](assets/media/detect.gif) |

**🌗 Tema claro/escuro** (identidade visual LLMInjection): ![Tema](assets/media/theme.gif)

Para regravar: `npm run demo` (Playwright + ffmpeg).

## Funcionalidades
- **🗺️ Mapa 2D** – coroplético origem/alvo, fluxos origem→alvo, painel por país (quem ataca, TTPs, cobertura), atalho “Ameaças ao Brasil”.
- **🕸️ Relacionamentos** – grafo (grupo, país, setor, ferramenta, técnica) com 8 tipos de relação filtráveis, ego-rede N saltos, similaridade TTP.
- **🔗 Traçagem** – seletor de grupos (lista por origem + filtro + ◀ ▶), cadeia clicável até Defender/D3FEND/DeTT&CT/RE&CT.
- **🎯 Priorização (Threat-Informed Defense)** – perfil setor+país → técnicas priorizadas, lacunas, telemetria, D3FEND, ASR.
- **🛡️ Detecções multi-SIEM**, **🧩 ATT&CK × cobertura**, **📋 dossiês**, **📚 fontes & metodologia**.
- **Exportações**: ATT&CK Navigator, DeTT&CT (group/data-source/technique), playbook RE&CT, Sigma, consultas por SIEM, CSV.

## Estrutura
```
index.html            # aplicação completa (offline, ~3,4 MB, dados gzip embutidos) — GERADO, não edite à mão
src/                  # fontes da página: head.html, body.html, theme.css, js/ (7 módulos), vendor/, data/ (payload)
tools/build.py        # monta index.html a partir de src/ (só biblioteca padrão)
tools/qa.sh           # QA completo: build, testes estáticos e E2E
tests/                # test_repo.py (dados, catálogos, segurança, contraste) e e2e.test.js (Playwright)
data/                 # CSVs: grupos, matriz técnica→defesa, cadeia de traçagem, ferramentas IR
detections/           # sigma/ splunk/ elastic/ eql/ esql/ opensearch/ qradar/ stellar/ defender/ + index.csv
defense/              # dettect/ navigator/ react/
docs/REPORT.md        # relatório de TI e engenharia de detecção
pipeline/             # coleta e enriquecimento dos dados (3 ambientes pySigma) + gravação das demos
assets/               # GIFs e vídeos de demonstração, imagem de compartilhamento
```

## Uso local
Abra `index.html` no navegador (Chrome/Edge ≥80, Firefox ≥113, Safari ≥16.4). Não há dependências externas em tempo de execução, e nenhum dado sai do seu navegador.

## Desenvolvimento
A interface vive em `src/`. Depois de editar, regenere e valide:

```bash
python3 tools/build.py      # regenera index.html
bash tools/qa.sh            # build em sincronia + 17 testes estáticos + 14 testes E2E
```

O E2E usa Playwright (`npm install && npx playwright install chromium`); `bash tools/qa.sh --fast` roda sem navegador.
O CI executa o mesmo roteiro a cada push e **só publica no GitHub Pages se o QA passar**.

| O QA cobre | Como |
|---|---|
| Página íntegra | `index.html` idêntico ao montado de `src/`, sem recursos externos, JS sem erro de sintaxe |
| Base de dados | referências cruzadas válidas, CSVs e README batendo com a base, sem URLs perigosas |
| Catálogos | 866 regras Sigma em YAML válido, arquivos por formato batendo com o índice, camadas Navigator, YAMLs DeTT&CT/RE&CT |
| Funcionalidade | 8 abas, filtros e presets, mapa, grafo, traçagem, priorização, modal, dossiê, link direto |
| Exportações | 19 arquivos baixados e validados (JSON, YAML, CSV, PNG) |
| Segurança | conteúdo de regras escapado (inclui regra com `<script>` literal), links de dados só http(s), `rel=noopener` |
| Acessibilidade e mobile | rótulos e nomes acessíveis, contraste WCAG AA dos dois temas, sem rolagem horizontal em 390 px, tecla Esc |

## Atualizar os dados
Veja [`pipeline/README.md`](pipeline/README.md). Os backends pySigma têm dependências conflitantes → 3 venvs
(`requirements-sys.txt`, `requirements-kusto-elastic.txt`, `requirements-qradar.txt`). O pipeline grava o payload em
`src/data/` e chama o mesmo `tools/build.py`.

## Ressalvas
Atribuição é contestável e aliases divergem entre fontes. Os mapeamentos ASR→ATT&CK e RE&CT são heurísticos ou curados. Stellar Cyber não tem backend pySigma oficial: a saída é Lucene/DSL com campos nativos, a mapear para o Interflow. Valide as consultas em homologação. Nenhuma amostra de malware foi baixada, executada ou distribuída. Ver [`NOTICE.md`](NOTICE.md).

## Contribuir e reportar
Mudanças: veja [`CONTRIBUTING.md`](CONTRIBUTING.md) e o [`CHANGELOG.md`](CHANGELOG.md). Problemas de segurança: [`SECURITY.md`](SECURITY.md).

## Licença
Código sob [MIT](LICENSE). Os dados derivados mantêm as licenças das fontes — ver [`NOTICE.md`](NOTICE.md).

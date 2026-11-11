# Changelog

## 1.0.0 — 2026-11-11
Primeira versão pronta para publicação.

### Estrutura
- Fontes da página separadas em `src/` (HTML, CSS, 7 módulos JS, bibliotecas, payload de dados); `index.html` passa a ser gerado por `tools/build.py`.
- Pipeline de dados com diretórios configuráveis por variável de ambiente (`pipeline/paths.py`) e usando o mesmo montador.
- `publish.sh` removido: o deploy é feito pelo GitHub Actions a cada push na `main`.

### Interface
- Identidade visual LLMInjection, com tema claro e escuro.
- Uso em celular: filtros compactos sem barra fixa, tabelas com rolagem própria, KPIs em três colunas.
- Legenda do grafo com as mesmas cores do desenho; rótulos de KPI sem corte.
- GIFs, vídeos de demonstração e imagem de compartilhamento (Open Graph).

### Segurança e acessibilidade
- Links vindos dos dados aceitam apenas `http(s)` (`safeUrl`); todo link externo abre com `rel="noopener noreferrer"`.
- Rótulos acessíveis em todos os campos, link "pular para o conteúdo", papéis de diálogo no dossiê e no modal, aviso sem JavaScript.

### Qualidade
- 17 testes estáticos e 14 testes E2E (`bash tools/qa.sh`), executados no CI como pré-requisito do deploy.

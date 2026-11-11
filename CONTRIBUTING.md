# Contribuir

1. Edite os fontes em `src/` (nunca o `index.html`, que é gerado).
2. Regenere a página: `python3 tools/build.py`.
3. Rode o QA: `bash tools/qa.sh` (ou `--fast`, sem navegador). O CI roda o mesmo roteiro e bloqueia o deploy se falhar.
4. Descreva a mudança no `CHANGELOG.md`.

## Convenções
- **Dados de terceiros são não confiáveis.** Todo texto vindo da base passa por `esc()`; todo `href` vindo da base passa por `safeUrl()`.
- **Sem dependências em tempo de execução.** Bibliotecas ficam em `src/vendor/` e são embutidas no HTML.
- **Cores só por tokens** de `src/theme.css`; novos pares texto/fundo precisam de contraste WCAG AA nos dois temas (há teste).
- **Novas fontes de dados** entram pelo `pipeline/` e devem ser listadas em `NOTICE.md` com a licença.
- Não versione amostras de malware, binários ou segredos.

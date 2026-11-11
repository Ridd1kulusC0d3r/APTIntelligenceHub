#!/usr/bin/env bash
# QA completo: build em sincronia, testes estáticos (dados, catálogos, segurança, contraste)
# e E2E no navegador. É o mesmo roteiro que o CI executa antes de publicar.
#   bash tools/qa.sh            # tudo
#   bash tools/qa.sh --fast     # pula o E2E (sem navegador)
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1/4 build em sincronia com src/"
python3 tools/build.py --check

echo "== 2/4 testes estáticos"
python3 -m unittest discover -s tests -p 'test_*.py'

if [[ "${1:-}" == "--fast" ]]; then echo "E2E pulado (--fast)"; exit 0; fi

echo "== 3/4 E2E (Playwright)"
# Usa o Playwright do projeto (npm install) ou, na falta, um global.
if [[ ! -d node_modules/playwright ]]; then export NODE_PATH="${NODE_PATH:-$(npm root -g)}"; fi
node --test tests/e2e.test.js

echo "== 4/4 validação dos arquivos exportados pelo E2E"
python3 -m unittest tests.test_repo.Exportacoes
echo "QA ok"

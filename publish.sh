#!/usr/bin/env bash
# Publica no GitHub: bash publish.sh   (requer git + acesso ao repositório)
set -e
git init -b main 2>/dev/null || true
git add -A
git commit -m "APT Threat Map: mapa 2D, grafo, traçagem ATT&CK→Defender→D3FEND→DeTT&CT→RE&CT, detecções multi-SIEM" || true
git remote remove origin 2>/dev/null || true
git remote add origin https://github.com/Ridd1kulusC0d3r/APTIntelligenceHub.git
git push -u origin main
echo "Ative Settings → Pages → Source: GitHub Actions. URL: https://ridd1kulusc0d3r.github.io/APTIntelligenceHub/"

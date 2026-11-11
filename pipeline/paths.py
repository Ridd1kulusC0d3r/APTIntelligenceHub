"""Diretórios de trabalho do pipeline, configuráveis por variável de ambiente.

    APT_RAW    insumos baixados manualmente (planilha, STIX…)      padrão: /tmp
    APT_EXT    repositórios/datasets de terceiros descompactados   padrão: /tmp/ext
    APT_BUILD  artefatos intermediários (data2.json, kb.json…)     padrão: /tmp/build
    APT_OUT    saídas finais (CSV, relatório, HTML)                padrão: /mnt/session/outputs

Os padrões são os caminhos históricos do projeto: sem variáveis definidas, nada muda.
"""
import os
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RAW = os.environ.get("APT_RAW", "/tmp")
EXT = os.environ.get("APT_EXT", "/tmp/ext")
BUILD = os.environ.get("APT_BUILD", "/tmp/build")
OUT = os.environ.get("APT_OUT", "/mnt/session/outputs")

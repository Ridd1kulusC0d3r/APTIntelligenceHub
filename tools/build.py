#!/usr/bin/env python3
"""Monta o index.html (arquivo único, offline) a partir de src/.

Uso:
    python3 tools/build.py            # escreve index.html
    python3 tools/build.py --check    # falha (exit 1) se index.html estiver desatualizado
    python3 tools/build.py -o saida.html

Só usa a biblioteca padrão. Não toca nos dados: o payload da base (src/data/) é
produzido pelo pipeline completo (pipeline/build_map.py); aqui apenas se junta
HTML + CSS + JS + bibliotecas + payload na mesma ordem em que o app espera.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# Ordem importa: 00-theme liga o botão de tema; 01-core define estado/boot usados pelos demais.
JS_MODULES = [
    "00-theme.js",
    "01-core.js",
    "02-map.js",
    "03-graph.js",
    "04-trace.js",
    "05-rules-exports.js",
    "06-views.js",
]
VENDOR = ["d3.min.js", "topojson-client.min.js"]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def validate_payload(b64: str) -> dict:
    """Garante que o payload decodifica e tem as chaves que o app usa no boot."""
    kb = json.loads(gzip.decompress(base64.b64decode(b64)))
    missing = [k for k in ("E", "TK", "TOOLS", "RULES", "D3", "RA", "ASR") if k not in kb]
    if missing:
        raise SystemExit(f"payload da base incompleto, faltam chaves: {missing}")
    return kb


def build() -> str:
    meta = json.loads(read(SRC / "data" / "meta.json"))
    b64 = read(SRC / "data" / "kb.json.gz.b64").strip()
    validate_payload(b64)

    head = read(SRC / "head.html")
    if "{{CSS}}" not in head:
        raise SystemExit("src/head.html sem o marcador {{CSS}}")
    head = head.replace("{{CSS}}", read(SRC / "theme.css"))

    body = read(SRC / "body.html")
    for key, value in (("{{KB_MB}}", meta["kb_mb"]), ("{{GEN}}", meta["generated"])):
        if key not in body:
            raise SystemExit(f"src/body.html sem o marcador {key}")
        body = body.replace(key, value)

    vendor = "".join(f"<script>{read(SRC / 'vendor' / name)}</script>\n" for name in VENDOR)
    static = read(SRC / "data" / "static.js")
    app = "\n".join(read(SRC / "js" / name) for name in JS_MODULES)
    for name, chunk in (("static.js", static), ("app", app)):
        if "</script" in chunk.lower():
            raise SystemExit(f"{name} contém '</script' literal, o que quebraria a página")

    return (
        head
        + body
        + vendor
        + f'<script id="kb" type="text/plain">{b64}</script>\n'
        + f"<script>\n{static}\n{app}\n</script>\n</body></html>\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default=str(ROOT / "index.html"))
    ap.add_argument("--check", action="store_true", help="não escreve; falha se a saída diferir do arquivo existente")
    args = ap.parse_args()

    html = build()
    out = Path(args.output)
    if args.check:
        if not out.exists() or read(out) != html:
            print(f"DESATUALIZADO: {out} difere de src/. Rode: python3 tools/build.py", file=sys.stderr)
            return 1
        print(f"ok: {out} está em sincronia com src/ ({len(html.encode()) / 1e6:.2f} MB)")
        return 0
    out.write_text(html, encoding="utf-8")
    print(f"escrito {out} ({len(html.encode()) / 1e6:.2f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

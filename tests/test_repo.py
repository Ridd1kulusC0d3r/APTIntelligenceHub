"""QA estático do repositório: build reproduzível, integridade da base, catálogos e exportações.

Uso: python3 -m unittest discover -s tests -v
Só biblioteca padrão; PyYAML é opcional (testes de YAML são pulados sem ele).
"""
from __future__ import annotations

import base64
import csv
import gzip
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import build  # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

FORMATS = ["sigma", "splunk", "elastic", "eql", "esql", "opensearch", "qradar", "stellar", "defender"]


def load_kb() -> dict:
    return json.loads(gzip.decompress(base64.b64decode((ROOT / "src/data/kb.json.gz.b64").read_text())))


def read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def luminance(hex_color: str) -> float:
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5))
    lin = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4  # noqa: E731
    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


class Build(unittest.TestCase):
    def test_index_em_sincronia_com_src(self):
        self.assertEqual((ROOT / "index.html").read_text(encoding="utf-8"), build.build(),
                         "index.html desatualizado: rode python3 tools/build.py")

    def test_pagina_e_autocontida(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        head = html[: html.index("<body")]
        externos = re.findall(r'<script[^>]+src="https?://[^"]+|<link[^>]+rel="?stylesheet[^>]+href="https?://[^"]+', html[: html.index('<script id="kb"')])
        self.assertEqual(externos, [], "a página não pode depender de recursos externos em runtime")
        self.assertEqual(re.findall(r"\{\{[A-Z_]+\}\}", head + html[html.index("<body"): html.index("<script>", html.index("<body"))]), [],
                         "marcador de template não substituído")
        self.assertLess(len(html.encode()), 6_000_000)

    def test_js_sem_erros_de_sintaxe(self):
        for js in sorted((ROOT / "src/js").glob("*.js")):
            r = subprocess.run(["node", "--check", str(js)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{js.name}: {r.stderr}")

    def test_links_de_dados_passam_por_safeurl(self):
        for js in (ROOT / "src/js").glob("*.js"):
            src = js.read_text(encoding="utf-8")
            sem_safeurl = re.findall(r'href="\$\{esc\((?!safeUrl)[^}]*\}', src)
            self.assertEqual(sem_safeurl, [], f"{js.name}: href de dados sem safeUrl()")
            sem_rel = len(re.findall(r'target=(?:"_blank"|_blank\b)(?! rel="noopener noreferrer")', src))
            self.assertEqual(sem_rel, 0, f"{js.name}: {sem_rel} link(s) target=_blank sem rel=noopener noreferrer")


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = load_kb()

    def test_estrutura_e_referencias(self):
        kb = self.kb
        E, TK, TOOLS = kb["E"], kb["TK"], kb["TOOLS"]
        self.assertGreater(len(E), 1000)
        for e in E:
            self.assertTrue(e["n"].strip(), "grupo sem nome")
            for k in e["tl"]:
                self.assertTrue(0 <= k < len(TOOLS), f"{e['n']}: índice de ferramenta inválido")
            for s in e["s"]:
                self.assertTrue(0 <= s < len(kb["SRC"]), f"{e['n']}: índice de fonte inválido")
            if e.get("iso"):
                self.assertRegex(e["iso"], r"^[A-Z]{2}$")
        for t in TK:
            self.assertRegex(t, r"^T\d{4}(\.\d{3})?$")
        for rule_id in {r for t in TK.values() for r in t["r"]}:
            self.assertIn(rule_id, kb["RULES"], "técnica aponta para regra inexistente")

    def test_sem_urls_perigosas(self):
        bad = []

        def walk(o):
            if isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
            elif isinstance(o, str) and re.match(r"^\s*(javascript|data|vbscript|file):", o, re.I):
                bad.append(o[:80])

        walk({k: v for k, v in self.kb.items() if k != "RULES"})
        self.assertEqual(bad, [])

    def test_csvs_batem_com_a_base(self):
        self.assertEqual(len(read_csv(ROOT / "data/APT_groups_consolidated.csv")), len(self.kb["E"]))
        self.assertEqual(len(read_csv(ROOT / "data/technique_defense_matrix.csv")), len(self.kb["TK"]))
        for name in ("group_trace_chain.csv", "IR_tools_catalog.csv"):
            self.assertGreater(len(read_csv(ROOT / "data" / name)), 100, name)

    def test_readme_cita_os_numeros_reais(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        fmt = lambda n: f"{n:,}".replace(",", ".")  # noqa: E731
        for label, n in (("grupos", len(self.kb["E"])), ("ferramentas", len(self.kb["TOOLS"])), ("regras", len(self.kb["RULES"]))):
            self.assertIn(fmt(n), readme, f"README sem o total de {label} ({fmt(n)})")


class Deteccoes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = read_csv(ROOT / "detections/index.csv")
        cls.kb = load_kb()

    def test_indice_cobre_todas_as_regras(self):
        self.assertEqual({r["rule_id"] for r in self.index}, set(self.kb["RULES"]))

    def test_arquivos_por_formato_batem_com_o_indice(self):
        for fmt in FORMATS:
            ok = sum(1 for r in self.index if r[fmt] == "ok" or r[fmt].startswith("ok"))
            files = [p for p in (ROOT / "detections" / fmt).iterdir() if p.is_file()]
            self.assertTrue(all(p.stat().st_size > 0 for p in files), f"{fmt}: arquivo vazio")
            self.assertGreaterEqual(len(files), ok, f"{fmt}: {len(files)} arquivos < {ok} conversões ok no índice")

    @unittest.skipUnless(yaml, "PyYAML não instalado")
    def test_regras_sigma_sao_yaml_valido(self):
        files = sorted((ROOT / "detections/sigma").glob("*.yml"))
        self.assertEqual(len(files), len(self.kb["RULES"]))
        for p in files:
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
            for key in ("title", "logsource", "detection"):
                self.assertIn(key, doc, f"{p.name}: sem '{key}'")


class Defesa(unittest.TestCase):
    def test_camadas_navigator(self):
        files = sorted((ROOT / "defense/navigator").glob("*.json"))
        self.assertGreater(len(files), 5)
        for p in files:
            layer = json.loads(p.read_text(encoding="utf-8"))
            self.assertIn("techniques", layer, p.name)
            self.assertTrue(layer["techniques"], p.name)

    @unittest.skipUnless(yaml, "PyYAML não instalado")
    def test_yaml_dettect_e_react(self):
        files = [*(ROOT / "defense/dettect").glob("*.y*ml"), *(ROOT / "defense/react").glob("*.y*ml")]
        self.assertGreater(len(files), 10)
        for p in files:
            self.assertTrue(yaml.safe_load(p.read_text(encoding="utf-8")), p.name)


class Publicacao(unittest.TestCase):
    def test_links_relativos_do_readme_existem(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for target in re.findall(r"\]\((?!https?://|#|mailto:)([^)\s]+)\)", readme):
            self.assertTrue((ROOT / target.split("#")[0]).exists(), f"README aponta para arquivo inexistente: {target}")

    def test_sem_binarios_ou_segredos_versionados(self):
        tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split("\n")
        banned = [f for f in tracked if re.search(r"\.(exe|dll|bin|zip|7z|pem|key|env)$", f, re.I)]
        self.assertEqual(banned, [])
        pat = re.compile(r"ghp_[A-Za-z0-9]{30,}|github_pat_|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |OPENSSH )?PRIVATE KEY")
        for f in tracked:
            p = ROOT / f
            if f == "tests/test_repo.py":
                continue  # contém os próprios padrões de busca
            if f and p.suffix in {".py", ".js", ".sh", ".yml", ".yaml", ".md", ".json", ".html", ".css", ".txt"} and p.stat().st_size < 400_000:
                self.assertFalse(bool(pat.search(p.read_text(encoding="utf-8", errors="ignore"))), f"possível segredo em {f}")

    def test_contraste_wcag_aa_dos_tokens(self):
        css = (ROOT / "src/theme.css").read_text(encoding="utf-8")
        blocks = {"claro": css[css.index(":root{"): css.index("@media (prefers-color-scheme:dark)")],
                  "escuro": css[css.index(':root[data-theme="dark"]{'): css.index("/* ---------- 2. base")]}
        for theme, block in blocks.items():
            tok = dict(re.findall(r"--([a-z0-9-]+):(#[0-9a-fA-F]{6})\b", block))
            pairs = [("txt", "bg"), ("txt", "panel"), ("txt2", "bg"), ("mut", "bg"), ("mut", "panel"), ("acc", "bg"), ("acc", "panel"),
                     ("acc-ink", "acc"), ("ok", "ok-soft"), ("warn", "warn-soft"), ("bad", "bad-soft"), ("vio", "vio-soft"), ("blue", "blue-soft")]
            for fg, bg in pairs:
                ratio = contrast(tok[fg], tok[bg])
                self.assertGreaterEqual(ratio, 4.5, f"tema {theme}: --{fg} sobre --{bg} = {ratio:.2f}:1 (< 4.5)")


class Exportacoes(unittest.TestCase):
    """Valida os arquivos baixados pelo E2E (tests/.out/downloads). Pulado se o E2E ainda não rodou."""
    DL = ROOT / "tests/.out/downloads"

    def setUp(self):
        if not self.DL.is_dir() or not any(self.DL.iterdir()):
            self.skipTest("rode antes: node --test tests/e2e.test.js")

    def test_formatos_validos(self):
        seen = set()
        for p in sorted(self.DL.iterdir()):
            text = p.read_bytes()
            ext = p.suffix.lower()
            seen.add(ext)
            if ext == ".json":
                self.assertTrue(json.loads(text), p.name)
            elif ext in (".yaml", ".yml") and yaml:
                self.assertTrue(list(yaml.safe_load_all(text.decode("utf-8"))), p.name)
            elif ext == ".csv":
                rows = list(csv.reader(text.decode("utf-8-sig").splitlines()))
                self.assertGreater(len(rows), 1, p.name)
                self.assertTrue(all(len(r) == len(rows[0]) for r in rows), f"{p.name}: colunas inconsistentes")
            elif ext == ".png":
                self.assertEqual(text[:8], b"\x89PNG\r\n\x1a\n", p.name)
        self.assertTrue({".json", ".csv"} <= seen, f"formatos exportados: {sorted(seen)}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

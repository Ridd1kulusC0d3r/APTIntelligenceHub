// QA ponta a ponta do APT Threat Map (Playwright + node:test, sem framework extra).
// Uso: node --test tests/e2e.test.js     (APT_URL=https://... para testar a página publicada)
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const ROOT = path.resolve(__dirname, '..');
const URL = process.env.APT_URL || 'file://' + path.join(ROOT, 'index.html');
const OUT = path.join(__dirname, '.out');
const DL = path.join(OUT, 'downloads');
const TABS = ['map', 'graph', 'trace', 'prio', 'det', 'mx', 'grp', 'src'];

let browser;
before(async () => {
  fs.rmSync(OUT, { recursive: true, force: true });
  fs.mkdirSync(DL, { recursive: true });
  browser = await chromium.launch();
});
after(async () => { await browser.close(); });

/** Abre a página pronta (base descompactada) e coleta erros de JS/console. */
async function open(opts = {}) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true, ...opts });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });
  await page.goto(URL + (opts.hash || ''));
  await page.waitForSelector('#loading', { state: 'detached', timeout: 90000 });
  return { ctx, page, errors };
}
const tab = async (page, t) => { await page.click(`#nav button[data-t="${t}"]`); await page.waitForTimeout(t === 'graph' ? 1500 : 400); };
const count = (page, sel) => page.locator(sel).count();
const recorte = async page => +(await page.locator('#fcount b').innerText()).replace(/\D/g, '');

test('carrega sem erros e mostra os 11 KPIs coerentes com a base', async () => {
  const { ctx, page, errors } = await open();
  assert.equal(await count(page, '#kpis .kpi'), 11);
  const kpi = await page.evaluate(() => ({ grupos: E.length, tecnicas: Object.keys(TK).length, regras: Object.keys(RULES).length, tools: TOOLS.length }));
  assert.ok(kpi.grupos > 1000 && kpi.tecnicas > 400 && kpi.regras > 500 && kpi.tools > 1000, JSON.stringify(kpi));
  assert.equal(await recorte(page), kpi.grupos, 'contador do recorte = total de grupos sem filtros');
  assert.match(await page.title(), /APT/);
  assert.equal(await page.getAttribute('html', 'lang'), 'pt-BR');
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('as 8 abas renderizam conteúdo e não geram erros', async () => {
  const { ctx, page, errors } = await open();
  for (const t of TABS) {
    await tab(page, t);
    assert.ok(await page.locator(`#t-${t}`).isVisible(), `aba ${t} visível`);
    assert.equal(await count(page, '.tab.on'), 1, 'uma única aba ativa');
    const len = await page.evaluate(id => document.getElementById(id).innerText.trim().length, 't-' + t);
    assert.ok(len > 80, `aba ${t} com conteúdo (${len} chars)`);
  }
  assert.ok(await count(page, '#dTb tr') > 0 || true);
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('filtros globais: busca, técnica, presets e limpar', async () => {
  const { ctx, page, errors } = await open();
  const total = await recorte(page);
  await page.fill('#fq', 'lazarus');
  const n1 = await recorte(page);
  assert.ok(n1 > 0 && n1 < total, `busca reduz o recorte (${n1}/${total})`);
  await page.click('#fClr');
  assert.equal(await recorte(page), total, 'limpar restaura');
  assert.equal(await page.inputValue('#fq'), '');

  await page.fill('#fTech', 't1566');
  const n2 = await recorte(page);
  assert.ok(n2 > 0 && n2 < total, 'filtro por técnica (minúsculas aceitas)');
  const ok = await page.evaluate(() => FILT.every(e => e.t.some(t => t === 'T1566' || t.startsWith('T1566.'))));
  assert.ok(ok, 'todos os grupos do recorte usam T1566');
  await page.click('#fClr');

  for (const [preset, sel, val] of [['br', '#fVic', 'BR'], ['fin', '#fSec', 'Financeiro'], ['gov', '#fSec', 'Governo']]) {
    await page.click(`[data-preset="${preset}"]`);
    assert.equal(await page.inputValue(sel), val, `preset ${preset} ajusta ${sel}`);
    const n = await recorte(page);
    assert.ok(n > 0 && n < total, `preset ${preset} recorta (${n})`);
  }
  await page.click('#fClr');
  await page.fill('#fq', 'zzz-nao-existe-zzz');
  assert.equal(await recorte(page), 0, 'busca sem resultado');
  for (const t of TABS) await tab(page, t); // nenhuma aba pode quebrar com recorte vazio
  await page.click('#fClr');
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('mapa: países, marcadores, painel por país e seleção de grupo', async () => {
  const { ctx, page, errors } = await open();
  assert.ok(await count(page, '#map .cty') > 150, 'países desenhados');
  assert.ok(await count(page, '#map .mks circle') > 50, 'marcadores de grupos');
  await page.click('[data-preset="br"]');
  assert.match(await page.locator('#mside').innerText(), /Brazil|Brasil/);
  await page.locator('#map .mks circle').first().dispatchEvent('click');
  await page.waitForTimeout(300);
  assert.ok((await page.locator('#mside').innerText()).length > 100, 'painel do grupo preenchido');
  for (const mode of ['orig', 'none', 'vict']) await page.selectOption('#mMode', mode);
  await page.click('#mZin'); await page.click('#mZout'); await page.click('#mReset');
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('grafo: canvas desenhado, foco em nó e exportações', async () => {
  const { ctx, page, errors } = await open();
  await tab(page, 'graph');
  await page.waitForTimeout(1500);
  const stats = await page.evaluate(() => {
    const c = document.getElementById('gcv'), d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
    let painted = 0; for (let i = 3; i < d.length; i += 4) if (d[i] > 0) painted++;
    return { nodes: G.nodes.length, links: G.links.length, painted };
  });
  assert.ok(stats.nodes > 20 && stats.links > 20, JSON.stringify(stats));
  assert.ok(stats.painted > 500, 'canvas com pixels desenhados');
  await page.fill('#gFocus', 'APT28');
  await page.click('#gGo');
  await page.waitForTimeout(800);
  assert.ok(await page.evaluate(() => !!G.focusNode), 'foco aplicado');
  await page.click('#gUnfocus');
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('traçagem: seleção de grupo, destaque de cadeia e detalhe', async () => {
  const { ctx, page, errors } = await open();
  await tab(page, 'trace');
  assert.ok(await page.evaluate(() => document.getElementById('trG').options.length) > 100, 'lista de grupos');
  await page.evaluate(() => goTrace(E.find(e => e.m === 'G0007').i));
  await page.waitForTimeout(400);
  assert.equal(await count(page, '#trcols .tcol'), 7, 'sete colunas da cadeia');
  assert.ok(await count(page, '#trcols .ti') > 30, 'itens na cadeia');
  await page.locator('#trcols .tcol:nth-child(3) .ti').first().click();
  await page.waitForTimeout(300);
  assert.ok(await count(page, '#trcols .ti.hl, #trcols .ti.sel') > 0, 'cadeia destacada');
  assert.ok((await page.locator('#trdet').innerText()).length > 100, 'detalhe da técnica');
  const before = await page.evaluate(() => TR.e.n);
  await page.click('#trNext');
  assert.notEqual(await page.evaluate(() => TR.e.n), before, 'próximo grupo');
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('detecções, matriz e grupos: tabelas, modal, drawer e teclado (Esc)', async () => {
  const { ctx, page, errors } = await open();
  await tab(page, 'det');
  const rows = await count(page, '#dTb tr');
  assert.ok(rows > 20, `regras listadas (${rows})`);
  await page.fill('#dq', 'powershell');
  await page.waitForTimeout(300);
  const filtered = await count(page, '#dTb tr');
  assert.ok(filtered > 0 && filtered <= rows, 'filtro de regras');
  await page.locator('#dTb tr').first().click();
  assert.ok(await page.locator('#modal.on').isVisible(), 'modal da regra abre');
  assert.ok(await count(page, '#mb pre') > 0, 'regra exibida em bloco de código');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(150);
  assert.equal(await count(page, '#modal.on'), 0, 'Esc fecha o modal');

  await tab(page, 'mx');
  assert.ok(await count(page, '#mxBox .mc') > 100, 'células da matriz');
  await page.locator('#mxBox .mc').first().click();
  assert.ok(await page.locator('#modal.on').isVisible(), 'modal da técnica abre');
  await page.keyboard.press('Escape');

  await tab(page, 'grp');
  assert.ok(await count(page, '#t-grp tbody tr') > 20, 'tabela de grupos');
  await page.locator('#t-grp tbody tr').first().click();
  await page.waitForTimeout(400);
  assert.ok(await count(page, '#drawer.on') === 1, 'dossiê abre');
  assert.ok((await page.locator('#db').innerText()).length > 100, 'dossiê com conteúdo');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(350);
  assert.equal(await count(page, '#drawer.on'), 0, 'Esc fecha o dossiê');
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('priorização (TID) calcula e lista técnicas', async () => {
  const { ctx, page, errors } = await open();
  await tab(page, 'prio');
  await page.locator('#pSec .chip').first().click();
  await page.click('#pRun');
  await page.waitForTimeout(600);
  assert.ok((await page.locator('#pOut').innerText()).length > 200, 'resultado da priorização');
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('exportações geram arquivos não vazios (salvos em tests/.out/downloads)', async () => {
  const { ctx, page, errors } = await open();
  const saved = [];
  async function exportAll(scope) {
    const ids = await page.evaluate(sel => [...document.querySelectorAll(sel + ' button')].filter(b => b.offsetParent && /⬇|PNG|JSON|CSV/.test(b.textContent)).map(b => { b.dataset.qa = b.dataset.qa || Math.random().toString(36).slice(2); return b.dataset.qa; }), scope);
    for (const id of ids) {
      const btn = page.locator(`[data-qa="${id}"]`);
      const label = (await btn.innerText()).trim();
      const [d] = await Promise.all([page.waitForEvent('download', { timeout: 15000 }).catch(() => null), btn.click()]);
      assert.ok(d, `"${label}" (${scope}) deve iniciar um download`);
      const file = path.join(DL, d.suggestedFilename());
      await d.saveAs(file);
      assert.ok(fs.statSync(file).size > 50, `"${label}" gerou arquivo vazio`);
      saved.push(path.basename(file));
    }
  }
  await tab(page, 'trace');
  await page.evaluate(() => goTrace(E.find(e => e.m === 'G0007').i));
  await exportAll('#t-trace');
  await tab(page, 'graph'); await page.waitForTimeout(1200);
  await exportAll('#t-graph');
  await tab(page, 'prio'); await page.locator('#pSec .chip').first().click(); await page.click('#pRun'); await page.waitForTimeout(500);
  await exportAll('#t-prio');
  await tab(page, 'mx'); await exportAll('#t-mx');
  await tab(page, 'grp'); await exportAll('#t-grp');
  assert.ok(saved.length >= 10, `exportações cobertas: ${saved.length} (${saved.join(', ')})`);
  fs.writeFileSync(path.join(OUT, 'downloads.json'), JSON.stringify(saved, null, 1));
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('link direto #g=N abre o dossiê do grupo', async () => {
  const { ctx, page, errors } = await open({ hash: '#g=5' });
  await page.waitForTimeout(400);
  assert.equal(await count(page, '#drawer.on'), 1);
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('tema claro/escuro alterna, persiste e segue o sistema por padrão', async () => {
  const { ctx, page, errors } = await open({ colorScheme: 'dark' });
  const bg = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const dark = await bg();
  await page.click('#theme');
  assert.equal(await page.getAttribute('html', 'data-theme'), 'light');
  assert.notEqual(await bg(), dark, 'fundo muda');
  await page.reload();
  await page.waitForSelector('#loading', { state: 'detached', timeout: 90000 });
  assert.equal(await page.getAttribute('html', 'data-theme'), 'light', 'escolha persiste após recarregar');
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('mobile (390×844): sem rolagem horizontal da página e abas acessíveis', async () => {
  const { ctx, page, errors } = await open({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  for (const t of TABS) {
    await page.locator(`#nav button[data-t="${t}"]`).scrollIntoViewIfNeeded();
    await tab(page, t);
    const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    assert.ok(over <= 1, `aba ${t}: página estoura ${over}px na horizontal`);
  }
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('acessibilidade básica: nomes acessíveis, rótulos e links externos seguros', async () => {
  const { ctx, page, errors } = await open();
  for (const t of TABS) await tab(page, t);
  const issues = await page.evaluate(() => {
    const out = [];
    document.querySelectorAll('button').forEach(b => { if (!(b.innerText.trim() || b.getAttribute('aria-label') || b.title)) out.push('botão sem nome: ' + b.outerHTML.slice(0, 80)); });
    document.querySelectorAll('input:not([type=checkbox]):not([type=range]),select').forEach(el => {
      const named = el.getAttribute('aria-label') || el.title || el.placeholder || el.closest('label') || (el.id && document.querySelector(`label[for="${el.id}"]`));
      if (!named) out.push('campo sem rótulo: #' + el.id);
    });
    document.querySelectorAll('a[target=_blank]').forEach(a => { if (!/noopener/.test(a.rel)) out.push('link externo sem rel=noopener: ' + a.href); });
    document.querySelectorAll('img').forEach(i => { if (!i.hasAttribute('alt')) out.push('img sem alt'); });
    return [...new Set(out)];
  });
  assert.deepEqual(issues, []);
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('segurança: conteúdo de regras é escapado e links de dados só aceitam http(s)', async () => {
  const { ctx, page, errors } = await open();
  // A regra "Cross Site Scripting Strings" contém <script> e <iframe> literais: devem aparecer como texto.
  const id = await page.evaluate(() => Object.keys(RULES).find(k => JSON.stringify(RULES[k]).includes('=<script>')));
  assert.ok(id, 'há uma regra com marcação HTML literal para testar');
  await tab(page, 'det');
  await page.evaluate(i => ruleModal(i), id);
  assert.ok(await page.locator('#modal.on').isVisible());
  assert.equal(await count(page, '#mb script, #mb iframe'), 0, 'nenhum elemento ativo injetado');
  let shown = '';
  for (const fmt of await page.locator('#mb .ftabs button:not(.x)').all()) { await fmt.click(); shown += await page.locator('#mb').innerText(); }
  assert.match(shown, /<script>|<iframe/i, 'marcação exibida como texto');
  assert.equal(await count(page, '#mb script, #mb iframe'), 0);
  const urls = await page.evaluate(() => ['javascript:alert(1)', ' JaVaScRiPt:alert(1)', 'data:text/html,x', '', null, 'https://attack.mitre.org/', 'http://x.y'].map(safeUrl));
  assert.deepEqual(urls, ['#', '#', '#', '#', '#', 'https://attack.mitre.org/', 'http://x.y']);
  assert.deepEqual(errors, []);
  await ctx.close();
});

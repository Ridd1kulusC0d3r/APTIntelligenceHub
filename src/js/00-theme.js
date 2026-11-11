// Tema claro/escuro (persistido em localStorage) e altura da barra de filtros (--fh),
// usada como deslocamento dos cabeçalhos de tabela sticky. Roda antes do app (01-core).
(function () {
  const root = document.documentElement, btn = document.getElementById("theme"), fbar = document.getElementById("fbar");
  const current = () => root.getAttribute("data-theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  if (btn) btn.addEventListener("click", () => {
    const next = current() === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("apt-theme", next); } catch (e) { /* armazenamento bloqueado: vale só para esta visita */ }
  });
  if (fbar && window.ResizeObserver) {
    const sync = () => root.style.setProperty("--fh", (getComputedStyle(fbar).position === "sticky" ? fbar.offsetHeight : 0) + "px");
    new ResizeObserver(sync).observe(fbar); addEventListener("resize", sync);
  }
})();

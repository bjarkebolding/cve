(async () => {
  const out = {};
  const j = (n) => fetch("data/" + n, { cache: "no-cache" }).then((r) => (r.ok ? r.json() : null)).catch(() => null);
  const [core, kev, sev, ap, dl, mal] = await Promise.all([j("data.json"), j("kev.json"), j("severity.json"), j("ai_packages.json"), j("downloads.json"), j("malicious.json")]);
  out.overflow = document.documentElement.scrollWidth - document.documentElement.clientWidth;
  out.width = document.documentElement.clientWidth;
  // a chart is REQUIRED when the data it is built from exists
  const need = {
    "chart-hero": !!(core && core.months),
    "chart-zeroday": !!(kev && (kev.byYear || (kev.entries || []).some((e) => typeof e.zeroDay === "boolean"))),
    "chart-supply": !!(core && core.originYears && core.originYears.supplychain),
    "chart-ttk": !!(kev && (kev.entries || []).some((e) => typeof e.daysToKev === "number")),
    "chart-sevall": !!(core && core.landscape && core.landscape.all),
    "chart-aiorigin": !!(core && core.landscape && core.landscape.ai),
    "chart-malicious": !!(mal && mal.byYear && Object.keys(mal.byYear).length),
    "chart-cves": !!(core && core.days),
    "chart-cna": !!(core && core.cnaYears),
  };
  out.inks = [];
  out.missing = [];
  for (const id of Object.keys(need)) {
    const c = document.querySelector("#" + id + " canvas");
    if (!c || !c.width) { if (need[id]) out.missing.push(id); else out.inks.push(id + ":n/a"); continue; }
    let a = 0, b = 0;
    const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
    for (let i = 0; i < d.length; i += 32) { b++; if (d[i] > 20 || d[i + 1] > 20 || d[i + 2] > 20) a++; }
    out.inks.push(id + ":" + (a ? Math.max(1, Math.round((100 * a) / b)) : 0) + "%");
  }
  // removed panels must stay gone
  out.removed = ["chart-hours", "chart-kev", "findings-list", "cards", "latest", "context", "layers", "chart-layers", "chart-rel", "exploitation", "chart-kev-origin", "threats", "threat-cards", "tbl-ai", "chart-aipkgs", "chart-adoption"].filter((id) => document.getElementById(id));
  out.epssRows = document.querySelectorAll("#tbl-epss tbody tr").length;
  out.headline = (document.querySelector("#headline") || {}).textContent || "";
  out.kpis = document.querySelectorAll("#kpis .kpi").length;
  out.whereRows = document.querySelectorAll("#where-bars .hb-row").length;
  out.tiers = ["summary", "exploit", "volume", "ai", "method"].filter((id) => document.getElementById(id)).length;
  // text that spills out of its card (measured on the text itself, not the element box)
  out.textOverflow = (() => {
    const bad = [], range = document.createRange();
    for (const b of document.querySelectorAll("main .panel, main .kpi, main .bl-item, main .brief-list > li, main .sub")) {
      const r = b.getBoundingClientRect();
      if (!r.width) continue;
      const tw = document.createTreeWalker(b, NodeFilter.SHOW_TEXT);
      let n;
      while ((n = tw.nextNode())) {
        if (!n.textContent.trim() || n.parentElement.closest("details:not([open])")) continue;
        const th = n.parentElement.closest("thead");  // phone tables keep headers only for screen readers (1px clip)
        if (th && th.getBoundingClientRect().width <= 2) continue;
        const wrap = n.parentElement.closest(".tablewrap");
        range.selectNodeContents(n);
        const e = range.getBoundingClientRect(), lim = wrap ? wrap.getBoundingClientRect() : r;
        if (e.width && (e.right > lim.right + 1 || e.left < lim.left - 1)) bad.push((b.id || b.className.split(" ")[0]) + ": " + n.textContent.trim().slice(0, 40));
      }
    }
    return bad.slice(0, 5);
  })();
  out.navLinks = [...document.querySelectorAll(".topnav a:not(.sub)")].filter((a) => document.querySelector(a.getAttribute("href"))).length;
  // tier 1 must come before tier 2/3 content
  const pos = (id) => { const e = document.getElementById(id); return e ? e.getBoundingClientRect().top + scrollY : -1; };
  out.tierOrder = pos("summary") < pos("volume") && pos("volume") < pos("exploit") && pos("exploit") < pos("ai") && pos("ai") < pos("method");
  // every slide card stands alone: title + "So what" + visible source
  out.slideGaps = [...document.querySelectorAll(".slide")].filter((u) => !u.querySelector("h2, h3") || !u.querySelector(".figfoot .so") || !u.querySelector(".src"))
    .map((u) => u.id || ((u.querySelector("h2, h3") || {}).id) || "?");
  out.slides = document.querySelectorAll(".slide").length;
  out.briefItems = document.querySelectorAll("#brief-list li").length;
  out.navSub = [...document.querySelectorAll(".topnav a.sub")].filter((a) => document.querySelector(a.getAttribute("href"))).length;
  out.navSubAll = document.querySelectorAll(".topnav a.sub").length;
  out.aiKpis = document.querySelectorAll("#ai-kpis .kpi").length;
  out.kevAllRows = document.querySelectorAll("#tbl-kevall tbody tr").length;
  out.topRows = document.querySelectorAll("#cweall .hb-row, #vendall .hb-row, #cnaall .hb-row").length;
  // Part 1 is AI-free: no AI wording in its headline, KPIs or hero
  out.part1Ai = /\bAI\b|MCP/.test(["#headline", "#subhead", "#kpis", "#h-hero", "#hero-note", "#h-where"].map((q) => (document.querySelector(q) || {}).textContent || "").join(" "));
  out.summaryBottom = Math.round(document.querySelector(".sumgrid") ? document.querySelector(".sumgrid").getBoundingClientRect().bottom + scrollY : -1);
  out.err = document.querySelectorAll(".err").length ? [...document.querySelectorAll(".err")].map((e) => e.textContent).join(" | ") : "no";
  const text = document.querySelector("main").innerText;
  out.badText = (text.match(/\b(NaN|undefined|Infinity)\b|\[object/g) || []).slice(0, 5);
  // external links must be target=_blank rel=noopener
  out.badLinks = [...document.querySelectorAll("a[href^='http']")].filter((a) => a.target !== "_blank" || !/noopener/.test(a.rel)).length;
  // main chart: default range 2018+, share mode labels
  const u = document.querySelector("#chart-cves")._u;
  if (u) {
    out.mainFirstX = u.data[0][0];
    out.defaultRange2018 = u.data[0][0] >= Date.UTC(2018, 0, 1) / 86400e3 && u.data[0][0] < Date.UTC(2018, 1, 1) / 86400e3;
    const share = document.querySelector("#ctl-cves [data-mode=share]");
    const count = document.querySelector("#ctl-cves [data-mode=count]");
    share.click();
    out.shareLabel = u.axes[1].label;
    await new Promise((r) => requestAnimationFrame(r));
    out.shareYLabel = (u.axes[1]._values || []).map(String).slice(0, 3);
    count.click();
    await new Promise((r) => requestAnimationFrame(r));
    out.countLabel = u.axes[1].label;
  }
  // exploited table must list every AI-flagged KEV entry
  out.kevAiRows = document.querySelectorAll("#tbl-kev tbody tr a").length;
  out.kevAiFlagged = kev && kev.entries ? kev.entries.filter((e) => e.ai).length : null;
  return JSON.stringify(out);
})()

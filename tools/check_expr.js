(async () => {
  const out = {};
  const j = (n) => fetch("data/" + n, { cache: "no-cache" }).then((r) => (r.ok ? r.json() : null)).catch(() => null);
  const [core, kev, sev, ap, dl, mal] = await Promise.all([j("data.json"), j("kev.json"), j("severity.json"), j("ai_packages.json"), j("downloads.json"), j("malicious.json")]);
  out.overflow = document.documentElement.scrollWidth - document.documentElement.clientWidth;
  out.width = document.documentElement.clientWidth;
  // a chart is REQUIRED when the data it is built from exists
  const need = {
    "chart-hero": !!(core && core.months),
    "chart-kev-origin": !!(kev && (kev.byYear || kev.entries)),
    "chart-zeroday": !!(kev && (kev.byYear || (kev.entries || []).some((e) => typeof e.zeroDay === "boolean"))),
    "chart-supply": !!(core && core.originYears && core.originYears.supplychain),
    "chart-malicious": !!(mal && mal.byYear && Object.keys(mal.byYear).length),
    "chart-cves": !!(core && core.days),
    "chart-layers": !!(core && core.layerMonths && core.layers),
    "chart-sev": !!(sev && sev.months && sev.months.length),
    "chart-cna": !!(core && core.cnaYears),
    "chart-aipkgs": !!(ap && ap.months && Object.keys(ap.months).length),
    "chart-adoption": !!(dl && dl.npmMonthly),
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
  out.removed = ["chart-hours", "chart-kev", "findings-list", "cards"].filter((id) => document.getElementById(id));
  out.rows = document.querySelectorAll("#tbl-ai tbody tr").length;
  out.epssRows = document.querySelectorAll("#tbl-epss tbody tr").length;
  out.headline = (document.querySelector("#headline") || {}).textContent || "";
  out.kpis = document.querySelectorAll("#kpis .kpi").length;
  out.whereRows = document.querySelectorAll("#where-bars .hb-row").length;
  out.tiers = ["summary", "risk", "detail", "method"].filter((id) => document.getElementById(id)).length;
  out.navLinks = [...document.querySelectorAll(".topnav a")].filter((a) => document.querySelector(a.getAttribute("href"))).length;
  // tier 1 must come before tier 2/3 content
  const pos = (id) => { const e = document.getElementById(id); return e ? e.getBoundingClientRect().top + scrollY : -1; };
  out.tierOrder = pos("summary") < pos("risk") && pos("risk") < pos("detail") && pos("detail") < pos("method");
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

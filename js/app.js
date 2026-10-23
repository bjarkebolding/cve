/* AI × Cybersecurity dashboard
 * Static, CSP-locked: all text below is inserted via textContent (no
 * innerHTML with data), charts are self-hosted uPlot, data is same-origin.
 */
"use strict";

const $ = (s) => document.querySelector(s);
const num = new Intl.NumberFormat("en");
const compact = (v) =>
  v >= 1e9 ? v / 1e9 + "B"
  : v >= 1e6 ? v / 1e6 + "M"
  : v >= 1e3 ? v / 1e3 + "k"
  : String(v);

const COLORS = {
  all: "rgba(255,255,255,0.85)",
  ai: "#4fd8ff",
  upd: "#b48cff",
  bars: "rgba(255,255,255,0.55)",
  pkgs: "#4fd8ff",
  npm1: "#4fd8ff", npm2: "rgba(255,255,255,0.85)", npm3: "#b48cff", npm4: "#56d364",
};

async function loadJSON(name) {
  const res = await fetch("data/" + name, { cache: "no-cache" });
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  return res.json();
}

function dayT(dateStr) { return Date.parse(dateStr + "T00:00:00Z") / 86400e3; }
function hourT(key) { return Date.parse(key + ":00Z") / 3600e3; }
function monthT(ym) { const [y, m] = ym.split("-"); return Date.UTC(+y, +m - 1, 1) / 86400e3; }

/* dense per-day array over [firstDay, lastDay] from sparse {dayStr: count} */
function denseDays(sparse, first, last) {
  const out = new Array(last - first + 1).fill(0);
  for (const d in sparse) out[dayT(d) - first] = sparse[d];
  return out;
}

/* bucket a dense daily array into day/week/month/year sums */
function bucketize(daily, first, agg) {
  const map = new Map();
  for (let i = 0; i < daily.length; i++) {
    const t = first + i;
    let key;
    if (agg === "day") key = t;
    else if (agg === "week") {
      const dow = (new Date(t * 86400e3).getUTCDay() + 6) % 7; // Monday
      key = t - dow;
    } else if (agg === "month") {
      const d = new Date(t * 86400e3);
      key = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1) / 86400e3;
    } else {
      const d = new Date(t * 86400e3);
      key = Date.UTC(d.getUTCFullYear(), 0, 1) / 86400e3;
    }
    map.set(key, (map.get(key) || 0) + daily[i]);
  }
  return [...map.entries()].sort((a, b) => a[0] - b[0]);
}

function cumulative(buckets) {
  let s = 0;
  return buckets.map(([t, v]) => [t, (s += v)]);
}

/* responsive uPlot wrapper (uPlot 1.6: width/height must be numbers; we
 * measure the container and re-set the size on resize) */
function makeChart(el, opts, data) {
  const w = Math.max(300, el.parentElement.clientWidth || 800);
  const h = opts.height || 300;
  const u = new uPlot({ ...opts, width: w, height: h }, data, el);
  const cv = u.ctx && u.ctx.canvas;
  if (cv) { cv.setAttribute("role", "img"); cv.setAttribute("aria-label", opts.ariaLabel || "chart"); }
  const ro = new ResizeObserver(() => {
    const cw = el.parentElement.clientWidth;
    if (cw > 0 && Math.abs(cw - u.width) > 2) u.setSize({ width: cw, height: h });
  });
  ro.observe(el.parentElement);
  el._u = u; // debug handle
  return u;
}

function fail(el, err) {
  const p = document.createElement("p");
  p.className = "err";
  p.textContent = `Could not load data (${err.message}).`;
  el.appendChild(p);
}

/* ================= stat cards ================= */
function buildCards(core, kev, ap, dl, nvd) {
  const aiSub = `${(100 * core.aiTotal / Math.max(1, core.total)).toFixed(2)}% of all published`
    + (nvd ? ` · NVD full-text: ML ${num.format(nvd.machineLearning || 0)}, LLM ${num.format(nvd.llm || 0)}` : "");
  const cards = [
    { k: "CVEs published", v: core.total, s: "all-time, official list" },
    {
      k: "AI-related CVEs", v: core.aiTotal, ai: true,
      s: aiSub,
    },
    core.projection
      ? {
          k: `${core.projection.month} pace`,
          v: core.projection.soFar,
          s: `~${num.format(core.projection.projected)} projected (median)`,
        }
      : null,
    {
      k: "Known exploited (KEV)", v: kev ? kev.total : "—",
      s: kev ? `${kev.aiCount} AI-matched` : "",
    },
    {
      k: "AI pkg advisories", v: ap ? Object.values(ap.perPackage).reduce((s, p) => s + p.count, 0) : "—",
      s: ap ? `${Object.keys(ap.perPackage).length} AI/ML packages` : "",
    },
    {
      k: "npm AI downloads", v: dl ? compact(sumNpmWeek(dl)) : "—",
      s: "per week, 9 AI SDKs (npm)",
    },
  ].filter(Boolean);

  const wrap = $("#cards");
  for (const c of cards) {
    const el = document.createElement("div");
    el.className = "card";
    const k = document.createElement("div");
    k.className = "k";
    k.textContent = c.k;
    const v = document.createElement("div");
    v.className = c.ai ? "v ai" : "v";
    v.textContent = typeof c.v === "number" ? num.format(c.v) : c.v;
    const s = document.createElement("div");
    s.className = "s";
    s.textContent = c.s;
    el.append(k, v, s);
    wrap.appendChild(el);
  }
}
function sumNpmWeek(dl) {
  return Object.values(dl.npmLastWeek || {}).reduce((a, b) => a + b, 0);
}

/* ================= main CVE chart ================= */
function buildMainChart(core) {
  const el = $("#chart-cves");
  const allDense = denseDays(Object.fromEntries(core.days.map((d, i) => [d, core.dayCounts[i]])), dayT(core.days[0]), dayT(core.days[core.days.length - 1]));
  const aiDense = denseDays(Object.fromEntries(core.aiDays.map((d, i) => [d, core.aiDayCounts[i]])), dayT(core.days[0]), dayT(core.days[core.days.length - 1]));
  const first = dayT(core.days[0]);
  const last = dayT(core.days[core.days.length - 1]);

  const state = { agg: "month", range: 0, mode: "count", showAll: true, showAi: true };
  const rangeMs = { "30d": 30 / 365.25, "1y": 1, "5y": 5, "10y": 10, all: 0 };

  function render() {
    let bAll = bucketize(allDense, first, state.agg);
    let bAi = bucketize(aiDense, first, state.agg);
    if (state.mode === "cum") { bAll = cumulative(bAll); bAi = cumulative(bAi); }
    const cut = rangeMs[state.range] ? last - rangeMs[state.range] * 365.25 : -Infinity;
    bAll = bAll.filter(([t]) => t >= cut);
    bAi = bAi.filter(([t]) => t >= cut);

    const seriesData = [
      bAll.map((x) => x[0]),
      bAll.map((x) => x[1]),
      bAi.map((x) => x[1]),
    ];
    uplot.axes[1].label = state.mode === "cum" ? "cumulative CVEs" : `CVEs / ${state.agg}`;
    uplot.setData(seriesData);
    uplot.setSeries(1, { show: state.showAll });
    uplot.setSeries(2, { show: state.showAi });
  }

  const opts = {
    width: "100%",
    height: 380,
    ariaLabel: "CVEs per period, all vs AI-related",
    scales: { time: { time: true } },
    axes: [
      { space: 70 },
      { space: 48, label: "CVEs", ticks: (u, val) => compact(val) },
    ],
    series: [
      { label: "date" },
      { label: "All CVEs", stroke: COLORS.all, width: 1.5, fill: "rgba(255,255,255,0.05)", spanGaps: true },
      { label: "AI-related", stroke: COLORS.ai, width: 1.5, fill: "rgba(79,216,255,0.08)", spanGaps: true },
    ],
    legend: { show: true },
    cursor: {
      dtl: (u, dtl) => {
        const i = u.cursor.idx;
        if (i == null) return dtl;
        const t = u.data[0][i];
        const d = new Date(t * (state.agg === "day" || state.agg === "week" ? 86400e3 : 86400e3));
        const label =
          state.agg === "year" ? String(d.getUTCFullYear())
          : state.agg === "month" ? d.toISOString().slice(0, 7)
          : d.toISOString().slice(0, 10);
        const parts = [label];
        if (state.showAll) parts.push("all " + num.format(u.data[1][i]));
        if (state.showAi) parts.push("AI " + num.format(u.data[2][i]));
        return parts.join("\t");
      },
    },
  };
  const uplot = makeChart(el, opts, [[], [], []]);
  render();

  function wire(attr, apply) {
    document.querySelectorAll(`#ctl-cves [data-${attr}]`).forEach((b) =>
      b.addEventListener("click", () => {
        document.querySelectorAll(`#ctl-cves [data-${attr}]`).forEach((x) => x.classList.remove("on"));
        b.classList.add("on");
        apply(b.dataset[attr]);
        render();
      }));
  }
  wire("agg", (v) => { state.agg = v; });
  wire("range", (v) => { state.range = v; });
  wire("mode", (v) => { state.mode = v; });
  $("#ser-all").addEventListener("change", (e) => { state.showAll = e.target.checked; render(); });
  $("#ser-ai").addEventListener("change", (e) => { state.showAi = e.target.checked; render(); });
}

/* ================= hourly chart ================= */
function buildHoursChart(core) {
  const el = $("#chart-hours");
  const newMap = core.hours || {};
  const aiMap = core.aiHours || {};
  const updMap = core.deltaHourUpdated || {};
  const keys = Object.keys(newMap).concat(Object.keys(updMap));
  if (!keys.length) { fail(el, new Error("no hourly data")); return; }
  const firstK = keys.sort()[0];
  const lastK = keys[keys.length - 1];
  const t0 = hourT(firstK), t1 = hourT(lastK);
  const denseNew = denseHours(newMap, t0, t1);
  const denseAi = denseHours(aiMap, t0, t1);
  const denseUpd = denseHours(updMap, t0, t1);
  const xs = Array.from({ length: denseNew.length }, (_, i) => t0 + i);

  const opts = {
    width: "100%",
    height: 300,
    ariaLabel: "Hourly CVE activity, new vs updates",
    scales: { time: { time: true }, y2: { range: (min, max) => [0, Math.max(1, max * 3)] } },
    axes: [
      {
        space: 60,
        ticks: (u, val) => {
          const d = new Date(val * 3600e3);
          return d.getUTCHours() === 0 ? d.toISOString().slice(5, 10) : "";
        },
      },
      { space: 40, label: "new CVEs / hr", ticks: (u, val) => compact(val) },
      {
        show: false,
        space: 40,
        ticks: (u, val) => compact(val),
      },
    ],
    series: [
      { label: "hour" },
      { label: "New CVEs", fill: "rgba(255,255,255,0.5)", stroke: "rgba(255,255,255,0.75)", width: 0, barWidth: (u, data) => Math.min(4, (u.width / data[0].length) * 0.9) },
      { label: "AI-related new", stroke: COLORS.ai, width: 1.5, fill: "rgba(79,216,255,0.08)" },
      { label: "Record updates (y2, ×1/3)", scale: "y2", stroke: COLORS.upd, width: 1, alpha: 0.55, fill: null },
    ],
    legend: { show: false },
    hooks: {
      setCursor: [(u, idx) => {
        // legend row as a DOM hint (no inline handlers needed; textContent only)
        let tip = el.querySelector(".htip");
        if (!tip) { tip = document.createElement("div"); tip.className = "htip"; el.appendChild(tip); }
        if (idx == null) { tip.style.display = "none"; return; }
        tip.style.display = "block";
        const d = new Date(xs[idx] * 3600e3).toISOString().slice(5, 16);
        tip.textContent = `${d}Z  new ${num.format(u.data[1][idx])}  AI ${num.format(u.data[2][idx])}  updates ${num.format(u.data[3][idx])}`;
      }],
    },
  };
  makeChart(el, opts, [xs, denseNew, denseAi, denseUpd]);
}
function denseHours(sparse, t0, t1) {
  const out = new Array(t1 - t0 + 1).fill(0);
  for (const k in sparse) out[hourT(k) - t0] = sparse[k];
  return out;
}

/* ================= AI package vulns (monthly) ================= */
function buildAiPkgsChart(ap) {
  const el = $("#chart-aipkgs");
  const months = Object.keys(ap.months).sort();
  const xs = months.map(monthT);
  const ys = months.map((m) => ap.months[m]);
  const opts = {
    width: "100%",
    height: 260,
    ariaLabel: "AI/ML package advisories per month",
    scales: { time: { time: true } },
    axes: [
      { space: 58, ticks: (u, val) => {
        const d = new Date(val * 86400e3);
        return d.getUTCMonth() === 0 ? String(d.getUTCFullYear()) : d.toISOString().slice(0, 7);
      } },
      { space: 36, label: "advisories / mo" },
    ],
    series: [
      { label: "month" },
      { label: "AI pkg advisories", stroke: COLORS.pkgs, width: 0, fill: "rgba(79,216,255,0.5)", barWidth: (u, data) => Math.max(1, Math.min(14, (u.width / data[0].length) * 0.85)) },
    ],
    legend: { show: false },
    cursor: {
      dtl: (u, dtl) => {
        const i = u.cursor.idx;
        if (i == null) return dtl;
        return `${months[i]}\t${num.format(u.data[1][i])}`;
      },
    },
  };
  makeChart(el, opts, [xs, ys]);
}

/* ================= adoption (npm, log scale) ================= */
function buildAdoptionChart(dl) {
  const el = $("#chart-adoption");
  const pkgs = ["openai", "ai", "langchain", "@huggingface/transformers"];
  const monthly = dl.npmMonthly || {};
  const monthSet = new Set();
  for (const p of pkgs) for (const m of Object.keys(monthly[p] || {})) monthSet.add(m);
  if (!monthSet.size) { fail(el, new Error("no download data")); return; }
  const months = [...monthSet].sort();
  const xs = months.map(monthT);
  const colors = [COLORS.npm1, COLORS.npm2, COLORS.npm3, COLORS.npm4];
  const series = [
    { label: "month" },
    ...pkgs.map((p, i) => ({
      label: p,
      stroke: colors[i], width: 1.5, fill: null,
    })),
  ];
  const seriesData = pkgs.map((p) => {
    const m = monthly[p] || {};
    return months.map((mm) => Math.max(1, m[mm] || 0));
  });
  const opts = {
    width: "100%",
    height: 260,
    ariaLabel: "Monthly npm downloads of AI packages, log scale",
    scales: { time: { time: true } },
    axes: [
      { space: 58, ticks: (u, val) => {
        const d = new Date(val * 86400e3);
        return d.getUTCMonth() === 0 ? String(d.getUTCFullYear()) : d.toISOString().slice(0, 7);
      } },
      { space: 40 },
    ],
    series: series,
    legend: { show: true },
  };
  const dataLog = [xs, ...seriesData.map((arr) => arr.map((v) => Math.log10(v)))];
  const optsLog = {
    ...opts,
    axes: [
      opts.axes[0],
      { space: 40, label: "downloads / mo (log₁₀)", ticks: (u, val) => {
        const p = Math.round(val);
        return p === 3 ? "1k" : p === 4 ? "10k" : p === 5 ? "100k" : p === 6 ? "1M" : p === 7 ? "10M" : p === 8 ? "100M" : "";
      } },
    ],
    cursor: {
      dtl: (u, dtl) => {
        const i = u.cursor.idx;
        if (i == null) return dtl;
        const parts = [months[i]];
        for (let s = 1; s < u.series.length; s++) {
          if (u.series[s].show !== false) parts.push(`${u.series[s].label} ${compact(Math.round(10 ** u.data[s][i]))}`);
        }
        return parts.join("\t");
      },
    },
  };
  makeChart(el, optsLog, dataLog);
}

/* ================= tables ================= */
function buildRecentAiTable(core, kev) {
  const tbody = $("#tbl-ai tbody");
  const kevSet = new Set((kev ? kev.entries : []).map((e) => e.cve));
  for (const r of core.recentAi || []) {
    const tr = document.createElement("tr");
    const tdId = document.createElement("td");
    const span = document.createElement("span");
    span.className = "cveid";
    const a = document.createElement("a");
    a.href = `https://www.cve.org/CVERecord?id=${encodeURIComponent(r.id)}`;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = r.id;
    span.appendChild(a);
    if (kevSet.has(r.id)) {
      const b = document.createElement("span");
      b.className = "badge";
      b.textContent = "KEV";
      span.appendChild(b);
    }
    if (r.cvss) {
      const s = document.createElement("span");
      s.className = "sev " + (r.cvss.sev || "").toUpperCase();
      s.textContent = (r.cvss.sev + " " + (r.cvss.score != null ? r.cvss.score : "")).trim();
      s.title = "NVD CVSS (primary)";
      span.appendChild(s);
    }
    tdId.appendChild(span);
    const tdPub = document.createElement("td");
    tdPub.textContent = r.published + "Z";
    tdPub.style.whiteSpace = "nowrap";
    const tdCna = document.createElement("td");
    const cna = r.cna || "";
    const isEmail = cna.includes("@");
    tdCna.textContent = isEmail ? cna : cna.slice(0, 8);
    tdCna.title = cna;
    tdCna.style.whiteSpace = isEmail ? "nowrap" : "";
    const tdDesc = document.createElement("td");
    tdDesc.className = "desc";
    tdDesc.textContent = r.description || "(no english description)";
    tr.append(tdId, tdPub, tdCna, tdDesc);
    tbody.appendChild(tr);
  }
}

function wireAiFilter() {
  const input = $("#ai-filter");
  const rows = [...document.querySelectorAll("#tbl-ai tbody tr")];
  if (!input) return;
  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    for (const tr of rows) tr.style.display = q && !tr.textContent.toLowerCase().includes(q) ? "none" : "";
  });
}

function buildKevAiTable(kev) {
  const tbody = $("#tbl-kev tbody");
  const rows = (kev ? kev.entries : []).filter((e) => e.ai).slice(0, 50);
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.textContent = "No AI-matched KEV entries at the moment.";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const r of rows) {
    const tr = document.createElement("tr");
    const tdId = document.createElement("td");
    tdId.style.whiteSpace = "nowrap";
    tdId.textContent = r.cve;
    const tdAdded = document.createElement("td");
    tdAdded.textContent = r.added;
    tdAdded.style.whiteSpace = "nowrap";
    const tdProd = document.createElement("td");
    tdProd.textContent = r.product;
    const tdDesc = document.createElement("td");
    tdDesc.className = "desc";
    tdDesc.textContent = r.desc;
    if (r.ransomware) {
      const b = document.createElement("span");
      b.className = "badge";
      b.textContent = "RANSOMWARE";
      tdDesc.appendChild(b);
    }
    tr.append(tdId, tdAdded, tdProd, tdDesc);
    tbody.appendChild(tr);
  }
}

/* ================= boot ================= */
(async () => {
  const stamp = $("#stamp");
  let core, kev, ap, dl, nvd;
  try {
    [core, kev, ap, dl, nvd] = await Promise.all([
      loadJSON("data.json"),
      loadJSON("kev.json").catch(() => null),
      loadJSON("ai_packages.json").catch(() => null),
      loadJSON("downloads.json").catch(() => null),
      loadJSON("nvd.json").catch(() => null),
    ]);
  } catch (err) {
    stamp.textContent = "error: " + err.message;
    return;
  }
  stamp.textContent =
    `data as of ${new Date(core.generatedAt).toUTCString()} · ` +
    (kev ? `KEV ${new Date(kev.generatedAt).toISOString().slice(0, 10)} · ` : "") +
    "rebuilt daily";
  try {
    buildCards(core, kev, ap, dl, nvd);
    buildMainChart(core);
    buildHoursChart(core);
    if (ap) buildAiPkgsChart(ap);
    if (dl) buildAdoptionChart(dl);
    buildRecentAiTable(core, kev);
    wireAiFilter();
    buildKevAiTable(kev);
  } catch (err) {
    const p = document.createElement("p");
    p.className = "err";
    p.textContent = "render error: " + err.message;
    document.querySelector("main").prepend(p);
  }
})();

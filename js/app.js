/* The vulnerability surge — and how much of it is AI — dashboard
 * Part 1 covers every CVE (no AI framing); Part 2 the AI-related slice.
 * Static, CSP-locked: all text below is inserted via textContent (no
 * innerHTML with data), charts are self-hosted uPlot, data is same-origin.
 * Every panel renders independently and degrades to a short note when its
 * data file or key is missing (old data builds must not throw).
 */
"use strict";

const $ = (s) => document.querySelector(s);
const num = new Intl.NumberFormat("en");
const fin = (v) => typeof v === "number" && Number.isFinite(v);
const compact = (v) => {
  if (!fin(v)) return "";
  const r = (x, p) => {
    const s = x.toFixed(p);
    return s.includes(".") ? s.replace(/\.?0+$/, "") : s;
  };
  const a = Math.abs(v);
  if (a >= 1e9) return r(v / 1e9, 2) + "B";
  if (a >= 1e6) return r(v / 1e6, 2) + "M";
  if (a >= 1e3) return r(v / 1e3, 1) + "k";
  return String(Math.round(v * 100) / 100);
};
/* axis numbers: thousands separators; compact only from a million */
const axisNum = (v) => (!fin(v) ? "" : Math.abs(v) >= 1e6 ? compact(v) : num.format(Math.round(v * 100) / 100));
const pct = (x, digits = 0) => (100 * x).toFixed(digits) + "%";

/* ---- palette ----
 * Every colour is a CSS token (css/style.css, :root + dark override); the
 * charts read the same tokens here, so CSS and canvas never drift apart.
 * Canvas takes its colours at draw time: a theme switch reloads the page
 * (see boot). The hex values below are only fallbacks if a token is missing.
 * Meaning is fixed: blue = AI, red/orange/amber = severity and exploitation
 * only, grey = "all" and the remainder; the other hues are muted categories
 * picked to stay apart under protan/deutan/tritan simulation. */
const FORCED_THEME = document.documentElement.getAttribute("data-theme");
const LIGHT = FORCED_THEME ? FORCED_THEME === "light" : !!(window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches);
const tone = (dark, light) => (LIGHT ? light : dark);
const ROOT_CSS = getComputedStyle(document.documentElement);
const tok = (name, dark, light) => (ROOT_CSS.getPropertyValue("--" + name) || "").trim() || tone(dark, light);
const P = {
  /* categories */
  blue: tok("c-blue", "#7c9cff", "#3457d5"),
  teal: tok("c-teal", "#4fb3a9", "#1f8a80"),
  sage: tok("c-sage", "#6e9d5e", "#4f7f34"),
  sand: tok("c-sand", "#d9c79f", "#b39d6a"),
  mauve: tok("c-mauve", "#b07cb8", "#a2559f"),
  sky: tok("c-sky", "#8cc8e8", "#7fbde0"),
  plum: tok("c-plum", "#6c64c8", "#4f3f7a"),
  navy: tok("c-navy", "#c3cdff", "#1d2c80"),
  neutral: tok("c-neutral", "#c9ced6", "#4b5563"),
  grey: tok("c-grey", "#646c7a", "#a3aab5"),
  slate: tok("c-slate", "#4e5767", "#c2c8d2"),
  steel: tok("c-steel", "#8594ae", "#7d8ca6"),
  /* severity / urgency only */
  red: tok("c-crit", "#ef6b63", "#c8372d"),
  orange: tok("c-high", "#e5925c", "#c9652c"),
  amber: tok("c-med", "#dcb162", "#b9861a"),
  dusk: tok("c-low", "#8fa6c4", "#93a8c4"),
  /* chart chrome */
  axis: tok("muted", "#8a919c", "#5f6773"),
  grid: tok("chart-grid", "rgba(138,145,156,0.14)", "rgba(95,103,115,0.13)"),
  tickLine: tok("chart-tick", "rgba(138,145,156,0.35)", "rgba(95,103,115,0.35)"),
  allFill: tok("chart-all-fill", "rgba(201,206,214,0.06)", "rgba(75,85,99,0.06)"),
  aiFill: tok("chart-ai-fill", "rgba(124,156,255,0.20)", "rgba(52,87,213,0.14)"),
};
const COLORS = {
  all: P.neutral,
  ai: P.blue,
  upd: P.dusk,
  pkgs: P.blue,
  npm1: P.blue, npm2: P.neutral, npm3: P.sand, npm4: P.teal,
  kev: P.red,
};
const SEV_KEYS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
/* ordinal: a warm ramp for urgency, a cool grey-blue for LOW */
const SEV_COLORS = { CRITICAL: P.red, HIGH: P.orange, MEDIUM: P.amber, LOW: P.dusk, UNRATED: P.slate };

/* AI stack layers: ids are fixed by the data contract. Distinct hues, so
 * neighbours in the stack never rely on red-vs-green alone. Labels here are
 * only a fallback for lookups — the data's own `layers` list is
 * authoritative. */
const LAYER_COLORS = {
  mcp: P.navy,              /* = the agent relation */
  gateway: P.sky,
  inference: P.teal,
  mlops: P.sage,
  llmapp: P.mauve,
  model: P.plum,
  cloud: P.neutral,
  framework: P.blue,
  other: P.grey,
};
const LAYER_FALLBACK = {
  mcp: "MCP servers & agent tools", gateway: "LLM gateways & proxies",
  inference: "Inference & model serving", mlops: "MLOps & ML platforms",
  llmapp: "LLM apps & orchestration", model: "Model files & loading",
  cloud: "AI cloud services & assistants", framework: "ML frameworks & libraries",
  other: "Other AI-related",
};
/* hex colour blended toward the card background: a = share of the colour kept */
function tint(hex, a) {
  const bg = tok("raise", "#181b21", "#ffffff");
  const rgb = (h) => { const m = /^#?([0-9a-f]{6})$/i.exec(String(h).trim()); return m ? [0, 2, 4].map((i) => parseInt(m[1].slice(i, i + 2), 16)) : null; };
  const c = rgb(hex), b = rgb(bg);
  if (!c || !b) return hex;
  return "#" + c.map((v, i) => Math.round(v * a + b[i] * (1 - a)).toString(16).padStart(2, "0")).join("");
}
const OTHER_COLOR = P.slate;

async function loadJSON(name) {
  const res = await fetch("data/" + name, { cache: "no-cache" });
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  return res.json();
}

function dayT(dateStr) { return Date.parse(dateStr + "T00:00:00Z") / 86400e3; }
function monthT(ym) { const [y, m] = ym.split("-"); return Date.UTC(+y, +m - 1, 1) / 86400e3; }
function ymAdd(ym, k) {
  const [y, m] = ym.split("-").map(Number);
  const d = new Date(Date.UTC(y, m - 1 + k, 1));
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}
function monthRange(a, b) { const out = []; for (let m = a; m <= b; m = ymAdd(m, 1)) out.push(m); return out; }
function daysBetween(a, b) {
  const x = dayT(a), y = dayT(b);
  return fin(x) && fin(y) ? Math.round(y - x) : null;
}
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const fmtDay = (s) => { const [y, m, d] = s.split("-"); return `${MONTHS[+m - 1]} ${+d}, ${y}`; };

/* uPlot 1.6: the axis *label* formatter is `values: (self, vals) => [..labels]`
 * (`ticks` only styles the tick marks) — wrap a per-value fn for readability */
const tick = (fn) => (u, vals) => vals.map(fn);
/* x axis in DAYS from epoch: uPlot's time-scale tick placement assumes
 * seconds, so we place ticks ourselves (axes[].splits) on clean boundaries —
 * Jan 1 / first of month / day — and label them to match. One label per year
 * at most, so long spans never repeat a year. */
function dayAxis(extra) {
  let kind = "y";
  return {
    space: 50,
    ...extra,
    splits: (u, ai, min, max) => {
      const maxLab = Math.max(2, Math.floor((u.width || 600) / 78));
      const span = max - min;
      const out = [];
      const a = new Date(min * 86400e3), b = new Date(max * 86400e3);
      if (span / 365.25 > 3) {
        kind = "y";
        const y0 = a.getUTCFullYear(), y1 = b.getUTCFullYear();
        const step = Math.max(1, Math.ceil((y1 - y0 + 1) / maxLab));
        for (let y = y0; y <= y1; y++) {
          const t = Date.UTC(y, 0, 1) / 86400e3;
          if (y % step === 0 && t >= min && t <= max) out.push(t);
        }
      } else if (span > 120) {
        kind = "m";
        const m0 = a.getUTCFullYear() * 12 + a.getUTCMonth(), m1 = b.getUTCFullYear() * 12 + b.getUTCMonth();
        const step = [1, 2, 3, 4, 6, 12].find((s) => (m1 - m0 + 1) / s <= maxLab) || 12;
        for (let m = m0; m <= m1; m++) {
          const t = Date.UTC(Math.floor(m / 12), m % 12, 1) / 86400e3;
          if (m % step === 0 && t >= min && t <= max) out.push(t);
        }
      } else {
        kind = "d";
        const step = [1, 2, 3, 7, 14, 28].find((s) => span / s <= maxLab) || 28;
        for (let t = Math.ceil(min); t <= max; t++) if (Math.round(t) % step === 0) out.push(t);
      }
      return out;
    },
    values: (u, vals) => vals.map((v) => {
      const iso = new Date(v * 86400e3).toISOString();
      return kind === "y" ? iso.slice(0, 4) : kind === "m" ? iso.slice(0, 7) : iso.slice(5, 10);
    }),
  };
}

/* ---------- DOM helpers (textContent only) ---------- */
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null) continue;
      if (k === "text") e.textContent = v;
      else if (k === "class") e.className = v;
      else e.setAttribute(k, v);
    }
  }
  for (const c of kids) if (c != null) e.append(c);
  return e;
}
function note(el, msg) {
  if (!el) return;
  el.append(h("p", { class: "na", text: msg }));
}
function cveLink(id) {
  return h("a", { class: "cveid", href: `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`, target: "_blank", rel: "noopener", text: id });
}
function badge(text, cls, title) { return h("span", { class: "badge" + (cls ? " " + cls : ""), text, title }); }
function sevBadge(sev, score, title) {
  const s = String(sev || "").toUpperCase();
  if (!SEV_KEYS.includes(s)) return null;
  return h("span", { class: "sev " + s, text: (s + (fin(score) ? " " + score : "")), title });
}
/* copy each column header into data-label so phones can show labelled cards */
function labelCells(table) {
  if (!table) return;
  const heads = [...table.querySelectorAll("thead th")].map((th) => th.textContent.trim());
  for (const tr of table.querySelectorAll("tbody tr")) {
    [...tr.children].forEach((td, i) => { if (heads[i] && !td.hasAttribute("colspan")) td.setAttribute("data-label", heads[i]); });
  }
}
function emptyRow(tbody, cols, msg) {
  tbody.append(h("tr", null, h("td", { colspan: String(cols), class: "na", text: msg })));
}

/* ---------- data normalisation ---------- */
function layerList(core, meta) {
  const l = (core && Array.isArray(core.layers) && core.layers) || (meta && Array.isArray(meta.layers) && meta.layers) || null;
  return l ? l.filter((x) => x && x.id) : null;
}
function makeLayerLabel(layers) {
  const m = {};
  for (const l of layers || []) m[l.id] = l.label || l.id;
  return (id) => (id ? m[id] || LAYER_FALLBACK[id] || id : null);
}
/* ai_meta ids: new schema {id: {d, layer, sev, ...}}, old schema {id: "YYYY-MM-DD"} */
function metaLookup(meta) {
  const ids = (meta && meta.ids) || {};
  return (id) => {
    const v = ids[id];
    if (v == null) return null;
    return typeof v === "string" ? { d: v } : v;
  };
}
function layerSwatch(id) {
  const s = h("span", { class: "swatch", "aria-hidden": "true" });
  s.style.background = LAYER_COLORS[id] || OTHER_COLOR;
  return s;
}
function layerCell(id, label) {
  const td = h("td", { class: "nowrap" });
  if (!id) { td.textContent = "—"; return td; }
  td.append(layerSwatch(id), document.createTextNode(label(id)));
  return td;
}
/* layer (swatch + label) with the product on a second, muted line */
function stackCell(layer, product, label) {
  const td = h("td", { class: "stack" });
  const l = h("div", { class: "nowrap" });
  if (layer) l.append(layerSwatch(layer), document.createTextNode(label(layer)));
  else l.textContent = "—";
  td.append(l);
  if (product) td.append(h("div", { class: "prod", text: product }));
  return td;
}
/* relation tags with the product on a second, muted line */
function relCell(rels, product, RL) {
  const td = h("td", { class: "stack" });
  td.append(rels && rels.length ? relTags(rels, RL) : h("div", { text: "—" }));
  if (product) td.append(h("div", { class: "prod", text: product }));
  return td;
}
/* KEV tables: EPSS the day before CISA listed the CVE (the advance signal);
 * falls back to today's score, marked, when no historical score is cached. */
function kevEpssCell(ctx, cve) {
  const pr = ctx.epssPrior && ctx.epssPrior.scores && ctx.epssPrior.scores[cve];
  if (pr) return h("td", { class: "num", text: fin(pr.epss) ? pct(pr.epss, pr.epss < 0.1 ? 1 : 0) : "no score", title: `EPSS on ${pr.date}, the day before CISA listed it` });
  const sc = ctx.epss && ctx.epss.scores && ctx.epss.scores[cve];
  return h("td", { class: "num", text: sc ? epssText(sc) + "*" : "—", title: sc ? "today's EPSS (* no pre-listing score cached; inflated by the known exploitation)" : null });
}
function epssText(s) { return s && fin(s.epss) ? pct(s.epss, s.epss < 0.1 ? 1 : 0) : "—"; }

/* ---------- chart plumbing ---------- */
/* responsive uPlot wrapper (uPlot 1.6: width/height must be numbers; we
 * measure the host and re-set the size on resize) */
function makeChart(el, opts, data) {
  // Measure the HOST element, not its parent: parent clientWidth includes the
  // panel's padding, which makes the canvas wider than the content area.
  const w = Math.max(260, el.clientWidth || 800);
  const hgt = opts.height || 300;
  // uPlot's default axis stroke is #000 (black) — invisible on the dark theme.
  const AXIS = { stroke: P.axis, grid: { stroke: P.grid, width: 1 }, ticks: { stroke: P.tickLine, width: 1 } };
  const ax = (opts.axes || []).map((a) => a && { ...AXIS, ...a, grid: { ...AXIS.grid, ...(a.grid || {}) } });
  const u = new uPlot({ ...opts, axes: ax, width: w, height: hgt }, data, el);
  const cv = u.ctx && u.ctx.canvas;
  if (cv) { cv.setAttribute("role", "img"); cv.setAttribute("aria-label", opts.ariaLabel || "chart"); }
  el.setAttribute("aria-label", opts.ariaLabel || "chart");
  const ro = new ResizeObserver(() => {
    const cw = el.clientWidth;
    if (cw > 0 && Math.abs(cw - u.width) > 2) u.setSize({ width: cw, height: hgt });
  });
  ro.observe(el.parentElement);
  el._u = u; // debug handle
  return u;
}
const barPaths = (max, gap) => uPlot.paths && uPlot.paths.bars ? uPlot.paths.bars({ size: [0.82, max || 40], gap }) : undefined;

/* Stacked bars. uPlot 1.6 has no native stacking: we draw each series as a
 * bar from 0 to its cumulative height, topmost layer first, so lower layers
 * overpaint the bottom of the bars above them. Legend/cursor values show the
 * raw (unstacked) counts. Hiding a series via the legend re-stacks. */
/* narrow screens: monthly bars thinner than ~3px alias badly (the stacked
 * overpaint bleeds) — re-bucket monthly data to quarters, then years */
function coarsenMonthly(el, cfg) {
  const avail = Math.max(200, (el.clientWidth || 800) - 70);
  let { xs, groups, xFmt } = cfg;
  for (const per of [3, 12]) {
    if (avail / xs.length >= 3) break;
    const keyOf = (t) => {
      const d = new Date(t * 86400e3);
      const m = d.getUTCMonth() - (d.getUTCMonth() % per);
      return Date.UTC(d.getUTCFullYear(), m, 1) / 86400e3;
    };
    const keys = [...new Set(xs.map(keyOf))];
    const pos = new Map(keys.map((k, i) => [k, i]));
    groups = groups.map((g) => {
      const data = new Array(keys.length).fill(0);
      xs.forEach((t, i) => { data[pos.get(keyOf(t))] += g.data[i] || 0; });
      return { ...g, data };
    });
    xs = keys;
    xFmt = per === 3
      ? (v) => { const d = new Date(v * 86400e3); return `${d.getUTCFullYear()}-Q${Math.floor(d.getUTCMonth() / 3) + 1}`; }
      : (v) => String(new Date(v * 86400e3).getUTCFullYear());
    cfg = { ...cfg, xLabel: per === 3 ? "quarter" : "year", yLabel: cfg.yLabel && cfg.yLabel.replace("per month", per === 3 ? "per quarter" : "per year") };
  }
  return { ...cfg, xs, groups, xFmt };
}
function stackedBars(el, cfg) {
  if (cfg.monthly) cfg = coarsenMonthly(el, cfg);
  const { xs, groups } = cfg; // groups: bottom → top [{label, color, data}]
  const n = groups.length;
  const order = groups.map((_, i) => n - 1 - i); // uPlot series k+1 ↔ group order[k]
  const visible = groups.map(() => true);
  const restack = () => {
    const acc = new Array(xs.length).fill(0);
    const cum = groups.map(() => null);
    for (let g = 0; g < n; g++) {
      if (!visible[g]) { cum[g] = acc.slice(); continue; }
      for (let i = 0; i < xs.length; i++) acc[i] += groups[g].data[i] || 0;
      cum[g] = acc.slice();
    }
    return [xs, ...order.map((g) => cum[g])];
  };
  let busy = false;
  const opts = {
    height: cfg.height || 300,
    ariaLabel: cfg.ariaLabel,
    // pad the x range by half a bar so the first/last bars aren't clipped
    scales: { x: { time: cfg.time !== false, range: (u, mn, mx) => { const p = cfg.time === false ? 0.5 : 16; return [mn - p, mx + p]; } }, y: { range: (u, mn, mx) => [0, cfg.yMax ? cfg.yMax : Math.max(1, mx * (cfg.draw ? 1.28 : 1.05))] } },
    axes: [
      cfg.time === false ? { space: cfg.xSpace || 58, values: cfg.xValues, incrs: cfg.xIncrs } : dayAxis(),
      { space: 40, label: cfg.yLabel, values: tick(axisNum), size: 62 },
    ],
    series: [
      // idle legend shows plain labels (no "—" placeholders); values appear on hover
      { label: cfg.xLabel || "month", value: (u, v) => (v == null ? "" : cfg.xFmt(v)) },
      ...order.map((g) => ({
        label: groups[g].label,
        stroke: groups[g].color,
        fill: groups[g].color,
        width: 0,
        paths: barPaths(cfg.barMax, (el.clientWidth || 800) / xs.length > 6 ? 1 : 0),
        points: { show: false },
        value: (u, v, si, i) => (i == null ? "" : num.format(groups[g].data[i] || 0)),
      })),
    ],
    legend: { show: true, live: true },
    cursor: { points: { show: false } },
    hooks: {
      setSeries: [(u, si) => {
        if (busy || si == null) return;
        busy = true;
        for (let k = 1; k < u.series.length; k++) visible[order[k - 1]] = u.series[k].show !== false;
        u.setData(restack());
        busy = false;
      }],
      draw: cfg.draw ? [cfg.draw] : [],
    },
  };
  if (cfg.legend === false) opts.legend = { show: false };
  const u = makeChart(el, opts, restack());
  if (u && u.root) u.root.classList.add("stacked");
  return u;
}

/* ================= derived facts (shared by cards + findings) ================= */
function computeFacts(ctx) {
  const { core, kev, sev, metaOf, label } = ctx;
  const F = {};
  const asOf = (core && core.generatedAt ? core.generatedAt : new Date().toISOString()).slice(0, 10);
  F.asOf = asOf;
  F.year = asOf.slice(0, 4);
  F.prevYear = String(+F.year - 1);
  // single products dominating a year's AI CVEs (bulk disclosures)
  F.concentration = (core && core.concentration && typeof core.concentration === "object") ? core.concentration : null;
  const md = asOf.slice(5);
  // YTD AI CVEs vs same period last year (day-level)
  try {
    if (Array.isArray(core.aiDays) && Array.isArray(core.aiDayCounts)) {
      let cur = 0, prev = 0, prevFull = 0;
      core.aiDays.forEach((d, i) => {
        const c = core.aiDayCounts[i] || 0;
        const y = d.slice(0, 4);
        if (y === F.year && d.slice(5) <= md) cur += c;
        if (y === F.prevYear) { prevFull += c; if (d.slice(5) <= md) prev += c; }
      });
      F.ytd = { cur, prev, prevFull };
    }
  } catch (e) { /* skip */ }
  // KEV AI entries
  try {
    if (kev && Array.isArray(kev.entries)) {
      const rows = kev.entries.filter((e) => e && e.ai).map((e) => {
        const m = metaOf(e.cve) || {};
        const published = e.published || m.d || null;
        let dtk = fin(e.daysToKev) ? e.daysToKev : null;
        if (dtk == null && published && e.added) dtk = daysBetween(published, e.added);
        return { ...e, published, daysToKev: dtk, layer: e.layer || m.layer || null, rels: e.rels && e.rels.length ? e.rels : m.rels || null };
      });
      rows.sort((a, b) => String(b.added).localeCompare(String(a.added)));
      F.kevAi = rows;
      F.kevAiThisYear = rows.filter((r) => String(r.added).startsWith(F.year)).length;
      F.kevAiRansom = rows.filter((r) => r.ransomware).length;
    }
  } catch (e) { /* skip */ }
  // layer growth: last 12 complete months vs the 12 before
  try {
    if (core.layerMonths && Array.isArray(core.months)) {
      const idx = new Map(core.months.map((m, i) => [m, i]));
      const curM = asOf.slice(0, 7);
      const end = ymAdd(curM, -1);
      const lastW = monthRange(ymAdd(end, -11), end), prevW = monthRange(ymAdd(end, -23), ymAdd(end, -12));
      const sum = (arr, w) => w.reduce((s, m) => s + (idx.has(m) ? arr[idx.get(m)] || 0 : 0), 0);
      let best = null;
      for (const [id, arr] of Object.entries(core.layerMonths)) {
        if (!Array.isArray(arr) || id === "other") continue;
        const a = sum(arr, lastW), b = sum(arr, prevW);
        if (a >= 10 && (!best || a - b > best.a - best.b)) best = { id, a, b };
      }
      if (best && best.a > best.b) F.growth = { ...best, label: label(best.id), end };
      const mcp = core.layerMonths.mcp;
      if (Array.isArray(mcp)) {
        F.mcpYtd = core.months.reduce((s, m, i) => s + (m.startsWith(F.year) ? mcp[i] || 0 : 0), 0);
      }
    }
  } catch (e) { /* skip */ }
  return F;
}

/* ================= origins (contract v2) ================= */
const ORIGIN_COLORS = {
  supplychain: P.teal,
  plugin: P.mauve,
  edge: P.plum,
  platform: P.sage,
  other: P.slate,          /* the large remainder stays quiet */
};
const ORIGIN_FALLBACK = {
  supplychain: "Open-source projects & packages (supply chain)",
  plugin: "Web CMS plugins & themes", edge: "Network & security edge devices",
  platform: "OS, browsers & core platforms", other: "Enterprise & other software",
};
const ORIGIN_RULES = {
  supplychain: "affected product identified by a package URL or registry (npm, PyPI, Maven, Go, crates.io, RubyGems, NuGet, Packagist, …), plus all GitHub-assigned (GitHub_M) records — open-source apps such as systemd or ImageMagick, not only registry packages.",
  plugin: "WordPress / Joomla / Drupal plugins and themes.",
  edge: "firewalls, VPN/SSL gateways, routers, load balancers, mail gateways (Fortinet, Ivanti, Citrix, Palo Alto, Cisco, SonicWall, Juniper, F5, …).",
  platform: "Microsoft Windows/Office/Exchange, Apple OSes/Safari, Android/Chrome, Linux kernel, Mozilla, …",
  other: "everything else — mostly enterprise software (Oracle, Adobe, IBM, SAP, Atlassian, SolarWinds, Apache) plus many small PHP web apps (VulDB-assigned).",
};
const ORIGIN_SHORT = { supplychain: "open-source projects", plugin: "CMS plugins", edge: "edge devices", platform: "platforms", other: "enterprise & other software" };
const oShort = (id, OL) => ORIGIN_SHORT[id] || lcFirst(OL(id));
function originList(core) {
  const l = core && Array.isArray(core.origins) ? core.origins.filter((o) => o && o.id) : null;
  return l && l.length ? l : null;
}
const originLabel = (core) => {
  const m = {};
  for (const o of originList(core) || []) m[o.id] = o.label || o.id;
  return (id) => m[id] || ORIGIN_FALLBACK[id] || id;
};
/* AI relations (multi-label tags; Part 2). Ids fixed by build.py AI_RELATIONS. */
/* AI relations stay in the AI blue family plus greys, so no relation shares a
 * colour with an origin (teal/mauve/plum/sage) or a severity (warm) */
const REL_COLORS = {
  agent: P.navy,
  product: P.blue,
  feature: P.neutral,
  weakness: P.steel,
  compute: P.sky,
  found: P.grey,
};
const REL_FALLBACK = {
  agent: "MCP servers & AI agents", product: "AI software & ML libraries",
  feature: "AI assistants in mainstream software", weakness: "AI-specific weakness",
  compute: "AI compute: GPU & accelerator stack", found: "Found by AI tools or AI labs",
};
const REL_SHORT = { agent: "MCP & agents", product: "AI software", feature: "AI feature", weakness: "AI weakness", compute: "AI compute", found: "found by AI" };
const REL_RULES = {
  agent: "MCP servers and clients, agent frameworks and coding agents (OpenClaw, Claude Code, Cline, CrewAI …).",
  product: "AI applications, LLM gateways, inference servers, MLOps platforms, model-file tooling and ML libraries (Langflow, LiteLLM, vLLM, MLflow, TensorFlow …).",
  feature: "AI assistants shipped inside mainstream products — Microsoft/GitHub Copilot, Gemini in Google products, Apple Intelligence, Einstein, Now Assist, GitLab Duo …",
  weakness: "a weakness that only exists because a model is in the loop: prompt injection, jailbreaks, system-prompt leaks, model poisoning, unsafe model loading, unhandled LLM output (CWE-1426/1427).",
  compute: "the GPU / accelerator stack AI runs on: NVIDIA GPU drivers, CUDA, vGPU, DGX/HGX, Container Toolkit, BlueField; AMD Instinct/ROCm; Intel Gaudi.",
  found: "the CVE record credits an AI discovery tool, model or lab (Google Big Sleep, XBOW, AISLE, depthfirst, ZeroPath, Claude/Anthropic, OpenAI …) or says an AI found it. Counted across all CVEs as a discovery trend; on its own it does not make a CVE AI-related.",
};
function relList(core, meta) {
  const l = (core && Array.isArray(core.relations) && core.relations) || (meta && Array.isArray(meta.relations) && meta.relations) || null;
  return l ? l.filter((x) => x && x.id) : null;
}
function makeRelLabel(rels) {
  const m = {};
  for (const r of rels || []) m[r.id] = r.label || r.id;
  return (id) => m[id] || REL_FALLBACK[id] || id;
}
const rShort = (id) => REL_SHORT[id] || id;
/* relation tags (swatch + short name) for a table cell */
function relTags(rels, RL) {
  const wrap = h("span", { class: "reltags" });
  for (const id of rels || []) {
    const sw = h("span", { class: "swatch", "aria-hidden": "true" });
    sw.style.background = REL_COLORS[id] || OTHER_COLOR;
    wrap.append(h("span", { class: "reltag", title: RL ? RL(id) : id }, sw, document.createTextNode(rShort(id))));
  }
  return wrap;
}
function originCell(id, OL) {
  const oc = h("td", { class: "nowrap" });
  if (!id) { oc.textContent = "—"; return oc; }
  const sw = h("span", { class: "swatch", "aria-hidden": "true" });
  sw.style.background = ORIGIN_COLORS[id] || OTHER_COLOR;
  oc.append(sw, document.createTextNode(oShort(id, OL)));
  oc.title = OL(id);
  return oc;
}
const sumObj = (o) => Object.values(o || {}).reduce((a, b) => a + (fin(b) ? b : 0), 0);

/* facts for the society-wide story; every field optional */
function computeSurgeFacts(ctx, F) {
  const { core, kev, mal } = ctx;
  const md = F.asOf.slice(5);
  const S = {};
  try {
    if (Array.isArray(core.days) && Array.isArray(core.dayCounts)) {
      let cur = 0, prev = 0, prevFull = 0;
      core.days.forEach((d, i) => {
        const c = core.dayCounts[i] || 0, y = d.slice(0, 4);
        if (y === F.year && d.slice(5) <= md) cur += c;
        if (y === F.prevYear) { prevFull += c; if (d.slice(5) <= md) prev += c; }
      });
      if (cur) S.total = { cur, prev, prevFull };
    }
  } catch (e) { /* skip */ }
  try {
    const om = core.originMonths;
    if (om && Array.isArray(core.months) && originList(core)) {
      const ytd = {};
      for (const [id, arr] of Object.entries(om)) {
        if (!Array.isArray(arr)) continue;
        ytd[id] = core.months.reduce((s, m, i) => s + (m.startsWith(F.year) ? arr[i] || 0 : 0), 0);
      }
      const tot = sumObj(ytd);
      if (tot) S.originYtd = { by: ytd, total: tot };
    }
  } catch (e) { /* skip */ }
  try {
    if (kev && Array.isArray(kev.entries)) {
      const ents = kev.entries.filter((e) => e && e.added);
      const cur = ents.filter((e) => e.added.startsWith(F.year));
      const prevSame = ents.filter((e) => e.added.startsWith(F.prevYear) && e.added.slice(5) <= md).length;
      const by = kev.byYear && kev.byYear[F.year];
      let origin = by && by.origin && sumObj(by.origin) ? by.origin : null;
      if (!origin && cur.length && cur.every((e) => e.origin)) {
        origin = {};
        for (const e of cur) origin[e.origin] = (origin[e.origin] || 0) + 1;
      }
      const hasZd = ents.some((e) => typeof e.zeroDay === "boolean");
      let zd = null, zdPrevSame = null;
      if (hasZd) {
        // zero-day proxy, bucketed by CVE publication year (YTD-aware compare)
        zd = ents.filter((e) => e.zeroDay && String(e.published || "").startsWith(F.year)).length;
        zdPrevSame = ents.filter((e) => e.zeroDay && String(e.published || "").startsWith(F.prevYear) && String(e.published).slice(5) <= md).length;
      } else if (by && fin(by.zeroDay)) zd = by.zeroDay;
      S.kev = { cur: cur.length, prevSame, origin, zd, zdPrevSame, aiCur: cur.filter((e) => e.ai).length, total: ents.length };
    }
  } catch (e) { /* skip */ }
  try {
    if (mal && mal.byYear) {
      let n = 0;
      for (const eco of Object.values(mal.byYear)) n += fin(eco && eco[F.year]) ? eco[F.year] : 0;
      S.malYtd = n;
    }
  } catch (e) { /* skip */ }
  if (S.originYtd && fin(S.originYtd.by.supplychain)) S.supply = { n: S.originYtd.by.supplychain, of: S.originYtd.total };
  // AI-related share of this year's CVEs (Part 2)
  if (F.ytd && S.total) S.aiShare = { n: F.ytd.cur, mcp: fin(F.mcpYtd) ? F.mcpYtd : null, of: S.total.cur };
  // HIGH/CRITICAL share: this year vs last year (record CVSS, rated only)
  try {
    // without the Linux kernel CNA when available (it rates few CVEs, nearly all HIGH)
    const la = core.landscape && core.landscape.all;
    const sy = la && (la.sevYearsXLinux || la.sevYears);
    const share = (o) => { if (!o) return null; const r = SEV_KEYS.reduce((t, k) => t + (o[k] || 0), 0); return r ? ((o.CRITICAL || 0) + (o.HIGH || 0)) / r : null; };
    if (sy) S.hc = { cur: share(sy[F.year]), prev: share(sy[F.prevYear]), crit: sy[F.year] ? sy[F.year].CRITICAL || 0 : 0 };
  } catch (e) { /* skip */ }
  // in-the-wild zero-days (Project Zero) this year
  try {
    const z = ctx.zd;
    if (z && z.byYear) S.p0 = { cur: z.byYear[F.year] || 0, prev: z.byYear[F.prevYear] || 0, total: z.total };
  } catch (e) { /* skip */ }
  return S;
}

/* ================= TIER 1: executive summary ================= */
const fmtX = (x) => (x >= 10 ? String(Math.round(x)) : x.toFixed(1));
/* "IBM Langflow" / "Langflow Langflow" → "Langflow"; "BerriAI LiteLLM" → "LiteLLM" */
function shortProduct(p) {
  if (!p) return null;
  const toks = String(p).trim().split(/[\s/]+/).filter(Boolean);
  return toks.length ? toks[toks.length - 1] : null;
}
/* "Strapi Strapi" → "Strapi", "Zammad GmbH Zammad" → "Zammad",
 * "Ray-Project Ray" → "Ray", "Ahsay AhsayCBS" → "AhsayCBS": drop a vendor
 * prefix the product name repeats. "Microsoft Windows" stays as it is. */
const normTok = (t) => t.toLowerCase().replace(/[^a-z0-9]/g, "");
function tidyProduct(p) {
  if (!p) return p;
  const toks = String(p).trim().split(/\s+/);
  // the vendor is at most three words, and only its first word may repeat
  const first = toks[0].split(/[-_.]/).map(normTok).filter(Boolean)[0] || "";
  for (let k = 1; k < Math.min(toks.length, 4); k++) {
    if (/,$/.test(toks[k - 1]) || /^(and|or|on|of|the|for)$/i.test(toks[k - 1])) break;
    const head = normTok(toks[k]);
    if (head && (head === first || (first.length >= 3 && head.startsWith(first)))) return toks.slice(k).join(" ");
  }
  return String(p);
}
/* Short display name for an AI product: the tidied name, cut at a subtitle
 * ("AI Engine – The Chatbot, AI Framework & MCP for WordPress" → "AI Engine");
 * a one-word vendor prefix is dropped ("langchain-ai langchain" → "langchain"). */
function aiProductName(p) {
  let n = tidyProduct(p);
  if (!n) return null;
  n = n.split(/\s+[–—:|]\s+|\s+-\s+/)[0].trim();
  const toks = n.split(/\s+/);
  if (toks.length >= 2 && /[a-z]-(?:ai|io|labs?|project)$|AI$/.test(toks[0])) n = toks.slice(1).join(" ");
  else if (toks.length >= 3 && /^[a-z0-9]+$/.test(toks[0])) n = toks.slice(1).join(" ");
  if (/wordpress/i.test(p) && !/wordpress/i.test(n)) n += " (WordPress plugin)";
  return n;
}
function kevProducts(F) {
  const m = new Map();
  for (const r of F.kevAi || []) {
    const name = shortProduct(r.product) || r.cve;
    const k = name.toLowerCase();
    const cur = m.get(k) || { name, n: 0, ransom: 0 };
    cur.n += 1; if (r.ransomware) cur.ransom += 1;
    m.set(k, cur);
  }
  return [...m.values()].sort((a, b) => b.n - a.n || a.name.localeCompare(b.name));
}
const listJoin = (a) => (a.length <= 1 ? a.join("") : a.slice(0, -1).join(", ") + " and " + a[a.length - 1]);
/* cut at a word boundary with an ellipsis (the build stores 240 characters) */
const wordClip = (s, n) => { if (!s) return s; if (s.length < n) return s; const cut = s.slice(0, n); const i = cut.lastIndexOf(" "); return (i > n * 0.6 ? cut.slice(0, i) : cut).replace(/[,;:.\s]+$/, "") + "…"; };
const lcFirst = (s) => (/^[A-Z][a-z]/.test(s) ? s[0].toLowerCase() + s.slice(1) : s);
const clean = (s) => (typeof s === "string" && s && !/NaN|undefined|null|Infinity/.test(s) ? s : null);

/* the page's message in three lines — what changed, where the risk is, what to do —
 * each computed from this build (the Brief and cards below carry the evidence) */
function buildBottomLine(ctx, F, S) {
  const host = $("#bottomline");
  if (!host) return;
  const items = [];
  try {
    const yr = ytdRatio(ctx.core), os = ytdRatio(ctx.core, "supplychain");
    if (yr && fin(yr.rx)) items.push(["What changed", `CVE volume ×${fmtX(yr.r)}, ×${fmtX(yr.rx)} without bulk filing${fin(yr.bulkShare) ? ` (${pct(yr.bulkShare)} of the rise is ${BULK_NAMES} filing, not more flaws)` : ""}${os && fin(os.rx) && os.rx >= 2 ? `; open-source component CVEs rose ×${fmtX(os.rx)} even without it` : ""}.`]);
  } catch (e) { /* skip */ }
  try {
    const k = S.kev, OL = originLabel(ctx.core);
    const pubK = ((ctx.kev && ctx.kev.entries) || []).filter((e) => String(e.published || "").startsWith(F.year) && e.origin);
    const yo = (ctx.core.ytd && ctx.core.ytd.origins) || {}, ya = ctx.core.ytd && ctx.core.ytd.all;
    const base = ya ? ya.cur - (ya.bulkCur || 0) : 0, ed = pubK.filter((e) => e.origin === "edge").length;
    const es = yo.edge && base ? (yo.edge.cur - (yo.edge.bulkCur || 0)) / base : null;
    const by = {};
    for (const e of ((ctx.kev && ctx.kev.entries) || []).filter((x) => String(x.added).startsWith(F.year))) by[e.vendor] = (by[e.vendor] || 0) + 1;
    // top 3, plus anyone tied with the third (Apple and Fortinet can share a count)
    const ranked = Object.entries(by).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const cut = ranked.length >= 3 ? ranked[2][1] : 0;
    const top = ranked.filter(([, n], i) => i < 3 || n === cut).slice(0, 5).map(([v]) => v);
    if (k && k.cur && k.prevSame) items.push(["Where the risk is", `CISA KEV additions ${k.cur / k.prevSame >= 1.05 ? `up ${pct(k.cur / k.prevSame - 1)}` : "level"}; ${pubK.length >= 50 && fin(es) ? `${oShort("edge", OL)} are ${pct(ed / pubK.length)} of newly exploited CVEs from ${pct(es, 1)} of new CVEs` : "exploitation is concentrated"}${top.length ? `; ${listJoin(top)} lead the list` : ""}.`]);
  } catch (e) { /* skip */ }
  items.push(["What to do", "Patch what CISA KEV lists first, edge devices within days, and re-scan the whole estate against KEV every week."]);
  if (items.length < 2) { host.remove(); return; }
  for (const [k, v] of items) host.append(h("div", { class: "bl-item" }, h("span", { class: "bl-k", text: k }), h("p", { class: "bl-v", text: clean(v) })));
}
function buildHeadline(ctx, F, S) {
  const el = $("#headline"), sub = $("#subhead");
  const OL = originLabel(ctx.core);
  let head = null;
  try {
    const t = S.total;
    if (t && t.prev) {
      const r = t.cur / t.prev;
      const yr = ytdRatio(ctx.core);
      const ex = yr && yr.rx ? ` (×${fmtX(yr.rx)} without bulk filing by ${BULK_NAMES})` : "";
      head = r >= 1.15 ? `CVE disclosures are up ×${fmtX(r)} on the same period last year${ex}: ${num.format(t.cur)} so far in ${F.year}.`
        : r >= 0.95 ? `CVE disclosures are running level with last year: ${num.format(t.cur)} so far in ${F.year}.`
        : `CVE disclosures are down ${pct(1 - r)} on the same period last year.`;
    } else if (t) head = `${num.format(t.cur)} CVEs published in ${F.year} so far.`;
    // volume alone overstates the change (much of it is reporting): pair it with confirmed exploitation
    const k = S.kev;
    if (head && k && k.cur && k.prevSame) {
      const kr = k.cur / k.prevSame;
      const kt = kr >= 2 ? `up ×${fmtX(kr)}` : kr >= 1.05 ? `up ${pct(kr - 1)}` : kr > 0.95 ? "level" : `down ${pct(1 - kr)}`;
      head = head.replace(/\.$/, `; additions to CISA's exploited list (KEV) are ${kt} (${num.format(k.cur)} vs ${num.format(k.prevSame)}).`);
    }
  } catch (e) { head = null; }
  head = clean(head);
  if (head) el.textContent = head; else el.remove();

  const parts = [];
  const add = (fn) => { try { const s = clean(fn()); if (s) parts.push(s); } catch (e) { /* skip */ } };
  add(() => {
    const k = S.kev;
    if (!k || !k.cur) return null;
    const vs = k.prevSame ? ` (${num.format(k.prevSame)} by this date last year)` : "";
    const zd = fin(k.zd) ? `, ${num.format(k.zd)} of them KEV-listed at disclosure (within a day of publication, a zero-day proxy)` : "";
    return `CISA added ${num.format(k.cur)} vulnerabilities to its Known Exploited Vulnerabilities list this year${vs}${zd}; KEV is a lower bound, scoped to products US federal agencies run.`;
  });
  add(() => {
    const k = S.kev;
    if (!k || !k.cur || !k.origin) return null;
    const ranked = Object.entries(k.origin).sort((a, b) => b[1] - a[1]).slice(0, 3);
    const lead = ranked.reduce((t, [, n]) => t + n, 0);
    return `${listJoin(ranked.map(([id]) => oShort(id, OL)))} account for ${num.format(lead)} of them.`.replace(/^./, (c) => c.toUpperCase());
  });
  add(() => (S.hc && fin(S.hc.cur) ? `${pct(S.hc.cur)} of this year's rated CVEs are HIGH or CRITICAL${fin(S.hc.prev) ? ` (${pct(S.hc.prev)} in ${F.prevYear})` : ""}, excluding the Linux kernel's selective ratings.` : null));
  // the KPI tiles carry these numbers: keep them one tap away, not on screen
  if (parts.length) { sub.textContent = parts.join(" "); sub.classList.add("hint"); } else sub.remove();
}

/* 24-month sparkline as inline SVG (no canvas: tiles stay crisp and light) */
const SVGNS = "http://www.w3.org/2000/svg";
function sparkline(vals, cls) {
  const W = 120, H = 34, n = vals.length, max = Math.max(1, ...vals);
  const pts = vals.map((v, i) => [(i / (n - 1)) * W, H - 3 - (v / max) * (H - 6)]);
  const line = pts.map(([x, y], i) => (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1)).join(" ");
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("class", "spark" + (cls ? " " + cls : ""));
  svg.setAttribute("aria-hidden", "true");
  const area = document.createElementNS(SVGNS, "path");
  area.setAttribute("d", `${line} L${W} ${H} L0 ${H} Z`);
  area.setAttribute("class", "spark-area");
  const path = document.createElementNS(SVGNS, "path");
  path.setAttribute("d", line);
  path.setAttribute("class", "spark-line");
  path.setAttribute("vector-effect", "non-scaling-stroke");
  svg.append(area, path);
  return svg;
}
function kpiTiles(wrap, tiles, emptyMsg) {
  if (!tiles.length) { note(wrap, emptyMsg); return; }
  for (const x of tiles) {
    const delta = x.delta ? h("span", { class: "delta" + (x.delta.up ? " up" : " down"), text: (x.delta.up ? "▲ " : "▼ ") + x.delta.text, title: x.delta.title || null }) : null;
    const spark = x.spark && x.spark.vals.length >= 6 && x.spark.vals.some((v) => v > 0)
      ? h("div", { class: "kspark", title: x.spark.title || null }, sparkline(x.spark.vals, x.cls)) : null;
    wrap.append(h("div", { class: "kpi" + (spark ? " has-spark" : "") },
      h("div", { class: "k", text: x.k }),
      h("div", { class: "vrow" }, h("span", { class: "v" + (x.cls ? " " + x.cls : ""), text: x.v }), delta),
      spark,
      x.d ? h("div", { class: "d", text: x.d }) : null,
      x.src ? h("div", { class: "ksrc", text: x.src }) : null));
  }
}
/* the last n complete months, oldest first */
function lastMonths(F, n) {
  const end = ymAdd(F.asOf.slice(0, 7), -1);
  return monthRange(ymAdd(end, -(n - 1)), end);
}
function monthSeries(months, allMonths, arr) {
  const idx = new Map((allMonths || []).map((m, i) => [m, i]));
  return months.map((m) => (idx.has(m) && fin(arr[idx.get(m)]) ? arr[idx.get(m)] : 0));
}
function countByMonth(months, items, keyFn) {
  const c = Object.fromEntries(months.map((m) => [m, 0]));
  for (const it of items || []) { const m = String(keyFn(it) || "").slice(0, 7); if (m in c) c[m] += 1; }
  return months.map((m) => c[m]);
}
/* Change badge vs the same period last year. Below a base of 10 a ratio
 * is noise ("×10" from 1 to 10), so the badge shows both counts instead. */
const growthDelta = (cur, prev, prevYear) => (prev > 0 && fin(cur)
  ? { up: cur >= prev, title: `vs the same period of ${prevYear}`,
      text: prev < 10 ? `${num.format(cur)} vs ${num.format(prev)}` : cur / prev >= 1.995 ? `×${fmtX(cur / prev)}` : `${Math.round(Math.abs(100 * (cur / prev - 1)))}%` }
  : null);
const tileSrc = (ctx, name) => `${name} · ${String((ctx.core && ctx.core.generatedAt) || "").slice(0, 10)} · ${SITE}`;
function buildKpis(ctx, F, S) {
  const tiles = [];
  const M = lastMonths(F, 24);
  const sparkTitle = "monthly, last 24 complete months";
  const ents = (ctx.kev && ctx.kev.entries) || [];
  const t = S.total;
  if (t) tiles.push({ k: `CVEs published ${F.year} YTD`, v: num.format(t.cur), delta: growthDelta(t.cur, t.prev, F.prevYear),
    spark: { vals: monthSeries(M, ctx.core.months, ctx.core.counts || []), title: sparkTitle },
    d: t.prev ? `${num.format(t.prev)} by this date in ${F.prevYear}` : `${num.format(t.prevFull)} in all of ${F.prevYear}` });
  const k = S.kev;
  if (k) tiles.push({ k: `Added to CISA KEV ${F.year}`, v: num.format(k.cur), cls: "warn", delta: growthDelta(k.cur, k.prevSame, F.prevYear),
    spark: { vals: countByMonth(M, ents, (e) => e.added), title: sparkTitle },
    d: k.prevSame ? `${num.format(k.prevSame)} by this date in ${F.prevYear}` : "added to CISA KEV this year" });
  if (k && fin(k.zd)) {
    const zb = ctx.zd && ctx.zd.byYear;
    // no trend arrow: the proxy also rises when CISA lists faster (its deadlines tightened in 2026)
    tiles.push({ k: `KEV-listed at disclosure ${F.year}`, v: num.format(k.zd), cls: "warn",
      spark: { vals: countByMonth(M, ents.filter((e) => e.zeroDay), (e) => e.published), title: sparkTitle },
      d: [fin(k.zdPrevSame) ? `${num.format(k.zdPrevSame)} by this date in ${F.prevYear}` : null,
        // why two zero-day numbers: Project Zero confirms a curated set of true zero-days; this
        // proxy also counts flaws attacked as soon as they were disclosed, in any product
        zb && fin(zb[F.year]) ? `broader than Project Zero: ${num.format(zb[F.year])} confirmed zero-days (${num.format(zb[F.prevYear] || 0)} in all of ${F.prevYear}); this proxy also counts flaws attacked as soon as they were disclosed` : null].filter(Boolean).join(" · ") });
  }
  if (S.supply || fin(S.malYtd)) {
    const om = ctx.core.originMonths && ctx.core.originMonths.supplychain;
    // the build's one YTD window, the same comparison as the CVEs-per-year chart title
    const ym = ytdRatio(ctx.core, "supplychain");
    const delta = ym ? growthDelta(ym.cur, ym.prev, F.prevYear) : null;
    if (delta) delta.title = `1 Jan–${fmtDay(F.asOf).replace(/, \d+$/, "")}, ${F.year} vs ${F.prevYear}`;
    tiles.push(S.supply
      // "component", not "supply chain": these are flaws in open-source code; supply-chain
      // attacks (malicious packages) are counted separately in the same tile
      ? { k: "Open-source component CVEs", v: num.format(ym ? ym.cur : S.supply.n), delta,
          spark: om ? { vals: monthSeries(M, ctx.core.months, om), title: sparkTitle } : null,
          d: (ym && ym.cur && ym.bulkShare != null ? `${pct((ctx.core.ytd.origins.supplychain.bulkCur) / ym.cur)} filed by ${BULK_NAMES}${fin(ym.rx) ? `; ×${fmtX(ym.rx)} without them` : ""}` : `${F.year} YTD`)
            + (fin(S.malYtd) && S.malYtd ? ` · plus ${num.format(S.malYtd)} malicious packages` : "") }
      : { k: "Malicious packages", v: num.format(S.malYtd), d: `${F.year} YTD, OSV MAL advisories` });
  }
  const SRC = [tileSrc(ctx, "CVE List"), tileSrc(ctx, "CISA KEV"), tileSrc(ctx, "CISA KEV"), tileSrc(ctx, "CVE List + OSV")];
  tiles.forEach((t, i) => { t.src = t.src || SRC[i] || tileSrc(ctx, "CVE List"); });
  kpiTiles($("#kpis"), tiles, "Key indicators are not available for this data build.");
  // the daily view: last 30 days of confirmed exploitation vs the 30 before
  try {
    const t = new Date(F.asOf + "T00:00:00Z"), iso = (d) => new Date(t - d * 86400e3).toISOString().slice(0, 10);
    const a30 = iso(30), a60 = iso(60);
    const l30 = ents.filter((e) => e.added > a30), p30 = ents.filter((e) => e.added > a60 && e.added <= a30);
    if (l30.length || p30.length) {
      const edge = l30.filter((e) => e.origin === "edge").length, rw = l30.filter((e) => e.ransomware).length;
      $("#kpis").after(h("p", { class: "last30", text: `Last 30 days: ${num.format(l30.length)} vulnerabilities newly confirmed exploited (${num.format(p30.length)} in the 30 days before), ${num.format(edge)} on edge devices, ${num.format(rw)} flagged ransomware so far · CISA KEV` }));
    }
  } catch (e) { /* skip */ }
}

/* ================= signal vs noise (one cohort) ================= */
/* All stages count CVEs published in the same trailing 365-day window, so
 * they are shares of one base (not a funnel: an exploited CVE can be MEDIUM). */
function signalStages(ctx) {
  const L = ctx.core.landscape && ctx.core.landscape.all;
  if (!L || !L.window || !L.window.n) return null;
  const [from, to] = L.window.cur;
  const sw = L.sevWindow || null;
  const dist = ctx.epss && ctx.epss.dist && ctx.epss.dist.all;
  const kev = ((ctx.kev && ctx.kev.entries) || []).filter((e) => e.published && e.published >= from && e.published <= to);
  // advance warning: EPSS the day BEFORE CISA listed each CVE (today's score
  // already reflects the exploitation). No score that day = no warning.
  const pr = (ctx.epssPrior && ctx.epssPrior.scores) || null;
  const scored = pr ? kev.filter((e) => pr[e.cve]) : [];
  const caught = scored.filter((e) => fin(pr[e.cve].epss) && pr[e.cve].epss >= 0.1).length;
  const unscored = scored.filter((e) => !fin(pr[e.cve].epss)).length;
  return {
    recall: scored.length >= 20 ? { caught, of: scored.length, unscored } : null,
    from, to, base: L.window.n,
    hc: sw ? (sw.CRITICAL || 0) + (sw.HIGH || 0) : null,
    epss: dist && fin(dist.ge10) ? dist.ge10 : null,
    kev: ctx.kev && ctx.kev.entries ? kev.length : null,
    // KEV is right-censored for recent CVEs: the year-earlier cohort, with 12+ months
    // of follow-up, gives the settled rate ("1 in N so far" alone understates it)
    kevFull: (() => {
      const [a, b] = L.window.prev || [], n = L.window.prevN;
      if (!a || !n) return null;
      const k = ((ctx.kev && ctx.kev.entries) || []).filter((e) => e.published && e.published >= a && e.published <= b).length;
      return k >= 20 ? { k, n } : null;
    })(),
  };
}
const oneIn = (n, base) => (n > 0 ? `1 in ${num.format(Math.round(base / n))}` : "none");
function buildSignal(ctx) {
  const el = $("#signal-bars");
  const st = signalStages(ctx);
  if (!st) { $("#signal").remove(); return; }
  const rows = [
    { label: "Published", sub: "all CVEs", n: st.base, cls: "all" },
    st.hc != null && { label: "Rated HIGH or CRITICAL", sub: "share of all published CVEs; unrated counted as not", n: st.hc, cls: "hc" },
    st.epss != null && { label: "Elevated exploit probability", sub: "EPSS ≥ 10% (30-day model estimate)", n: st.epss, cls: "epss" },
    st.kev != null && { label: "Confirmed exploited", sub: "in CISA KEV so far (a lower bound)", n: st.kev, cls: "kev" },
  ].filter(Boolean);
  const list = h("div", { class: "sig", role: "list" });
  for (const r of rows) {
    const fill = h("span", { class: "sig-fill " + r.cls });
    fill.style.width = Math.max(0.35, (100 * r.n) / st.base).toFixed(2) + "%";
    const share = r.cls === "all" ? "" : r.n / st.base >= 0.1 ? pct(r.n / st.base) : oneIn(r.n, st.base);
    list.append(h("div", { class: "sig-row", role: "listitem", "aria-label": `${r.label}: ${num.format(r.n)}${share ? " (" + share + ")" : ""}` },
      h("div", { class: "sig-lab" }, h("span", { class: "sig-name", text: r.label }), h("span", { class: "sig-sub", text: r.sub })),
      h("span", { class: "sig-bar" }, fill),
      h("span", { class: "sig-n" }, h("b", { text: num.format(r.n) }), share ? h("span", { class: "sig-share", text: share }) : null)));
  }
  el.append(list);
  const ratio = st.hc && st.kev ? st.hc / st.kev : null;
  fig(el, {
    titleEl: "#h-signal",
    title: st.hc && st.kev ? `Last 12 months: severity flags ${pct(st.hc / st.base)} of new CVEs; CISA KEV lists ${oneIn(st.kev, st.base)} so far${st.kevFull ? ` (${oneIn(st.kevFull.k, st.kevFull.n)} for the year before, fully followed)` : ""}` : null,
    subEl: "#signal-hint",
    sub: `Every bar counts the same CVEs: the ${num.format(st.base)} published from ${fmtDay(st.from)} to ${fmtDay(st.to)}. Bars are shares of that one base, not a funnel: an exploited CVE can be rated MEDIUM. EPSS is a model estimate; KEV is confirmed exploitation and lags. The severity card further down shows a higher share because it counts only rated CVEs, per calendar year, and leaves out the Linux kernel's selective ratings.`,
    so: ratio ? `A severity-first queue is about ${num.format(Math.round(ratio))} times larger than the confirmed-exploited list so far${st.kevFull ? `, and still about ${num.format(Math.round(st.hc / (st.base * st.kevFull.k / st.kevFull.n)))} times larger at the fully followed rate` : ""}. Patch KEV first, then rank the rest by EPSS, severity and exposure`
      + (st.recall ? `. EPSS is not an early warning: the day before CISA listed them, only ${num.format(st.recall.caught)} of these ${num.format(st.recall.of)} exploited CVEs (${pct(st.recall.caught / st.recall.of)}) had an EPSS of 10% or more, and ${pct(st.recall.unscored / st.recall.of)} had no score yet.` : ".") : null,
    src: srcLine(ctx, ["cve", "epss", "kev"]),
  });
}

/* ================= executive brief: how to adjust ================= */
/* Five programme changes, each backed by this build's numbers. An item only
 * renders when its evidence exists, so the list never states a bare opinion. */
function buildBrief(ctx, F, S) {
  const ol = $("#brief-list");
  const items = [];
  const add = (fn) => { try { const r = fn(); if (r && clean(r.why)) items.push(r); } catch (e) { /* skip */ } };
  const OL = originLabel(ctx.core);
  // 1. find the signal: exploitation first
  add(() => {
    const st = signalStages(ctx);
    if (!st || !st.hc || !st.kev) return null;
    return { act: "Rank the patch queue by exploitation, not by severity.", href: "#signal",
      why: `In the last 12 months ${pct(st.hc / st.base)} of new CVEs were rated HIGH or CRITICAL, but only ${oneIn(st.kev, st.base)} is in CISA KEV so far${st.kevFull ? ` (${oneIn(st.kevFull.k, st.kevFull.n)} once fully followed up, judging by the year before)` : ""}${st.epss ? `, and ${oneIn(st.epss, st.base)} has an elevated exploit probability (EPSS ≥ 10%)` : ""}. Patch KEV first, then rank the rest by EPSS, severity and exposure.` };
  });
  add(() => {
    const ents = (ctx.kev && ctx.kev.entries || []).filter((e) => e && String(e.added).startsWith(F.year) && fin(e.daysToKev));
    if (ents.length < 10) return null;
    const week = ents.filter((e) => e.daysToKev <= 7).length;
    const edge = S.kev && S.kev.origin && S.kev.origin.edge;
    const tail = fin(edge) && edge ? ` ${oShort("edge", OL).replace(/^./, (c) => c.toUpperCase())} alone account for ${num.format(edge)}.` : "";
    const ec = ttkCohort(ctx, "edge");
    const edgeTxt = ec && ec.full && ec.full.n >= 15 ? `; edge devices ${pct(ec.full.wk / ec.full.n)} (median ${daysText(ec.full.median)})` : "";
    // one finding + one action; the like-for-like trend lives on the time-to-listing card
    return { act: "Patch internet-facing systems in days, not monthly cycles.", href: "#speed",
      why: (() => { const c = ttkCohort(ctx); return c && c.full && c.full.n >= 20 ? `${pct(c.full.wk / c.full.n)} of exploited CVEs reach CISA KEV within a week of publication (median ${daysText(c.full.median)})${edgeTxt}.` : `${pct(week / ents.length)} of this year's KEV additions came within a week of the CVE's publication.${tail}`; })()
        + " Keep an emergency-change path and take management interfaces off the internet."
        + (() => { const dl = kevDeadlines(ctx, F); return dl ? ` Board metric: KEV entries fixed within CISA's deadline (median ${daysText(dl.median)} in the last 90 days).` : ""; })() };
  });
  add(() => {
    const o = oldKev(ctx, F);
    if (!o || !o.y3) return null;
    return { act: "Re-check the whole estate against KEV every week, not just new advisories.", href: "#speed",
      why: `${pct(o.y1 / o.n)} of ${F.year}'s KEV additions are CVEs published more than a year earlier, and ${num.format(o.y3)} (${pct(o.y3 / o.n, 1)}) are over three years old${o.oldestYear ? `, back to ${o.oldestYear}` : ""}${o.prods.length ? ` (${listJoin(o.prods)})` : ""}. Scan every asset against KEV weekly and set retirement dates for end-of-life systems you cannot patch.` };
  });
  add(() => {
    const t = S.total;
    if (!t || !t.prev) return null;
    const doy = Math.max(1, Math.round(daysBetween(F.year + "-01-01", F.asOf) + 1));
    return { act: "Size for the volume: automate intake and triage.", href: "#volume",
      why: (() => {
        // split the intake: bulk filers' records still need triage, but they are not the same growth
        const yr = ytdRatio(ctx.core), day = (n) => num.format(Math.round(n / doy));
        const split = yr && yr.rx ? ` (×${fmtX(yr.rx)} without bulk filing by ${BULK_NAMES})` : "";
        const perDay = yr && yr.rx ? `about ${day(t.cur)} a day, ${day(t.cur - yr.xcur)} of them from those two filers` : `about ${day(t.cur)} a day`;
        return `${num.format(t.cur)} CVEs so far in ${F.year}, ×${fmtX(t.cur / t.prev)} the same period of ${F.prevYear}${split}: ${perDay}. Manual review of every advisory does not scale.`;
      })() };
  });
  if (!items.length) { $("#brief").remove(); return; }
  for (const it of items) {
    ol.append(h("li", null,
      h("p", { class: "act" }, h("a", { href: it.href, text: it.act })),
      h("p", { class: "why", text: it.why }),
      null));
  }
}

/* the CNA whose filings grew most (last 12 months vs the 12 before) — the
 * honest "who files moves the curve" caveat under the hero chart */
function cnaSurge(L, min) {
  const top = (L && L.cnaTop) || [];
  let best = null;
  for (const r of top) if (r.n - r.prev > (best ? best.n - best.prev : 0)) best = r;
  return best && best.n - best.prev >= (min || 1000) ? best : null;
}

/* hero: all CVEs per year since 2018, stacked by origin (AI/MCP on top) */
function buildHeroChart(ctx, F) {
  const el = $("#chart-hero");
  const core = ctx.core;
  const OL = originLabel(core);
  const oy = core.originYears;
  const origins = originList(core);
  let years, groups;
  if (oy && origins) {
    const ys = new Set();
    for (const o of origins) for (const y of Object.keys(oy[o.id] || {})) if (/^\d{4}$/.test(y) && y >= "2018") ys.add(y);
    years = [...ys].sort();
    groups = [...origins].reverse().filter((o) => oy[o.id])
      .map((o) => ({ label: OL(o.id), color: ORIGIN_COLORS[o.id] || OTHER_COLOR, data: years.map((y) => oy[o.id][y] || 0) }));
  } else if (Array.isArray(core.months) && Array.isArray(core.counts)) {
    const all = {};
    core.months.forEach((m, i) => { const y = m.slice(0, 4); if (y >= "2018") all[y] = (all[y] || 0) + (core.counts[i] || 0); });
    years = Object.keys(all).sort();
    groups = [{ label: "all CVEs", color: OTHER_COLOR, data: years.map((y) => all[y]) }];
  }
  if (!years || !years.length || !groups.length) { note(el, "Yearly CVE counts are not available."); return; }
  const partial = years[years.length - 1] === F.year;
  const yLab = (v) => String(v) + (partial && String(v) === F.year ? "\nYTD" : "");
  const totals = years.map((_, i) => groups.reduce((s, g) => s + (g.data[i] || 0), 0));
  stackedBars(el, {
    xs: years.map(Number), groups, height: 165, time: false, xLabel: "year", yLabel: "CVEs per year",
    ariaLabel: `Published CVEs per year since 2018 stacked by origin${partial ? `; ${F.year} is year-to-date` : ""}`,
    xValues: tick(yLab), xIncrs: [1, 2, 5], xSpace: 34, xFmt: yLab, barMax: 64,
    draw: partial ? yearNotes({ [F.year]: `${F.year} = ${partialLabel(F)}` }, false) : null,
  });
  // honest caption: part of the surge is who files, not more vulnerable code
  const noteEl = $("#hero-note");
  const L = core.landscape && core.landscape.all;
  const b = cnaSurge(L);
  const s = b ? clean(`Read the surge with care: part of it is who files. ${prettyCna(b.id)} assigned ${num.format(b.n)} CVEs in the last 12 months vs ${num.format(b.prev)} in the 12 before — new filers and bulk assignment raise counts without any change in the software.`) : null;
  if (s) noteEl.textContent = s; else noteEl.remove();
}

/* KEV additions this year by origin, as labelled horizontal bars (DOM) */
function hbars(el, rows, opts) {
  const max = Math.max(1, ...rows.map((r) => r.n));
  const list = h("div", { class: "hbars", role: "list" });
  for (const r of rows) {
    const fill = h("span", { class: "hb-fill" });
    fill.style.width = ((100 * r.n) / max).toFixed(2) + "%";
    fill.style.background = r.color;
    list.append(h("div", { class: "hb-row" + (r.hi ? " hi" : ""), role: "listitem", "aria-label": `${r.label}: ${r.n}` },
      h("span", { class: "hb-lab", text: r.label, title: r.label }),
      h("span", { class: "hb-bar" }, fill),
      h("span", { class: "hb-n", text: r.txt || num.format(r.n) + (opts && opts.of ? ` · ${pct(r.n / opts.of)}` : "") })));
  }
  el.append(list);
}
function buildWhere(ctx, F, S) {
  const el = $("#where-bars");
  const k = S.kev;
  if (!k) { note(el, "CISA KEV data is not available."); return; }
  if (!k.cur) { note(el, `No KEV additions in ${F.year} yet.`); return; }
  const OL = originLabel(ctx.core);
  const hint = $("#where-hint");
  // the same cohort as the title: CVEs PUBLISHED this year that CISA has listed, against
  // each origin's share of all new CVEs (without bulk filers) — older CVEs added this year are left out
  const pubK = ((ctx.kev && ctx.kev.entries) || []).filter((e) => String(e.published || "").startsWith(F.year) && e.origin);
  const yo = (ctx.core.ytd && ctx.core.ytd.origins) || {}, ya = ctx.core.ytd && ctx.core.ytd.all;
  const baseN = ya ? ya.cur - (ya.bulkCur || 0) : 0;
  if (pubK.length >= 20 && baseN) {
    const by = {};
    for (const e of pubK) by[e.origin] = (by[e.origin] || 0) + 1;
    const order = (originList(ctx.core) || Object.keys(ORIGIN_FALLBACK).map((id) => ({ id }))).map((o) => o.id);
    const rows = order.filter((id) => by[id]).map((id) => {
      const cs = yo[id] ? (yo[id].cur - (yo[id].bulkCur || 0)) / baseN : null;
      return { label: OL(id), n: by[id], color: ORIGIN_COLORS[id] || OTHER_COLOR,
        txt: `${num.format(by[id])} · ${pct(by[id] / pubK.length)}${fin(cs) ? ` (${pct(cs, 1)} of new CVEs)` : ""}` };
    }).sort((a, b) => b.n - a.n);
    hbars(el, rows);
    const older = k.cur - ((ctx.kev.entries || []).filter((e) => String(e.added).startsWith(F.year) && String(e.published || "").startsWith(F.year)).length);
    if (hint) hint.textContent = `The ${num.format(pubK.length)} CVEs published in ${F.year} that CISA has listed as exploited, by origin; text = count · share of them (share of all new CVEs, without bulk filers).${older > 0 ? ` The ${num.format(older)} older CVEs CISA added this year are left out.` : ""}`;
  } else if (k.origin) {
    const order = (originList(ctx.core) || Object.keys(ORIGIN_FALLBACK).map((id) => ({ id }))).map((o) => o.id);
    const rows = order.filter((id) => fin(k.origin[id])).map((id) => ({ label: OL(id), n: k.origin[id], color: ORIGIN_COLORS[id] || OTHER_COLOR }))
      .sort((a, b) => b.n - a.n);
    hbars(el, rows, { of: k.cur });
    if (hint) hint.textContent = `The ${num.format(k.cur)} vulnerabilities CISA added to its Known Exploited catalog in ${F.year}, by origin.`;
  } else {
    note(el, "Per-origin classification of KEV entries is not in this data build.");
  }
}

/* ================= TIER 2: zero-day proxy ================= */
function buildZeroDay(ctx) {
  const el = $("#chart-zeroday");
  const kev = ctx.kev;
  const zdj = ctx.zd;
  let by = null;
  if (kev && kev.byYear) {
    by = {};
    for (const [y, b] of Object.entries(kev.byYear)) if (b && fin(b.zeroDay)) by[y] = b.zeroDay;
  } else if (kev && Array.isArray(kev.entries) && kev.entries.some((e) => typeof e.zeroDay === "boolean")) {
    by = {};
    for (const e of kev.entries) if (e.zeroDay && e.published) { const y = e.published.slice(0, 4); by[y] = (by[y] || 0) + 1; }
  }
  const years = Object.keys(by || {}).filter((y) => /^\d{4}$/.test(y) && y >= "2022").sort();
  if (!years.length) { note(el, "The zero-day proxy needs CVE publication dates for every KEV entry — not in this data build."); }
  else {
    const cur = ctx.F.year;
    const yLab = (v) => String(v) + (String(v) === cur ? "\nYTD" : "");
    stackedBars(el, {
      xs: years.map(Number), groups: [{ label: "KEV-listed at disclosure", color: P.red, data: years.map((y) => by[y]) }],
      height: 200, time: false, xLabel: "publication year", yLabel: "CVEs per year", legend: false,
      ariaLabel: "KEV entries listed at disclosure (added within one day of publication), per CVE publication year",
      xValues: tick(yLab), xIncrs: [1, 2, 5], xSpace: 34, xFmt: yLab, barMax: 50,
    });
  }
  const hint = $("#zd-hint");
  if (hint && zdj && zdj.byYear && fin(zdj.byYear[ctx.F.prevYear])) {
    hint.textContent += ` For comparison, ${zdj.source || "Project Zero"} counted ${num.format(zdj.byYear[ctx.F.prevYear])} in-the-wild zero-days in ${ctx.F.prevYear}.`;
  }
  // recent zero-days table
  const tbody = $("#tbl-zd tbody");
  const OL = originLabel(ctx.core);
  let rows = [];
  if (zdj && Array.isArray(zdj.recent) && zdj.recent.length) {
    rows = zdj.recent.map((r) => ({ cve: r.cve, product: tidyProduct([r.vendor, r.product].filter(Boolean).join(" ")), origin: r.origin, date: r.date }));
    $("#zd-list-hint").textContent = `Latest in-the-wild zero-days from ${zdj.source || "the zero-day tracker"}.`;
  } else if (kev && Array.isArray(kev.entries)) {
    rows = kev.entries.filter((e) => e && e.zeroDay).sort((a, b) => String(b.added).localeCompare(String(a.added)))
      .map((e) => ({ cve: e.cve, product: e.product, origin: e.origin, date: e.added }));
    $("#zd-list-hint").textContent = "Latest KEV entries added within one day of their CVE's publication (date = added to KEV).";
  }
  rows = rows.filter((r) => r.cve).slice(0, 10);
  if (!rows.length) { emptyRow(tbody, 4, "No zero-day list in this data build."); return; }
  for (const r of rows) {
    const oc = h("td", { class: "nowrap" });
    if (r.origin) { const sw = h("span", { class: "swatch", "aria-hidden": "true" }); sw.style.background = ORIGIN_COLORS[r.origin] || OTHER_COLOR; oc.append(sw, document.createTextNode(oShort(r.origin, OL))); oc.title = OL(r.origin); }
    else oc.textContent = "—";
    tbody.append(h("tr", null, h("td", { class: "nowrap" }, cveLink(r.cve)), h("td", { text: tidyProduct(r.product) || "—" }), oc, h("td", { class: "nowrap", text: r.date || "—" })));
  }
}

/* ================= TIER 2: supply chain ================= */
function buildSupply(ctx) {
  const el = $("#chart-supply");
  const oy = ctx.core.originYears && ctx.core.originYears.supplychain;
  const cur = ctx.F.year;
  const yLab = (v) => String(v) + (String(v) === cur ? "\nYTD" : "");
  if (oy && Object.keys(oy).length) {
    const years = Object.keys(oy).filter((y) => /^\d{4}$/.test(y) && y >= "2018").sort();
    stackedBars(el, {
      xs: years.map(Number), groups: [{ label: "open-source CVEs", color: ORIGIN_COLORS.supplychain, data: years.map((y) => oy[y] || 0) }],
      height: 220, time: false, xLabel: "year", yLabel: "CVEs per year", legend: false,
      ariaLabel: "CVEs in open-source packages per year", xValues: tick(yLab), xIncrs: [1, 2, 5], xSpace: 34, xFmt: yLab, barMax: 50,
    });
  } else note(el, "Per-origin CVE counts are not in this data build.");
  const el2 = $("#chart-malicious");
  const mal = ctx.mal;
  if (!mal || !mal.byYear || !Object.keys(mal.byYear).length) { note(el2, "Malicious-package counts are not available in this data build."); return; }
  const ecos = Object.entries(mal.byYear).map(([eco, by]) => [eco, sumObj(by)]).sort((a, b) => b[1] - a[1]);
  const top = ecos.slice(0, 4).map((x) => x[0]);
  const years = [...new Set(Object.values(mal.byYear).flatMap((by) => Object.keys(by || {})))].filter((y) => /^\d{4}$/.test(y) && y >= "2018").sort();
  // registries are open source: tints of the open-source teal (blue means AI on this page)
  const cols = [P.teal, tint(P.teal, 0.68), tint(P.teal, 0.45), tint(P.teal, 0.25)];
  const groups = top.map((eco, i) => ({ label: eco, color: cols[i], data: years.map((y) => (mal.byYear[eco] || {})[y] || 0) }));
  if (ecos.length > 4) groups.push({ label: "other", color: OTHER_COLOR, data: years.map((y) => ecos.slice(4).reduce((s, [eco]) => s + ((mal.byYear[eco] || {})[y] || 0), 0)) });
  if (!years.length) { note(el2, "No malicious-package counts since 2018."); return; }
  stackedBars(el2, {
    xs: years.map(Number), groups, height: 220, time: false, xLabel: "year", yLabel: "packages per year",
    ariaLabel: "Malicious open-source packages per year by ecosystem (OSV MAL advisories)", draw: malOutlierNotes(mal), yMax: malClipMax(mal, years), xValues: tick(yLab), xIncrs: [1, 2, 5], xSpace: 34, xFmt: yLab, barMax: 50,
  });
  const hint = $("#mal-hint");
  if (hint && fin(mal.total)) hint.textContent += ` ${num.format(mal.total)} in total${mal.method ? ` (${mal.method})` : ""}.`;
}

/* ================= Part 1: exploited vulnerabilities by vendor ================= */
function buildKevVendors(ctx, F) {
  const el = $("#kevvend-bars");
  const ents = ((ctx.kev && ctx.kev.entries) || []).filter((e) => String(e.added).startsWith(F.year));
  if (ents.length < 20) { $("#kev-vendors").remove(); return; }
  const by = new Map();
  for (const e of ents) {
    const name = (e.vendor || "").trim() || "Unknown";
    const k = name.toLowerCase();
    const r = by.get(k) || { name, n: 0, zd: 0, ransom: 0 };
    r.n += 1; r.zd += e.zeroDay ? 1 : 0; r.ransom += e.ransomware ? 1 : 0;
    by.set(k, r);
  }
  const rows = [...by.values()].sort((a, b) => b.n - a.n || a.name.localeCompare(b.name)).slice(0, 10);
  hbars(el, rows.map((r) => ({ label: r.name, n: r.n, color: P.red })));
  // count · at disclosure · ransomware, per row
  el.querySelectorAll(".hb-n").forEach((cell, i) => {
    const r = rows[i];
    cell.textContent = [num.format(r.n), r.zd ? `${num.format(r.zd)} at disclosure` : null, r.ransom ? `${num.format(r.ransom)} ransomware` : null].filter(Boolean).join(" · ");
  });
  // name every vendor tied with the third, so the cut-off is not alphabetical
  const cut = rows.length >= 3 ? rows[2].n : 0;
  const top3 = rows.filter((r, i) => i < 3 || r.n === cut), n3 = top3.reduce((t, r) => t + r.n, 0);
  fig(el, {
    titleEl: "#h-kevvend",
    title: `${listJoin(top3.map((r) => r.name))} account for ${pct(n3 / ents.length)} of ${F.year}'s exploited vulnerabilities`,
    subEl: "#kevvend-hint",
    sub: `Vulnerabilities added to CISA KEV in ${F.year} (${partialLabel(F)}), top 10 vendors of ${num.format(by.size)}. "At disclosure" = added to KEV within one day of CVE publication; "ransomware" = CISA reports known ransomware use.`,
    how: "Bar length = KEV additions this year. Pitfall: KEV favours products US federal agencies run, so niche vendors are under-represented; a vendor's count reflects its install base as much as its code quality.",
    so: "For these vendors, agree patch timelines in days, track your own time-to-fix for their KEV entries, and keep their management interfaces off the internet.",
    src: srcLine(ctx, ["kev"]),
  });
}

/* ================= Part 1: ransomware-linked exploitation ================= */
/* CISA sets the ransomware flag after the fact, so the most recent years read
 * low until campaigns are attributed: they are shown, but marked as filling in. */
const RANSOM_SETTLE_YEARS = 2;
function buildRansom(ctx, F) {
  const el = $("#ransom-bars");
  const ents = (ctx.kev && ctx.kev.entries) || [];
  const by = {};
  for (const e of ents) {
    const y = String(e.added || "").slice(0, 4);
    if (!/^\d{4}$/.test(y) || y < "2023") continue;  // 2021-22: catalog launch and catch-up
    const r = by[y] || (by[y] = { n: 0, r: 0 });
    r.n += 1; r.r += e.ransomware ? 1 : 0;
  }
  const years = Object.keys(by).sort();
  if (years.length < 3) { $("#ransom").remove(); return; }
  const settledTo = String(+F.year - RANSOM_SETTLE_YEARS);
  const settled = years.filter((y) => y <= settledTo);
  const sn = settled.reduce((t, y) => t + by[y].n, 0), sr = settled.reduce((t, y) => t + by[y].r, 0);
  const rows = years.map((y) => ({ label: y + (y > settledTo ? " (still filling in)" : "") + (y === F.year ? " YTD" : ""), n: by[y].r / by[y].n, y,
    color: y > settledTo ? tint(P.red, 0.4) : P.red }));
  hbars(el, rows.map((r) => ({ label: r.label, n: Math.round(1000 * r.n), color: r.color })));
  el.querySelectorAll(".hb-n").forEach((cell, i) => {
    const y = rows[i].y;
    cell.textContent = `${pct(by[y].r / by[y].n)} · ${num.format(by[y].r)} of ${num.format(by[y].n)}`;
  });
  // vendors behind the ransomware-linked entries of the last three years
  const since = String(+F.year - 2);
  const vc = new Map();
  for (const e of ents) if (e.ransomware && String(e.added) >= since) { const v = (e.vendor || "").trim(); if (v) vc.set(v, (vc.get(v) || 0) + 1); }
  const ranked = [...vc.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const lead = ranked.filter(([, n], i) => i < 3 || (ranked[2] && n === ranked[2][1]));
  const share = sn ? sr / sn : null;
  fig(el, {
    titleEl: "#h-ransom",
    title: share ? `About ${pct(share)} of exploited vulnerabilities are later linked to ransomware (${settled[0]}–${settledTo}); recent years are still filling in` : null,
    subEl: "#ransom-hint",
    sub: `Share of each year's CISA KEV additions flagged "known ransomware campaign use", ${years[0]} → ${F.year} (${partialLabel(F)}). CISA adds the flag when a campaign is attributed, often months later, so the last ${RANSOM_SETTLE_YEARS} years (lighter bars) will rise.` + (lead.length ? ` Since ${since}: ${lead.map(([v, n]) => `${v} ${n}`).join(", ")}.` : ""),
    how: "Bar length = share of that year's KEV additions with the ransomware flag; text = share · flagged of all. Pitfall: a falling share in the newest years is a reporting lag, not a falling threat.",
    so: `Treat any KEV entry for software you run as a potential ransomware entry point${lead.length ? `, especially ${listJoin(lead.map(([v, n]) => `${v} (${n})`))}, the vendors with the most ransomware-linked entries since ${since}` : ""}: patch it on an emergency timeline and check for compromise, because ransomware crews reuse these flaws for months.`,
    src: srcLine(ctx, ["kev"]),
  });
}

/* ================= Part 1: time from CVE publication to KEV listing ================= */
const TTK_BUCKETS = [
  { id: "d1", label: "≤1 day (at disclosure)", color: P.red, test: (d) => d <= 1 },
  { id: "w1", label: "2–7 days", color: P.orange, test: (d) => d <= 7 },
  { id: "m1", label: "8–30 days", color: P.amber, test: (d) => d <= 30 },
  { id: "y1", label: "31–365 days", color: P.dusk, test: (d) => d <= 365 },
  { id: "old", label: "over a year", color: P.slate, test: () => true },
];
function ttkBuckets(entries, fromYear) {
  const by = {};
  for (const e of entries || []) {
    if (!e || !e.added || !fin(e.daysToKev)) continue;
    const y = e.added.slice(0, 4);
    if (y < fromYear) continue;
    const b = TTK_BUCKETS.find((x) => x.test(e.daysToKev));
    const row = by[y] || (by[y] = Object.fromEntries(TTK_BUCKETS.map((x) => [x.id, 0])));
    row[b.id] += 1;
  }
  return by;
}
/* Of the CVEs published in the 12-month window (and the 12 before) that are in
 * KEV: how many were added within 7 days, and the median days. One cohort,
 * so old CVEs newly added to KEV do not dilute the speed figure. */
function ttkCohort(ctx, origin) {
  const L = ctx.core.landscape && ctx.core.landscape.all, w = L && L.window;
  if (!w || !w.cur || !w.prev) return null;
  const ents = ((ctx.kev && ctx.kev.entries) || []).filter((e) => e.published && fin(e.daysToKev) && (!origin || e.origin === origin));
  // equal follow-up: the earlier cohort only counts KEV additions made by the
  // end of its own window, or its extra year of late additions biases it down
  const stat = ([a, b], addedBy) => {
    const c = ents.filter((e) => e.published >= a && e.published <= b && (!addedBy || String(e.added) <= addedBy)).map((e) => e.daysToKev).sort((x, y) => x - y);
    if (!c.length) return null;
    const mid = c.length >> 1;
    return { n: c.length, wk: c.filter((d) => d <= 7).length, median: c.length % 2 ? c[mid] : (c[mid - 1] + c[mid]) / 2 };
  };
  // full = the earlier cohort with all its additions (12+ months of follow-up): the
  // LEVEL; cur vs prev (equal follow-up) is only a like-for-like trend, because the
  // recent cohort's slow listings have not happened yet
  const cur = stat(w.cur), prev = stat(w.prev, w.prev[1]), full = stat(w.prev);
  return cur ? { cur, prev, full, from: w.cur[0] } : null;
}
/* this year's KEV additions whose CVE is old: >1 year and >3 years since publication */
/* CISA's BOD 22-01 deadline (KEV dueDate - dateAdded) for this year's additions */
/* CISA's BOD 22-01 deadlines changed during the year (21 → 14 → 3 days), so the
 * benchmark is the CURRENT policy: additions of the last 90 days, plus the
 * median at the start of the year for contrast. */
function kevDeadlines(ctx, F) {
  const gap = (e) => Math.round((Date.parse(e.due) - Date.parse(e.added)) / 86400e3);
  const ents = ((ctx.kev && ctx.kev.entries) || []).filter((e) => e.due && fin(gap(e)) && gap(e) >= 0);
  const med = (a) => { const d = a.slice().sort((x, y) => x - y), m = d.length >> 1; return d.length % 2 ? d[m] : (d[m - 1] + d[m]) / 2; };
  const from = new Date(Date.parse(F.asOf) - 90 * 86400e3).toISOString().slice(0, 10);
  const recent = ents.filter((e) => String(e.added) > from).map(gap);
  if (recent.length < 20) return null;
  const early = ents.filter((e) => String(e.added).startsWith(F.year) && String(e.added) < `${F.year}-03-01`).map(gap);
  return { n: recent.length, median: med(recent), wk: recent.filter((x) => x <= 7).length, early: early.length >= 10 ? med(early) : null };
}
function oldKev(ctx, F) {
  const a = ((ctx.kev && ctx.kev.entries) || []).filter((e) => String(e.added).startsWith(F.year) && fin(e.daysToKev));
  if (a.length < 20) return null;
  const y1 = a.filter((e) => e.daysToKev > 365), y3 = a.filter((e) => e.daysToKev > 1095);
  const byAge = y3.slice().sort((x, y) => String(x.published).localeCompare(String(y.published)));
  return { n: a.length, y1: y1.length, y3: y3.length, oldestYear: byAge.length ? String(byAge[0].published).slice(0, 4) : null,
    prods: [...new Set(byAge.map((e) => tidyProduct(e.product)).filter(Boolean))].slice(0, 3) };
}
/* two-proportion z-test: is a/n vs b/m a real change or noise? */
function propZ(a, n, b, m) {
  if (!n || !m) return null;
  const p = (a + b) / (n + m);
  const se = Math.sqrt(p * (1 - p) * (1 / n + 1 / m));
  return se > 0 ? (a / n - b / m) / se : null;
}
const daysText = (d) => (d < 1 ? "under a day" : d === 1 ? "1 day" : `${Number.isInteger(d) ? d : fmtX(d)} days`);
function buildTtk(ctx) {
  const el = $("#chart-ttk");
  const ents = ctx.kev && ctx.kev.entries;
  if (!ents || !ents.some((e) => fin(e.daysToKev))) { note(el, "Days-to-KEV needs CVE publication dates for KEV entries — not in this data build."); return; }
  const by = ttkBuckets(ents, "2022");
  const years = Object.keys(by).sort();
  const cur = ctx.F.year;
  const yLab = (v) => String(v) + (String(v) === cur ? "\nYTD" : "");
  stackedBars(el, {
    xs: years.map(Number), groups: TTK_BUCKETS.map((b) => ({ label: b.label, color: b.color, data: years.map((y) => by[y][b.id]) })),
    height: 200, time: false, xLabel: "year added", yLabel: "KEV additions per year",
    ariaLabel: "CISA KEV additions per year, stacked by days from CVE publication to KEV addition",
    draw: yearNotes(kevCatchUpYears(ctx.kev), false),
    xValues: tick(yLab), xIncrs: [1, 2, 5], xSpace: 34, xFmt: yLab, barMax: 50,
  });
}

/* ================= Part 1: latest exploited + patch next ================= */
function buildKevAll(ctx) {
  const tbody = $("#tbl-kevall tbody");
  const ents = ctx.kev && Array.isArray(ctx.kev.entries) ? ctx.kev.entries : null;
  if (!ents) { emptyRow(tbody, 6, "CISA KEV data is not available."); return; }
  const OL = originLabel(ctx.core);
  const scores = (ctx.epss && ctx.epss.scores) || null;
  const rows = [...ents].sort((a, b) => String(b.added).localeCompare(String(a.added)) || String(b.cve).localeCompare(String(a.cve))).slice(0, 15);
  for (const r of rows) {
    const idCell = h("td", { class: "nowrap" }, cveLink(r.cve));
    if (r.ransomware) idCell.append(badge("RANSOMWARE", "", "CISA: known use in ransomware campaigns"));
    if (r.zeroDay) idCell.append(badge("AT DISCLOSURE", "", "added to CISA KEV within one day of CVE publication (a zero-day proxy)"));
    const sc = scores ? scores[r.cve] : null;
    tbody.append(h("tr", null, idCell,
      h("td", { text: tidyProduct(r.product) || "—", title: r.desc || null }),
      originCell(r.origin, OL),
      h("td", { class: "nowrap", text: r.added || "—" }),
      h("td", { class: "num", text: fin(r.daysToKev) ? num.format(r.daysToKev) : "—" }),
      kevEpssCell(ctx, r.cve)));
  }
}
function epssTopTable(tbody, rows, cols, cell) {
  if (!rows || !rows.length) { emptyRow(tbody, cols, "No EPSS ranking in this data build (needs the EPSS bulk file)."); return; }
  for (const r of rows) {
    tbody.append(h("tr", null,
      h("td", { class: "nowrap" }, cveLink(r.cve)),
      h("td", { text: tidyProduct(r.product) || "—" }),
      cell(r),
      h("td", { class: "nowrap", text: r.published || "—" }),
      h("td", { class: "num", text: epssText(r), title: fin(r.pct) ? `percentile ${(100 * r.pct).toFixed(1)}` : null })));
  }
}
function buildNext(ctx) {
  const top = ctx.epss && ctx.epss.top;
  const OL = originLabel(ctx.core);
  epssTopTable($("#tbl-next tbody"), top && top.all, 5, (r) => originCell(r.origin, OL));
}

/* ================= Part 1: severity per year (record CVSS) ================= */
function sevYearsChart(el, sy, cfg) {
  const years = Object.keys(sy || {}).filter((y) => /^\d{4}$/.test(y) && y >= "2018").sort();
  if (!years.length) { note(el, "Per-year severity is not in this data build."); return; }
  const keys = [...SEV_KEYS, "UNRATED"];
  const cur = cfg.year;
  const yLab = (v) => String(v) + (String(v) === cur ? "\nYTD" : "");
  stackedBars(el, {
    xs: years.map(Number), groups: keys.map((k) => ({ label: k === "UNRATED" ? "unrated" : k, color: SEV_COLORS[k], data: years.map((y) => (sy[y] || {})[k] || 0) })),
    height: cfg.height || 240, time: false, xLabel: "year", yLabel: cfg.yLabel,
    ariaLabel: cfg.ariaLabel, xValues: tick(yLab), xIncrs: [1, 2, 5], xSpace: 34, xFmt: yLab, barMax: 60,
  });
}
function buildSevAll(ctx) {
  const L = ctx.core.landscape && ctx.core.landscape.all;
  sevYearsChart($("#chart-sevall"), L && L.sevYears, { year: ctx.F.year, yLabel: "CVEs per year",
    ariaLabel: "Published CVEs per year stacked by CVSS severity, CRITICAL at the bottom, unrated on top" });
}

/* ================= ranked lists with last-12-months vs prior-12-months ================= */
const growthText = (n, prev) => (prev > 0 ? (n / prev >= 1.05 ? `×${n / prev >= 10 ? Math.round(n / prev) : (n / prev).toFixed(1)}` : n >= prev ? "flat" : `−${Math.round(100 * (1 - n / prev))}%`) : "new");
/* rows [{label, n, prev, title}] → bar (n) with a tick at the previous
 * period's value and the change as text */
function topList(el, rows, opts) {
  if (!rows || !rows.length) { note(el, (opts && opts.empty) || "Not available in this data build."); return; }
  const max = Math.max(1, ...rows.map((r) => Math.max(r.n, r.prev || 0)));
  const list = h("div", { class: "hbars toplist", role: "list" });
  for (const r of rows) {
    const fill = h("span", { class: "hb-fill" });
    fill.style.width = ((100 * r.n) / max).toFixed(2) + "%";
    fill.style.background = opts.color || P.steel;
    const bar = h("span", { class: "hb-bar" }, fill);
    if (fin(r.prev)) {
      const mark = h("span", { class: "hb-prev", title: `previous 12 months: ${num.format(r.prev)}` });
      mark.style.left = `calc(${((100 * r.prev) / max).toFixed(2)}% - 1px)`;
      bar.append(mark);
    }
    list.append(h("div", { class: "hb-row", role: "listitem", "aria-label": `${r.label}: ${r.n}, previous 12 months ${r.prev}` },
      h("span", { class: "hb-lab", text: r.label, title: r.title || r.label }),
      bar,
      h("span", { class: "hb-n", text: `${num.format(r.n)} · ${growthText(r.n, r.prev)}` })));
  }
  el.append(list);
}
/* carry the counts without the year's surge filers (build: nx/prevx) */
const withX = (r, row) => (fin(r.nx) ? { ...row, nx: r.nx, prevx: r.prevx } : row);
/* counts without the year's surge filers, re-ranked: bars, ticks, counts and
 * titles then all use the same basis as the "grew fastest" claim */
function exRows(rows) {
  if (!rows.length || !rows.every((r) => fin(r.nx))) return rows;
  return rows.map((r) => ({ ...r, n: r.nx, prev: r.prevx })).sort((a, b) => b.n - a.n || String(a.label).localeCompare(String(b.label)));
}
const exKey = (L) => `Counts exclude the year's ${surgeWord(L)} (${surgeDef(L)}). Bar = last 12 months; tick = the 12 months before; text = count · change.`;
function cweRows(top, names, n) {
  return (top || []).slice(0, n || 10).map((r) => withX(r, { label: names[r.id] ? `${names[r.id]} (${r.id})` : r.id, title: r.id, n: r.n, prev: r.prev }));
}
function vendorRows(top, n) { return (top || []).slice(0, n || 10).map((r) => withX(r, { label: r.name || r.id, n: r.n, prev: r.prev })); }
/* bulk filers (build: surgeCnas) among the top CNAs, then everyone else in one row */
function bulkFilerRows(L) {
  const surge = new Set((L.surgeCnas || []).map((c) => c.toLowerCase()));
  const w = L.window || {};
  const rows = (L.cnaTop || []).filter((r) => surge.has(String(r.id).toLowerCase()))
    .map((r) => ({ label: prettyCna(r.id), title: r.id, n: r.n, prev: r.prev }));
  if (!surge.size || !fin(w.nx)) return cnaRows(L.cnaTop);
  return rows.concat([{ label: "Everyone else", title: "all other CNAs", n: w.nx, prev: w.prevNx }]);
}
function cnaRows(top, n) { return (top || []).slice(0, n || 10).map((r) => ({ label: prettyCna(r.id), title: r.id, n: r.n, prev: r.prev })); }
/* the row that grew most in absolute terms, among the shown rows */
/* Grew fastest RELATIVE to all CVEs: the largest rise in share (n/N vs
 * prev/prevN), among rows with a meaningful base; null if none outgrew the
 * overall rate. Raw increases mostly re-rank the biggest classes. */
function shareRiser(rows, w, minPrev) {
  if (!w || !w.n || !w.prevN) return null;
  // without the year's surge filers when available: their jump is reporting, not software
  const useX = fin(w.nx) && w.prevNx > 0 && rows.every((r) => fin(r.nx));
  const N = useX ? w.nx : w.n, P = useX ? w.prevNx : w.prevN;
  let best = null;
  for (const r of rows) {
    const n = useX ? r.nx : r.n, prev = useX ? r.prevx : r.prev;
    if (!prev || prev < (minPrev || 100)) continue;
    const rel = (n / N) / (prev / P);
    if (rel > 1.05 && (!best || rel > best.rel)) best = { ...r, rel, gn: n, gprev: prev, base: N / P, ex: useX };
  }
  // significant = its share of all CVEs rose beyond noise (two-proportion test, 95%)
  if (best) { const z = propZ(best.gn, N, best.gprev, P); best.sig = z != null && z >= 1.96; best.z = z; }
  return best;
}
const surgeNames = (L) => listJoin((L && L.surgeCnas || []).map((c) => prettyCna(c)));
/* "bulk filers" = third parties filing for others in bulk (GitHub, VulnCheck); a surge
 * set that also holds vendors now filing their own CVEs (Oracle, Chrome…) is "surge filers" */
const THIRD_PARTY_FILERS = new Set(["GitHub_M", "VulnCheck"]);
const surgeWord = (L) => ((L && L.surgeCnas || []).every((c) => THIRD_PARTY_FILERS.has(c)) ? "bulk filers" : "surge filers");
const surgeDef = (L) => {
  const all = (L && L.surgeCnas) || [], tp = all.filter((c) => THIRD_PARTY_FILERS.has(c)), own = all.filter((c) => !THIRD_PARTY_FILERS.has(c));
  return own.length ? `CNAs whose filing grew at least ×4 to 1,000+: ${listJoin(tp.map(prettyCna))} filing for others in bulk, and ${listJoin(own.map(prettyCna))} now filing many more CVEs for their own products`
    : `${listJoin(tp.map(prettyCna)) || "none"}, filing for others in bulk`;
};
const baseX = (w) => (w && w.prevN ? `×${fmtX(w.n / w.prevN)}` : null);
const topRiser = (rows) => rows.reduce((b, r) => (r.n - (r.prev || 0) > (b ? b.n - (b.prev || 0) : 0) ? r : b), null);
function buildTops(ctx) {
  const L = ctx.core.landscape && ctx.core.landscape.all;
  const names = (ctx.sev && ctx.sev.cweNames) || {};
  const legend = h("p", { class: "hint toplegend", text: "Bar = last 12 months; tick = the 12 months before; text = count · change." });
  if (!L) { for (const id of ["#cweall", "#vendall", "#cnaall"]) note($(id), "Not in this data build."); return; }
  // Part 1 lists share one quiet colour: the ranking is the message
  topList($("#cweall"), exRows(cweRows(L.cweTop, names)), { color: P.steel });
  topList($("#vendall"), exRows(vendorRows(L.vendorTop)), { color: P.steel });
  topList($("#cnaall"), bulkFilerRows(L), { color: P.steel });
  // the key sits inside every list card, so a screenshot of one card still explains the tick
  for (const id of ["#cweall", "#vendall"]) $(id).before(h("p", { class: "hint toplegend", text: exKey(L) }));
  $("#cnaall").before(legend.cloneNode(true));
}

/* ================= Part 2: AI-related summary ================= */
/* AI-risk relations per year (this year, last year). "found" is left out:
 * an AI tool finding a bug in curl is discovery, not AI attack surface. */
function relYtd(core, F) {
  const ry = core.landscape && core.landscape.ai && core.landscape.ai.relYears;
  if (!ry) return null;
  return Object.fromEntries(Object.entries(ry).filter(([id]) => id !== "found")
    .map(([id, by]) => [id, { cur: (by || {})[F.year] || 0, prev: (by || {})[F.prevYear] || 0 }]));
}
/* CVEs whose discovery credits an AI tool or lab, across ALL CVEs */
function foundYtd(core, F) {
  const by = core.landscape && core.landscape.all && core.landscape.all.relYears && core.landscape.all.relYears.found;
  return by ? { cur: by[F.year] || 0, prev: by[F.prevYear] || 0 } : null;
}
function buildAiHeadline(ctx, F, S) {
  const el = $("#ai-headline"), sub = $("#ai-subhead");
  let head = null;
  try {
    const a = S.aiShare;
    if (a && a.of) {
      const r = F.ytd && F.ytd.prev ? F.ytd.cur / F.ytd.prev : null;
      const ra = ytdRatio(ctx.core, "ai"), rall = ytdRatio(ctx.core);
      const both = ra && rall && ra.rx && rall.rx ? ` Without bulk filing by ${BULK_NAMES}: ×${fmtX(ra.rx)} against ×${fmtX(rall.rx)}.` : "";
      head = `${num.format(a.n)} of this year's ${num.format(a.of)} CVEs are AI-related (${pct(a.n / a.of, a.n / a.of < 0.1 ? 1 : 0)})`
        + (r && r >= 1.15 ? ` — ×${fmtX(r)} on the same period last year, against ×${fmtX(S.total.cur / S.total.prev)} for all CVEs.${both}` : ".");
    }
  } catch (e) { head = null; }
  head = clean(head);
  if (head) el.textContent = head; else el.remove();
  const parts = [];
  const add = (fn) => { try { const s = clean(fn()); if (s) parts.push(s); } catch (e) { /* skip */ } };
  const RL = ctx.relLabel;
  add(() => {
    const ry = relYtd(ctx.core, F);
    if (!ry) return null;
    const ranked = Object.entries(ry).sort((a, b) => b[1].cur - a[1].cur).filter(([, v]) => v.cur);
    return ranked.length ? `Most are ${listJoin(ranked.slice(0, 2).map(([id, v]) => `${lcFirst(RL(id))} (${num.format(v.cur)})`))}.` : null;
  });
  add(() => {
    const k = S.kev;
    if (!k || !k.cur) return null;
    const prev = (F.kevAi || []).filter((e) => String(e.added).startsWith(F.prevYear)).length;
    return `Exploitation is rising from a low base: ${num.format(k.aiCur)} of the ${num.format(k.cur)} vulnerabilities CISA added to KEV in ${F.year} are AI-related, against ${num.format(prev)} in all of ${F.prevYear}.`;
  });
  add(() => {
    const fy = foundYtd(ctx.core, F);
    return fy && fy.cur ? `Separately, AI is finding bugs: ${num.format(fy.cur)} CVEs this year, in any software, credit an AI tool or AI lab (${num.format(fy.prev)} in ${F.prevYear}). They count as discovery, not as AI-related risk.` : null;
  });
  if (parts.length) { sub.textContent = parts.join(" "); sub.classList.add("hint"); } else sub.remove();
}
function buildAiKpis(ctx, F, S) {
  const tiles = [];
  const M = lastMonths(F, 24);
  const sparkTitle = "monthly, last 24 complete months";
  const core = ctx.core;
  const a = S.aiShare;
  if (a && a.of) tiles.push({ k: `AI-related CVEs ${F.year} YTD`, v: num.format(a.n), cls: "ai",
    delta: F.ytd ? growthDelta(F.ytd.cur, F.ytd.prev, F.prevYear) : null,
    spark: Array.isArray(core.aiMonths) ? { vals: monthSeries(M, core.months, core.aiMonths), title: sparkTitle } : null,
    d: `${pct(a.n / a.of, 1)} of all CVEs` + (F.ytd && F.ytd.prev ? ` · ${num.format(F.ytd.prev)} by this date in ${F.prevYear}` : "")
      + (() => { const ra = ytdRatio(core, "ai"); return ra && ra.rx ? ` · ×${fmtX(ra.rx)} without ${BULK_NAMES}` : ""; })() });
  const ry = relYtd(core, F);
  const mcp = core.layerMonths && core.layerMonths.mcp;
  if (ry && ry.agent) {
    // the build's one YTD window for value, comparison and badge
    const ag = ytdRel(core, "agent");
    tiles.push({ k: `MCP & agent CVEs ${F.year}`, v: num.format(ag ? ag.cur : ry.agent.cur), cls: "ai",
      delta: ag ? growthDelta(ag.cur, ag.prev, F.prevYear) : null,
      spark: mcp ? { vals: monthSeries(M, core.months, mcp), title: sparkTitle } : null,
      d: ag ? `${num.format(ag.prev)} by this date in ${F.prevYear}` + (ag.rx ? ` · ×${fmtX(ag.rx)} without ${BULK_NAMES}` : "") : `${num.format(ry.agent.prev)} in all of ${F.prevYear}` });
  }

  const k = S.kev;
  if (k && F.kevAi) {
    const md = F.asOf.slice(5);
    const prevSame = F.kevAi.filter((e) => String(e.added).startsWith(F.prevYear) && String(e.added).slice(5) <= md).length;
    // small numbers: no trend arrow below 10 a year earlier, and KEV is a floor for AI —
    // ShadowRay (CVE-2023-48022) was exploited at scale but is not in KEV
    tiles.push({ k: `AI-related added to CISA KEV ${F.year}`, v: num.format(k.aiCur), cls: "warn",
      delta: fin(prevSame) && prevSame >= 10 ? growthDelta(k.aiCur, prevSame, F.prevYear) : null,
      spark: { vals: countByMonth(M, F.kevAi, (e) => e.added), title: sparkTitle },
      d: `${fin(prevSame) ? `${num.format(prevSame)} by this date in ${F.prevYear} · ` : ""}${pct(k.cur ? k.aiCur / k.cur : 0, 1)} of ${F.year} KEV additions · ${num.format(F.kevAi.length)} all time · a floor: ShadowRay (CVE-2023-48022) was exploited but is not in KEV` });
  }
  const fy = foundYtd(core, F);
  if (fy) {
    const fk = ((ctx.kev && ctx.kev.entries) || []).filter((e) => e.found).length;
    tiles.push({ k: `Found by AI ${F.year} (any software)`, v: num.format(fy.cur),
      d: `discovery, not AI risk · ${num.format(fy.prev)} in all of ${F.prevYear}` + (fk ? ` · ${num.format(fk)} later exploited` : "") });
  }
  const SRC = [tileSrc(ctx, "CVE List"), tileSrc(ctx, "CVE List"), tileSrc(ctx, "CISA KEV"), tileSrc(ctx, "CVE List")];
  tiles.forEach((t, i) => { t.src = t.src || SRC[i] || tileSrc(ctx, "CVE List"); });
  kpiTiles($("#ai-kpis"), tiles, "AI indicators are not available for this data build.");
}
/* one card per AI relation: this year's count and the change on the same days last
 * year (the per-year lines and the stack-layer chart said the same thing again) */
function buildRelations(ctx, F) {
  const el = $("#rel-bars");
  const ry = relYtd(ctx.core, F);
  const RL = ctx.relLabel;
  if (!ry) { note(el, "AI relation tags are not in this data build (it predates them)."); return; }
  const ids = (ctx.rels || []).map((r) => r.id).filter((id) => ry[id]);
  hbars(el, ids.map((id) => {
    const y = ytdRel(ctx.core, id);
    return { label: RL(id), n: ry[id].cur, color: REL_COLORS[id] || OTHER_COLOR,
      txt: num.format(ry[id].cur) + (y ? ` · ${y.prev >= 10 ? growthText(y.cur, y.prev) + (fin(y.rx) && Math.abs(y.rx - y.cur / y.prev) >= 0.3 ? ` (×${fmtX(y.rx)} without bulk filers)` : "") : `${num.format(y.cur)} vs ${num.format(y.prev)}`}` : "") };
  }).sort((a, b) => b.n - a.n));
}
function buildAiOrigin(ctx) {
  const el = $("#chart-aiorigin");
  const L = ctx.core.landscape && ctx.core.landscape.ai;
  const origins = originList(ctx.core);
  if (!L || !L.originYears || !origins) { note(el, "Not in this data build."); return; }
  const OL = originLabel(ctx.core);
  const years = Object.keys(L.years || {}).filter((y) => y >= "2018").sort();
  const cur = ctx.F.year;
  const yLab = (v) => String(v) + (String(v) === cur ? "\nYTD" : "");
  stackedBars(el, {
    xs: years.map(Number), height: 240, time: false, xLabel: "year", yLabel: "AI-related CVEs per year",
    groups: [...origins].reverse().filter((o) => L.originYears[o.id]).map((o) => ({ label: OL(o.id), color: ORIGIN_COLORS[o.id] || OTHER_COLOR, data: years.map((y) => L.originYears[o.id][y] || 0) })),
    ariaLabel: "AI-related CVEs per year stacked by origin", xValues: tick(yLab), xIncrs: [1, 2, 5], xSpace: 34, xFmt: yLab, barMax: 60,
  });
}

/* ================= AI deep dive lead-in: exploited chips + actions ================= */
function buildKevChips(F) {
  const el = $("#kev-chips");
  if (!F.kevAi) { note(el, "KEV data is not available."); return; }
  const prods = kevProducts(F);
  if (!prods.length) { note(el, "No AI-related CVE is in CISA KEV in this data build."); return; }
  for (const p of prods) {
    el.append(h("a", { class: "chip", href: "#exploited",
      title: `${p.n} CVE${p.n === 1 ? "" : "s"} in CISA KEV${p.ransom ? ` (${p.ransom} with known ransomware use)` : ""} — see the exploited table` },
      h("span", { class: "chip-n", text: p.name }), p.n > 1 ? h("span", { class: "chip-x", text: `×${p.n}` }) : null,
      p.ransom ? h("span", { class: "chip-r", text: "R", title: "known ransomware use" }) : null));
  }
  const hint = $("#kev-chips-hint");
  if (hint) hint.textContent = `${num.format(F.kevAi.length)} AI-related CVEs in CISA's Known Exploited Vulnerabilities catalog, ${num.format(F.kevAiThisYear)} added in ${F.year}. A lower bound — most exploitation is never catalogued.`;
}

/* data-tied actions only: exploited products, next-highest EPSS, biggest layer */
function buildTodo(ctx, F) {
  const ul = $("#todo-list");
  const out = [];
  const add = (fn) => { try { const s = fn(); if (s && !/NaN|undefined|null|Infinity/.test(s)) out.push(s); } catch (e) { /* skip */ } };
  const prods = kevProducts(F);
  add(() => prods.length
    ? `Patch ${listJoin(prods.map((p) => p.name))} first: each has CISA-confirmed exploited CVEs (${num.format((F.kevAi || []).length)} in total; see the exploited table).`
    : null);
  add(() => {
    const top = ctx.epss && ctx.epss.top && ctx.epss.top.ai;
    if (!top) return null;
    // only AI you deploy (AI software, agents, AI features): a curl bug that
    // an AI tool found is AI-related, but not an AI system to inventory
    const DEPLOYED = new Set(["product", "agent", "feature"]);
    const names = [];
    const seen = new Set(prods.map((p) => p.name.toLowerCase()));
    for (const r of top) {
      if (!(r.rels || []).some((x) => DEPLOYED.has(x))) continue;
      const n = aiProductName(r.product);
      if (n && !seen.has(n.toLowerCase()) && names.length < 3) { seen.add(n.toLowerCase()); names.push(n); }
    }
    return names.length ? `Next, check ${listJoin(names)}: the AI software with the highest exploit-probability (EPSS) CVEs of the last 12 months that are not yet in KEV.` : null;
  });
  if (!out.length) { note(ul.parentElement, "Not enough data for recommendations in this build."); ul.remove(); return; }
  for (const s of out) ul.append(h("li", { text: s }));
}

/* ================= exploited AI software (KEV) ================= */
function buildKevTable(F, ctx) {
  const tbody = $("#tbl-kev tbody");
  if (!F.kevAi) { emptyRow(tbody, 7, "KEV data not available."); return; }
  if (!F.kevAi.length) { emptyRow(tbody, 7, "No AI-flagged KEV entries in this data build."); return; }
  const scores = (ctx.epss && ctx.epss.scores) || null;
  for (const r of F.kevAi) {
    const idCell = h("td", { class: "nowrap" }, cveLink(r.cve));
    if (r.ransomware) idCell.append(badge("RANSOMWARE", "", "CISA: known use in ransomware campaigns"));
    const s = scores ? scores[r.cve] : null;
    tbody.append(h("tr", null,
      idCell,
      h("td", { text: tidyProduct(r.product) || "—", title: r.desc || null }),
      h("td", null, relTags(r.rels && r.rels.length ? r.rels : ["product"], ctx.relLabel)),
      h("td", { class: "nowrap", text: r.published || "—" }),
      h("td", { class: "nowrap", text: r.added || "—" }),
      h("td", { class: "num", text: fin(r.daysToKev) ? num.format(r.daysToKev) : "—" }),
      kevEpssCell(ctx, r.cve)));
  }
  const hint = $("#kev-hint");
  if (hint && ctx.kev && ctx.kev.generatedAt) {
    hint.textContent += ` Catalog fetched ${String(ctx.kev.generatedAt).slice(0, 10)}.`;
  }
}

/* ================= layer chart ================= */
/* ================= main CVE chart (all vs AI) ================= */
function denseDays(daysArr, counts, first, last) {
  const out = new Array(last - first + 1).fill(0);
  daysArr.forEach((d, i) => { const k = dayT(d) - first; if (k >= 0 && k < out.length) out[k] = counts[i] || 0; });
  return out;
}
function bucketize(daily, first, agg) {
  const map = new Map();
  for (let i = 0; i < daily.length; i++) {
    const t = first + i;
    let key;
    if (agg === "day") key = t;
    else if (agg === "week") key = t - ((new Date(t * 86400e3).getUTCDay() + 6) % 7); // Monday
    else {
      const d = new Date(t * 86400e3);
      key = Date.UTC(d.getUTCFullYear(), agg === "month" ? d.getUTCMonth() : 0, 1) / 86400e3;
    }
    map.set(key, (map.get(key) || 0) + daily[i]);
  }
  return [...map.entries()].sort((a, b) => a[0] - b[0]);
}
function cumulative(buckets) { let s = 0; return buckets.map(([t, v]) => [t, (s += v)]); }

function buildMainChart(core) {
  const el = $("#chart-cves");
  if (!Array.isArray(core.days) || !core.days.length || !Array.isArray(core.aiDays)) {
    note(el, "Daily CVE counts are not available in this data build.");
    $("#ctl-cves").hidden = true;
    return;
  }
  const first = dayT(core.days[0]);
  const last = dayT(core.days[core.days.length - 1]);
  const allDense = denseDays(core.days, core.dayCounts || [], first, last);
  const aiDense = denseDays(core.aiDays, core.aiDayCounts || [], first, last);

  // opens in share mode: the panel title is about AI's share, and in count mode
  // the AI line is flattened under all CVEs (~500 vs ~15,000 a month)
  const state = { agg: "month", range: "2018", mode: "share", showAll: true, showAi: true };
  const rangeY = { "30d": 30 / 365.25, "1y": 1, "5y": 5, "10y": 10 };

  function render() {
    let bAll = bucketize(allDense, first, state.agg);
    let bAi = bucketize(aiDense, first, state.agg);
    if (state.mode === "cum") { bAll = cumulative(bAll); bAi = cumulative(bAi); }
    const cut = state.range === "2018" ? dayT("2018-01-01")
      : rangeY[state.range] ? last - rangeY[state.range] * 365.25 : -Infinity;
    bAll = bAll.filter(([t]) => t >= cut);
    bAi = bAi.filter(([t]) => t >= cut);
    if (state.mode === "share") {
      const share = bAi.map(([, a], i) => (bAll[i][1] ? (100 * a) / bAll[i][1] : 0));
      uplot.axes[1].label = "AI share of CVEs (%)";
      uplot.axes[1].values = (u, vals) => vals.map((v) => v.toFixed(1) + "%");
      uplot.setData([bAll.map((x) => x[0]), bAll.map(() => null), share]);
      uplot.setSeries(1, { show: false });
      uplot.setSeries(2, { show: state.showAi });
      return;
    }
    uplot.axes[1].label = state.mode === "cum" ? "cumulative CVEs" : `CVEs per ${state.agg}`;
    uplot.axes[1].values = tick(axisNum);
    uplot.setData([bAll.map((x) => x[0]), bAll.map((x) => x[1]), bAi.map((x) => x[1])]);
    uplot.setSeries(1, { show: state.showAll });
    uplot.setSeries(2, { show: state.showAi });
  }
  const fmtX = (v) => {
    const d = new Date(v * 86400e3);
    return state.agg === "year" ? String(d.getUTCFullYear())
      : state.agg === "month" ? d.toISOString().slice(0, 7) : d.toISOString().slice(0, 10);
  };
  const opts = {
    height: 340,
    ariaLabel: "CVEs per period, all vs AI-related",
    scales: { x: { time: true } },
    axes: [
      dayAxis(),
      { space: 48, label: "CVEs per month", values: tick(axisNum), size: 62 },
    ],
    series: [
      { label: "date", value: (u, v) => (v == null ? "" : fmtX(v)) },
      { label: "All CVEs", stroke: COLORS.all, width: 1.5, fill: P.allFill, spanGaps: true,
        value: (u, v) => (v == null ? "" : num.format(v)) },
      { label: "AI-related", stroke: COLORS.ai, width: 1.8, fill: P.aiFill, spanGaps: true,
        value: (u, v) => (v == null ? "" : state.mode === "share" ? v.toFixed(2) + "%" : num.format(v)) },
    ],
    legend: { show: true },
  };
  const uplot = makeChart(el, opts, [[], [], []]);
  render();

  // uPlot 1.6 legends toggle series natively; mirror that into the checkboxes
  // (legend DOM exists only after the first layout frame, so defer).
  requestAnimationFrame(() => {
    const legendEl = uplot.root.querySelector(".u-legend");
    if (!legendEl) return;
    legendEl.addEventListener("click", (e) => {
      const tr = e.target && e.target.closest ? e.target.closest("tr.u-series") : null;
      if (!tr) return;
      const i = [...legendEl.querySelectorAll("tr.u-series")].indexOf(tr);
      if (i === 1 && state.mode !== "share") { state.showAll = uplot.series[1].show; $("#ser-all").checked = state.showAll; }
      if (i === 2) { state.showAi = uplot.series[2].show; $("#ser-ai").checked = state.showAi; }
    });
  });
  function wire(attr, apply) {
    document.querySelectorAll(`#ctl-cves [data-${attr}]`).forEach((b) =>
      b.addEventListener("click", () => {
        document.querySelectorAll(`#ctl-cves [data-${attr}]`).forEach((x) => { x.classList.remove("on"); x.setAttribute("aria-pressed", "false"); });
        b.classList.add("on");
        b.setAttribute("aria-pressed", "true");
        apply(b.dataset[attr]);
        render();
      }));
    document.querySelectorAll(`#ctl-cves [data-${attr}]`).forEach((x) => x.setAttribute("aria-pressed", x.classList.contains("on") ? "true" : "false"));
  }
  wire("agg", (v) => { state.agg = v; });
  wire("range", (v) => { state.range = v; });
  wire("mode", (v) => { state.mode = v; });
  $("#ser-all").addEventListener("change", (e) => { state.showAll = e.target.checked; render(); });
  $("#ser-ai").addEventListener("change", (e) => { state.showAi = e.target.checked; render(); });
}

/* ================= how AI software breaks ================= */
function buildCweCompare(ctx) {
  const el = $("#cwe-compare");
  const names = (ctx.sev && ctx.sev.cweNames) || {};
  const cc = ctx.core.cweCompare;
  const hint = $("#cwe-hint");
  let ai, all = null, aiTot, allTot = null;
  if (cc && cc.ai) {
    ai = cc.ai; all = cc.all || null;
    aiTot = cc.aiTotal || Object.values(ai).reduce((a, b) => a + b, 0);
    allTot = cc.allTotal || null;
    hint.textContent = `Share of CVEs with each CWE (first CWE of the CVE record) — AI: ${num.format(aiTot)} CVEs` +
      (allTot ? `, all: ${num.format(allTot)} CVEs` : "") + ". Top 10 AI weaknesses.";
  } else if (ctx.sev && ctx.sev.cwe) {
    ai = ctx.sev.cwe;
    aiTot = Object.values(ai).reduce((a, b) => a + b, 0);
    hint.textContent = `AI-related CVEs only (no all-CVE comparison in this data build; NVD CWE mappings). Share of ${num.format(aiTot)} CWE mappings.`;
  } else {
    note(el, "CWE data is not available in this data build.");
    return;
  }
  const rows = Object.entries(ai).filter(([, n]) => fin(n)).sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (!rows.length || !aiTot) { note(el, "No CWE mappings yet."); return; }
  const shares = rows.map(([id, n]) => [id, n / aiTot, all && allTot && fin(all[id]) ? all[id] / allTot : null]);
  const max = Math.max(...shares.map((r) => Math.max(r[1], r[2] || 0)));
  const list = h("div", { class: "cwe-list" });
  if (all) {
    list.append(h("div", { class: "cwe-key" },
      h("span", { class: "k-ai", text: "AI" }), h("span", { class: "k-all", text: cc.allIs === "non-AI" ? "Non-AI CVEs" : "All CVEs" })));
  }
  for (const [id, sAi, sAll] of shares) {
    const name = names[id] || "";
    const lab = h("div", { class: "cwe-lab", title: name ? `${id} — ${name}` : id },
      h("span", { class: "cwe-id", text: id }), h("span", { class: "cwe-name", text: name || id }));
    const bars = h("div", { class: "cwe-bars" });
    const mk = (cls, s, who) => {
      const r = h("div", { class: "cwe-pair" });
      const b = h("span", { class: "cwe-bar" });
      const f = h("span", { class: "cwe-fill " + cls });
      f.style.width = s != null && max ? ((100 * s) / max).toFixed(2) + "%" : "0%";
      b.append(f);
      r.append(b, h("span", { class: "cwe-n", text: s != null ? pct(s, 1) : "—",
        title: s != null ? `${who}: ${pct(s, 2)}` : `${who}: not among the top CWEs` }));
      return r;
    };
    bars.append(mk("ai", sAi, "AI CVEs"));
    if (all) bars.append(mk("all", sAll, cc.allIs === "non-AI" ? "Non-AI CVEs" : "All CVEs"));
    list.append(h("div", { class: "cwe-row" }, lab, bars));
  }
  el.append(list);
}

/* ================= patch first (EPSS) ================= */
function buildEpssTable(ctx, F) {
  const tbody = $("#tbl-epss tbody");
  const ep = ctx.epss;
  if (!ep || !ep.scores) { emptyRow(tbody, 5, "EPSS scores are not available in this data build."); return; }
  let rows = ep.top && Array.isArray(ep.top.ai) ? ep.top.ai : null;
  if (!rows) {
    // older data: rank the AI CVEs that have scores (KEV entries excluded)
    const kevAll = new Set(((ctx.kev && ctx.kev.entries) || []).map((e) => e.cve));
    rows = Object.entries(ep.scores).filter(([id, sc]) => sc && fin(sc.epss) && ctx.metaOf(id) && !kevAll.has(id))
      .sort((a, b) => b[1].epss - a[1].epss).slice(0, 15)
      .map(([id, sc]) => { const m = ctx.metaOf(id) || {}; return { cve: id, epss: sc.epss, pct: sc.pct, product: m.product, published: m.d, rels: m.rels || (m.layer ? ["product"] : []) }; });
  }
  epssTopTable(tbody, rows, 5, (r) => h("td", null, relTags(r.rels, ctx.relLabel)));
}

/* ================= who reports AI CVEs ================= */
function buildCnaChart(ctx) {
  const el = $("#chart-cna");
  const cy = ctx.core.cnaYears;
  if (!cy || typeof cy !== "object") { note(el, "Per-assigner (CNA) counts are not available in this data build."); return; }
  const years = Object.keys(cy).filter((y) => /^\d{4}$/.test(y) && +y >= 2018).sort();
  if (!years.length) { note(el, "No per-assigner counts since 2018."); return; }
  const tot = {};
  for (const y of years) for (const [c, n] of Object.entries(cy[y] || {})) if (c !== "other" && fin(n)) tot[c] = (tot[c] || 0) + n;
  const top = Object.entries(tot).sort((a, b) => b[1] - a[1]).slice(0, 7).map((x) => x[0]);
  const topSet = new Set(top);
  // filers are not a category with a meaning elsewhere: one quiet steel ramp, largest darkest
  const ramp = [1, 0.84, 0.7, 0.58, 0.47, 0.38, 0.3];
  const groups = top.map((c, i) => ({ label: prettyCna(c), color: tint(P.steel, ramp[i] || 0.3), data: years.map((y) => (cy[y] || {})[c] || 0) }));
  groups.push({ label: "other CNAs", color: tint(P.steel, 0.18), data: years.map((y) =>
    Object.entries(cy[y] || {}).reduce((s, [c, n]) => s + (!topSet.has(c) && fin(n) ? n : 0), 0)) });
  // top assigner of the latest complete year → one data-driven sentence
  const hint = $("#cna-hint");
  try {
    const yr = years.filter((y) => y < String(new Date().getUTCFullYear())).at(-1);
    if (hint && yr) {
      const ent = Object.entries(cy[yr] || {}).filter(([c, n]) => c !== "other" && fin(n)).sort((a, b) => b[1] - a[1]);
      const sum = Object.values(cy[yr] || {}).reduce((s, n) => s + (fin(n) ? n : 0), 0);
      if (ent.length && sum) hint.textContent += ` In ${yr}, the largest assigner was ${prettyCna(ent[0][0])} (${pct(ent[0][1] / sum)} of AI CVEs).`;
    }
  } catch (e) { /* keep static hint */ }
  stackedBars(el, {
    xs: years.map(Number), groups, height: 280, time: false, xLabel: "year",
    yLabel: "AI CVEs per year", ariaLabel: "AI-related CVEs per year by assigning CNA, stacked",
    xValues: tick((v) => String(v)), xIncrs: [1, 2, 5], xSpace: 40, xFmt: (v) => String(v), barMax: 60,
  });
}

/* ================= methodology ================= */
function buildMethod(ctx) {
  const ol = $("#method-origins");
  const origins = originList(ctx.core);
  const OL = originLabel(ctx.core);
  if (ol) {
    const ids = origins ? origins.map((o) => o.id) : Object.keys(ORIGIN_FALLBACK);
    for (const id of ids) {
      const sw = h("span", { class: "swatch", "aria-hidden": "true" });
      sw.style.background = ORIGIN_COLORS[id] || OTHER_COLOR;
      ol.append(h("li", null, sw, h("b", { text: OL(id) }), document.createTextNode(ORIGIN_RULES[id] ? " — " + ORIGIN_RULES[id] : "")));
    }
    if (!origins) ol.after(h("p", { class: "na", text: "This data build predates per-origin classification; origin charts fall back to AI vs all other software." }));
  }
  const rl = $("#method-relations");
  if (rl) {
    const rels = ctx.rels && ctx.rels.length ? ctx.rels : null;
    if (rels) {
      const ry = relYtd(ctx.core, ctx.F);
      for (const r of rels) {
        const sw = h("span", { class: "swatch", "aria-hidden": "true" });
        sw.style.background = REL_COLORS[r.id] || OTHER_COLOR;
        const n = ry && ry[r.id] ? ` (${num.format(ry[r.id].cur)} in ${ctx.F.year})` : "";
        rl.append(h("li", null, sw, h("b", { text: ctx.relLabel(r.id) }), document.createTextNode((REL_RULES[r.id] ? " — " + REL_RULES[r.id] : "") + n)));
      }
    } else {
      rl.after(h("p", { class: "na", text: "This data build predates the AI relation tags: AI-related means AI software only." }));
      rl.remove();
    }
  }
  const ul = $("#method-layers");
  if (ctx.layers && ctx.layers.length) {
    for (const l of ctx.layers) ul.append(h("li", null, layerSwatch(l.id), h("b", { text: l.label || l.id }), h("span", { class: "lid", text: ` (${l.id})` })));
  } else {
    ul.remove();
    note($("#method"), "This data build predates the stack-layer definitions (keyword-only AI matching).");
  }
  const p = $("#method-eval");
  const ev = ctx.core.evaluation;
  if (ev && fin(ev.precision) && fin(ev.recall)) {
    // Recall is weighted by stratum size, so one miss in the huge "random"
    // stratum swings it; say so instead of presenting it as a precise figure.
    const st = ev.strata || {};
    const sus = st.suspect && fin(st.suspect.tp) && fin(st.suspect.fn) && st.suspect.tp + st.suspect.fn > 0
      ? ` Among AI-looking records the matcher did not flag, it caught ${st.suspect.tp} of ${st.suspect.tp + st.suspect.fn} genuine AI CVEs.` : "";
    const rnd = st.random && fin(st.random.n) ? ` (${st.random.fn || 0} miss in ${st.random.n} purely random records)` : "";
    p.textContent = `Measured on a hand-labelled sample of ${fin(ev.sample) ? num.format(ev.sample) : "?"} CVEs` +
      (ev.labeledAt ? ` (${ev.labeledAt})` : "") + ` for the AI-software matcher (AI software, MCP agents, AI features): precision ${pct(ev.precision)} — flagged CVEs are almost always genuinely AI software.` +
      sus + ` Population-weighted recall estimates ~${pct(ev.recall)}, but that figure is highly uncertain${rnd}: ` +
      "treat every AI count on this page as a lower bound. The weakness, compute and found-by-AI rules are not part of this sample; their rules are listed above." +
      (ev.method ? ` Method: ${ev.method}` : "");
  } else {
    p.textContent = "No measured precision/recall is available for this data build — treat the AI flag as approximate.";
  }
}

/* ================= chart framing: takeaway title, subtitle, how-to-read, so-what, source =================
 * Every chart/table gets: a title that states the data-computed takeaway, a
 * neutral subtitle (measure, unit, grain, window), a one-line "How to read",
 * an optional "So what" (only when the data supports an action) and a
 * source + freshness line. All text via textContent; anything that fails to
 * compute is skipped and the static HTML wording stays. */
const PRODUCT_NAMES = { tensorflow: "TensorFlow", openclaw: "OpenClaw", pytorch: "PyTorch", langflow: "Langflow", litellm: "LiteLLM", mlflow: "MLflow", vllm: "vLLM", ollama: "Ollama" };
const prettyProduct = (p) => (p ? PRODUCT_NAMES[String(p).toLowerCase()] || (String(p)[0].toUpperCase() + String(p).slice(1)) : p);
const CNA_NAMES = { GitHub_M: "GitHub (advisories)", certcc: "CERT/CC", "@certcc": "CERT/CC", "@huntr_ai": "huntr (Protect AI)", huntr_ai: "huntr (Protect AI)", mitre: "MITRE", VulnCheck: "VulnCheck",
  microsoft: "Microsoft", nvidia: "NVIDIA", ibm: "IBM", VulDB: "VulDB", apache: "Apache", intel: "Intel", oracle: "Oracle", redhat: "Red Hat", Wordfence: "Wordfence", Patchstack: "Patchstack", snyk: "Snyk", Google: "Google", INCD: "Israel NCD", other: "other CNAs" };
/* takeaway for "who reports": the assigner with the biggest jump on last
 * year (a new bulk filer moves the curve), else the largest assigner.
 * Assigners outside last year's top list were below its smallest entry. */
function cnaTitle(cnaYears, F, top, tot) {
  if (!top || !tot) return null;
  const cur = cnaYears[F.year] || {}, prev = cnaYears[F.prevYear] || {};
  const prevVals = Object.entries(prev).filter(([c]) => c !== "other").map(([, n]) => n);
  const floor = prevVals.length ? Math.min(...prevVals) : null;
  let best = null;
  for (const [c, n] of Object.entries(cur)) {
    if (c === "other") continue;
    const p = prev[c];
    const gain = n - (p != null ? p : floor || 0);
    if (!best || gain > best.gain) best = { c, n, p, gain };
  }
  const lead = `${prettyCna(top[0])} remains the largest assigner (${pct(top[1] / tot)})`;
  if (!best || best.gain < 0.25 * tot || best.c === top[0]) return `${prettyCna(top[0])} assigned ${pct(top[1] / tot)} of ${F.year}'s AI CVEs`;
  const before = best.p != null ? num.format(best.p) : floor != null ? `under ${num.format(floor)}` : "almost none";
  return `Who reports AI CVEs: ${prettyCna(best.c)} assigned ${num.format(best.n)} AI CVEs in ${F.year} so far, up from ${before} in all of ${F.prevYear} — ${lead}`;
}
const prettyCna = (c) => (c ? CNA_NAMES[c] || String(c).replace(/^@/, "").replace(/_/g, " ") : c);
function partialLabel(F) { const [, m, d] = F.asOf.split("-"); return `Jan–${MONTHS[+m - 1]} ${+d}`; }

function fig(host, o) {
  const el = typeof host === "string" ? $(host) : host;
  if (!el) return;
  const t = clean(o.title);
  if (t && o.titleEl && $(o.titleEl)) $(o.titleEl).textContent = t;
  const s = clean(o.sub);
  if (s && o.subEl && $(o.subEl)) $(o.subEl).textContent = s;
  const anchor = o.after ? (typeof o.after === "string" ? $(o.after) : o.after) || el : el;
  const foot = h("div", { class: "figfoot" });
  const how = clean(o.how), so = clean(o.so), src = clean(o.src);
  if (how) foot.append(h("p", { class: "how" }, h("b", { text: "How to read: " }), document.createTextNode(how)));
  if (so) foot.append(h("p", { class: "so" }, h("b", { text: "So what: " }), document.createTextNode(so)));
  if (src) foot.append(h("p", { class: "src", text: src }));
  if (foot.childNodes.length) anchor.after(foot);
}
const SITE = "cve.turrican.dk";
function srcLine(ctx, names) {
  const d = (x) => (x ? String(x).slice(0, 10) : null);
  const map = {
    cve: ["CVE List (cvelistV5)", d(ctx.core && ctx.core.generatedAt)],
    kev: ["CISA KEV", d(ctx.kev && ctx.kev.generatedAt)],
    epss: ["FIRST EPSS", ctx.epss && (ctx.epss.modelDate || d(ctx.epss.generatedAt))],
    osv: ["OSV.dev", d((ctx.ap && ctx.ap.generatedAt) || (ctx.mal && ctx.mal.generatedAt))],
    zd: [ctx.zd && ctx.zd.source ? ctx.zd.source : "zero-day tracker", d(ctx.zd && ctx.zd.generatedAt)],
    sev: ["CVE record CVSS (CNA/ADP), NVD fallback", d(ctx.sev && ctx.sev.generatedAt)],
  };
  const parts = names.map((n) => map[n]).filter(Boolean);
  const dates = parts.map((p) => p[1]).filter(Boolean).sort();
  return "Source: " + parts.map((p) => p[0]).join(" + ") + (dates.length ? ` · data as of ${dates[dates.length - 1]}` : "") + ` · ${SITE}`;
}
/* like-for-like: complete months Jan..(M-1) of this year vs the same months last year */
/* Year-to-date ratio over the build's one window (1 Jan → as-of day, both
 * years), overall or for one origin, with and without the bulk filers. */
function ytdRatio(core, origin) {
  const y = core && core.ytd;
  const c = y && (origin === "ai" ? y.ai : origin ? (y.origins || {})[origin] : y.all);
  if (!c || !c.prev) return null;
  const xc = c.cur - c.bulkCur, xp = c.prev - c.bulkPrev;
  return { cur: c.cur, prev: c.prev, r: c.cur / c.prev, rx: xp > 0 ? xc / xp : null, xcur: xc, xprev: xp,
    bulkShare: c.cur - c.prev > 0 ? (c.bulkCur - c.bulkPrev) / (c.cur - c.prev) : null };
}
const BULK_NAMES = "GitHub and VulnCheck";
/* one relation (agent, product …) over the same YTD window */
function ytdRel(core, rel) {
  const c = core && core.ytd && core.ytd.rels && core.ytd.rels[rel];
  if (!c || !c.prev) return null;
  const xp = c.prev - c.bulkPrev;
  return { cur: c.cur, prev: c.prev, rx: xp > 0 ? (c.cur - c.bulkCur) / xp : null };
}
function ytdMonths(core, arr, F) {
  if (!Array.isArray(arr) || !Array.isArray(core.months)) return null;
  const curM = +F.asOf.slice(5, 7);
  const lastFull = Math.max(1, curM - 1);
  let cur = 0, prev = 0;
  core.months.forEach((m, i) => {
    const mm = +m.slice(5, 7);
    if (mm > lastFull) return;
    if (m.startsWith(F.year)) cur += arr[i] || 0;
    if (m.startsWith(F.prevYear)) prev += arr[i] || 0;
  });
  return { cur, prev, label: lastFull === 1 ? "Jan" : `Jan–${MONTHS[lastFull - 1]}` };
}
const xr = (a, b) => (b > 0 ? `×${a / b >= 10 ? Math.round(a / b) : (a / b).toFixed(1)}` : null);

/* canvas annotations above the tallest bar of a given year (stacked charts:
 * u.data[1] is the top of the stack) */
/* malicious-package years ≥5× the median of the other years (since 2018):
 * {year: {eco, mult}}, eco = the ecosystem contributing most that year */
function malOutliers(mal) {
  const out = {};
  if (!mal || !mal.byYear) return out;
  const tot = {};
  for (const by of Object.values(mal.byYear)) {
    for (const [y, n] of Object.entries(by || {})) if (/^\d{4}$/.test(y) && y >= "2018" && fin(n)) tot[y] = (tot[y] || 0) + n;
  }
  for (const [y, n] of Object.entries(tot)) {
    const rest = Object.entries(tot).filter(([o, v]) => o !== y && v > 0).map(([, v]) => v).sort((a, b) => a - b);
    if (rest.length < 2) continue;
    const med = rest[Math.floor((rest.length - 1) / 2)];
    if (med > 0 && n >= 5 * med) {
      const eco = Object.entries(mal.byYear).sort((a, b) => ((b[1] || {})[y] || 0) - ((a[1] || {})[y] || 0))[0][0];
      out[y] = { eco, mult: Math.round(n / med) };
    }
  }
  return out;
}
/* " 2022 is mostly catch-up: X% of its additions were CVEs published before
 * 2021" — computed, and only said when the share is high (≥50%) */
/* KEV years that were mostly catalog catch-up (>= 40% of additions were CVEs
 * over three years old when listed): {year: "catch-up: N% old CVEs"} */
function kevCatchUpYears(kev) {
  const by = {};
  for (const e of (kev && kev.entries) || []) {
    if (!fin(e.daysToKev)) continue;
    const y = String(e.added).slice(0, 4), r = by[y] || (by[y] = { n: 0, old: 0 });
    r.n += 1; r.old += e.daysToKev > 1095 ? 1 : 0;
  }
  const out = {};
  for (const [y, r] of Object.entries(by)) if (r.n >= 50 && r.old / r.n >= 0.4) out[y] = `catch-up year: ${pct(r.old / r.n)} were CVEs 3+ years old`;
  return out;
}

/* y-axis cap that keeps normal years readable when an outlier year exists:
 * 1.4× the largest non-outlier year; outlier bars are clipped and labelled */
function malClipMax(mal, years) {
  const o = malOutliers(mal);
  if (!Object.keys(o).length) return null;
  const tot = (y) => Object.values(mal.byYear).reduce((s, by) => s + ((by || {})[y] || 0), 0);
  const normal = years.filter((y) => !o[y]).map(tot);
  return normal.length ? Math.max(1, Math.max(...normal) * 1.4) : null;
}
function malOutlierNotes(mal) {
  const o = malOutliers(mal);
  const tot = (y) => Object.values(mal.byYear).reduce((s, by) => s + ((by || {})[y] || 0), 0);
  const notes = Object.fromEntries(Object.entries(o).map(([y, v]) => [y, `${v.eco} spike: ${compact(tot(y))}, bar cut (×${v.mult})`]));
  return Object.keys(notes).length ? yearNotes(notes, false) : null;
}

function yearNotes(notes, isTime) {
  return (u) => {
    const c = u.ctx, xs = u.data[0], tops = u.data[1];
    if (!xs || !tops) return;
    const dpr = devicePixelRatio || 1;
    c.save();
    c.font = `${Math.round(11 * dpr)}px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`;
    c.fillStyle = P.axis;
    c.textAlign = "center";
    for (const [y, text] of Object.entries(notes)) {
      if (!text) continue;
      let bi = -1, bv = -1;
      xs.forEach((x, i) => {
        const yy = isTime ? new Date(x * 86400e3).getUTCFullYear() : x;
        if (String(yy) === String(y) && tops[i] != null && tops[i] > bv) { bv = tops[i]; bi = i; }
      });
      if (bi < 0) continue;
      const w = c.measureText(text).width;
      let px = u.valToPos(xs[bi], "x", true);
      const ymax = u.scales.y && u.scales.y.max;
      if (fin(ymax) && bv > ymax) {
        // clipped bar: the note goes beside it (left, or right if no room), never on it
        const half = 22 * dpr;
        const left = px - half - 6 * dpr - w >= u.bbox.left;
        c.textAlign = left ? "right" : "left";
        c.fillText(text, left ? px - half - 6 * dpr : px + half + 6 * dpr, u.bbox.top + 12 * dpr);
        c.textAlign = "center";
        continue;
      }
      px = Math.min(Math.max(px, u.bbox.left + w / 2 + 2), u.bbox.left + u.bbox.width - w / 2 - 2);
      const py = Math.max(u.bbox.top + 11 * dpr, u.valToPos(bv, "y", true) - 9 * dpr);
      c.fillText(text, px, py);
    }
    c.restore();
  };
}
function bulkNotes(F, minShare) {
  const out = {};
  const conc = F.concentration || {};
  for (const [y, c] of Object.entries(conc)) {
    const t = c && c.top && c.top[0];
    if (!t || !fin(t.n) || !fin(t.share)) continue;
    if ((t.share >= (minShare || 0.5) && t.n >= 100) || (y === F.year && t.n >= 300)) out[y] = `${prettyProduct(t.product)} bulk (${num.format(t.n)})`;
  }
  return out;
}

/* ---- per-panel framing ---- */
function explainSummary(ctx, F, S) {
  const core = ctx.core;
  // hero
  try {
    const OL = originLabel(core);
    let best = null;
    for (const id of Object.keys((core.ytd && core.ytd.origins) || {})) {
      const r = ytdRatio(core, id);
      if (r && r.prev >= 20 && (!best || r.r > best.r)) best = { id, ...r };
    }
    const t = S.total;
    const all = ytdRatio(core);
    const title = t && t.prev
      ? `CVEs ${xr(t.cur, t.prev)} vs the same period last year` + (all && all.rx ? ` (×${fmtX(all.rx)} without ${BULK_NAMES})` : "")
        + (best ? `; ${oShort(best.id, OL)} growing fastest (${xr(best.cur, best.prev)})` : "")
      : null;
    fig("#chart-hero", {
      titleEl: "#h-hero", title,
      subEl: "#hero-sub", sub: `Published CVEs per calendar year, 2018 → ${F.year} (${partialLabel(F)}), stacked by origin (what kind of software). Y-axis: CVEs per year.`,
      after: "#hero-note",
      how: "Each bar is one year's published CVE records; the coloured segments add up to the year's total. Pitfall: the last bar is a partial year, and CVE counts measure disclosure volume, not risk.",
      so: t && t.prev && t.cur / t.prev >= 1.3 ? "Expect the intake to keep growing: automate CVE intake, de-duplication and matching to your asset inventory, and judge risk by exploitation, not by count." : null,
      src: srcLine(ctx, ["cve"]),
    });
  } catch (e) { /* keep static */ }
  // where exploitation happens
  try {
    const k = S.kev;
    if (k && k.cur) {
      const OL = originLabel(core);
      let title = null, so = null;
      if (k.origin) {
        const lead = Object.entries(k.origin).sort((a, b) => b[1] - a[1]).slice(0, 3);
        if (lead.length) {
          const n = lead.reduce((t, [, x]) => t + x, 0);
          // lead with the origin most over-represented among exploited CVEs vs new CVEs
          // one cohort: CVEs PUBLISHED this year — exploited ones (KEV) vs all new ones,
          // the latter without the bulk filers (their surge would shrink every other share)
          const yo = (core.ytd && core.ytd.origins) || {}, ya = core.ytd && core.ytd.all;
          const pubK = ((ctx.kev && ctx.kev.entries) || []).filter((e) => String(e.published || "").startsWith(F.year));
          const kBy = {}; for (const e of pubK) kBy[e.origin || "other"] = (kBy[e.origin || "other"] || 0) + 1;
          const baseN = ya ? ya.cur - (ya.bulkCur || 0) : 0;
          const over = baseN && pubK.length >= 50 ? Object.entries(kBy).filter(([id, x]) => x >= 10 && yo[id] && yo[id].cur - (yo[id].bulkCur || 0) > 0)
            .map(([id, x]) => ({ id, x, ks: x / pubK.length, cs: (yo[id].cur - (yo[id].bulkCur || 0)) / baseN })).map((o) => ({ ...o, r: o.ks / o.cs })).sort((a, b) => b.r - a.r)[0] : null;
          if (over && over.r >= 2) {
            title = `${oShort(over.id, OL).replace(/^./, (c) => c.toUpperCase())} are ${pct(over.ks)} of the CVEs published in ${F.year} that CISA KEV lists (${num.format(over.x)} of ${num.format(pubK.length)}) but ${pct(over.cs, 1)} of all new CVEs: about ${fmtX(over.r)} times their share`;
          } else {
            title = `${listJoin(lead.map(([id]) => oShort(id, OL)))} make up ${pct(n / k.cur)} of ${F.year}'s exploited vulnerabilities`; title = title[0].toUpperCase() + title.slice(1);
          }
          so = over && over.id === "edge"
            ? "Put internet-facing appliances on a days-not-weeks patch track and take their management interfaces off the internet."
            : `Keep emergency patching and attack-surface monitoring focused on ${listJoin(lead.map(([id]) => oShort(id, OL)))}.`;
        }
      }
      fig("#where-bars", {
        titleEl: "#h-where", title,
        subEl: "#where-hint", sub: (() => {
          const pubN = ((ctx.kev && ctx.kev.entries) || []).filter((e) => String(e.published || "").startsWith(F.year) && e.origin).length;
          const older = k.cur - ((ctx.kev && ctx.kev.entries) || []).filter((e) => String(e.added).startsWith(F.year) && String(e.published || "").startsWith(F.year)).length;
          return `The ${num.format(pubN)} CVEs published in ${F.year} (${partialLabel(F)}) that CISA KEV lists, by origin: count · share of them (that origin's share of all new CVEs, without bulk filers).${older > 0 ? ` The ${num.format(older)} older CVEs CISA added this year are left out.` : ""}`;
        })(),
        how: "Bar length = CVEs published this year that CISA lists as exploited; the bracket = that origin's share of all new CVEs (without bulk filers), so a share far above its bracket means over-represented. Pitfall: KEV is a lower bound weighted to products US agencies run and to flaws incident responders report, which favours enterprise appliances; the multiple is KEV-shaped, the direction matches other exploitation reports.",
        so, src: srcLine(ctx, ["kev"]),
      });
    }
  } catch (e) { /* keep static */ }
}

function explainRisk(ctx, F, S) {
  const core = ctx.core;
  const OL = originLabel(core);
  try {
    const k = S.kev;
    let so = null;
    const ents = ((ctx.kev && ctx.kev.entries) || []).filter((e) => e.zeroDay && String(e.published || "").startsWith(F.year));
    if (ents.length && ents.every((e) => e.origin)) {
      const c = {};
      for (const e of ents) c[e.origin] = (c[e.origin] || 0) + 1;
      const top = Object.entries(c).sort((a, b) => b[1] - a[1])[0];
      if (top) so = `${num.format(top[1])} of ${num.format(ents.length)} were ${oShort(top[0], OL)}. These were exploited by the time they were published: assume compromise was possible, hunt in logs from before the patch date, and pre-stage mitigations for these products.`;
    }
    fig("#chart-zeroday", {
      titleEl: "#h-zd",
      title: k && fin(k.zd) ? `${num.format(k.zd)} CVEs published in ${F.year} were listed in CISA KEV within a day of publication (a zero-day proxy)` : null,
      subEl: "#zd-hint", sub: `KEV entries added ≤1 day after the CVE was published, per CVE publication year, 2022 → ${F.year} (${partialLabel(F)}). Not stacked.`,
      how: (() => {
        // the proxy against an independent zero-day list: how many of its recent entries it catches
        const rz = ((ctx.zd && ctx.zd.recent) || []).filter((r) => r.cve), byCve = new Map(((ctx.kev && ctx.kev.entries) || []).map((e) => [e.cve, e]));
        const caught = rz.filter((r) => (byCve.get(r.cve) || {}).zeroDay).length;
        const cmp = rz.length >= 10 ? ` Of the ${rz.length} most recent in-the-wild zero-days tracked by Google Project Zero, it catches ${caught}.` : "";
        return `A proxy for zero-days: CISA listed the CVE as exploited within a day of its publication. It misses zero-days CISA lists later and does not fill in afterwards; it also rises when CISA lists faster, so year-on-year changes are not a zero-day trend.${cmp}`;
      })(),
      so, src: srcLine(ctx, ctx.zd ? ["kev", "zd"] : ["kev"]),
    });
    const zb = ctx.zd && ctx.zd.byYear;
    const zprods = ctx.zd && ctx.zd.recent ? [...new Set(ctx.zd.recent.map((r) => shortProduct(tidyProduct([r.vendor, r.product].filter(Boolean).join(" "))) || r.product).filter(Boolean))].slice(0, 3) : [];
    fig("#tbl-zd", {
      titleEl: "#h-zdlist",
      title: zb && fin(zb[F.year]) ? `${num.format(zb[F.year])} in-the-wild zero-days patched in ${F.year} so far (${num.format(zb[F.prevYear] || 0)} in all of ${F.prevYear})` + (zprods.length ? `; the latest hit ${listJoin(zprods)}` : "") : null,
      so: "If you run these products, patch status is not enough: review logs from before the patch date for signs of earlier compromise.",
      subEl: "#zd-list-hint", sub: ctx.zd && ctx.zd.recent ? `Latest in-the-wild zero-days, newest first (${ctx.zd.source || "tracker"}).` : "Latest KEV entries added ≤1 day after publication, newest first; date = added to KEV.",
      src: srcLine(ctx, ctx.zd ? ["zd"] : ["kev"]),
    });
  } catch (e) { /* skip */ }
  try {
    const sc = ytdRatio(core, "supplychain");
    fig("#chart-supply", {
      titleEl: "#h-supply-cves",
      title: sc ? `Open-source CVEs ${xr(sc.cur, sc.prev)}: ${num.format(sc.cur)} so far in ${F.year} vs ${num.format(sc.prev)} by this date in ${F.prevYear}`
        + (sc.bulkShare != null && sc.bulkShare >= 0.5 ? `; ${pct(sc.bulkShare)} of the rise is ${BULK_NAMES} filing${fin(sc.rx) ? `, but without them it is still ×${fmtX(sc.rx)}` : ""}` : "") : null,
      subEl: "#supply-hint", sub: `CVEs in open-source projects and packages (registry packages + GitHub-assigned OSS records), per year, 2018 → ${F.year} (${partialLabel(F)}). Not stacked.`,
      how: "Each bar = open-source CVEs published that year (registry packages plus GitHub-assigned OSS projects, AI packages included). Pitfall: much of the recent jump comes from GitHub's CNA (GitHub_M) issuing far more CVEs — partly a reporting change, not only more vulnerable code.",
      so: sc && sc.prev && sc.cur / sc.prev >= 1.3 ? "The growth is real beyond the filing change: make sure dependency scanning (SCA) and open-source patching cover every build pipeline." : null,
      src: srcLine(ctx, ["cve"]),
    });
  } catch (e) { /* skip */ }
  try {
    const mal = ctx.mal;
    if (mal && mal.byYear) {
      let cur = 0;
      for (const by of Object.values(mal.byYear)) cur += fin(by && by[F.year]) ? by[F.year] : 0;
      fig("#chart-malicious", {
        titleEl: "#h-mal", title: cur ? `${num.format(cur)} malicious open-source packages reported in ${F.year} so far` : null,
        subEl: "#mal-hint", sub: `Malicious packages reported to OSV (MAL-* advisories) per year by ecosystem, stacked, through ${F.year} (${partialLabel(F)}). These are not CVEs.`,
        how: "Each bar = malicious-package reports that year, split by registry. Pitfall: " + (Object.entries(malOutliers(mal))
          .map(([y, o]) => `${y} is ${o.mult} times a typical year, almost all ${o.eco} — a mass spam/campaign wave that flattens the other years; `)
          .join("") || "") + "one report can cover many package versions.",
        so: cur ? "Block or quarantine newly published packages in your package proxy and pin dependencies — malicious uploads now arrive by the thousand." : null,
        src: srcLine(ctx, ["osv"]),
      });
    }
  } catch (e) { /* skip */ }
}

/* " N of M show EPSS under 10% despite confirmed exploitation …" — the trap
 * of reading a low EPSS on a KEV entry as "safe to defer" */
/* the score the day BEFORE CISA listed each CVE, as in the table's column: today's
 * score already reflects the exploitation, so it would understate the miss */
function lowEpssNote(rows, prior) {
  const sc = prior && prior.scores;
  if (!sc || !rows || !rows.length) return "";
  const scored = rows.filter((r) => sc[r.cve]);
  const low = scored.filter((r) => !fin(sc[r.cve].epss) || sc[r.cve].epss < 0.1).length;
  return low ? ` ${low} of ${scored.length} had an EPSS under 10% (or no score) the day before CISA listed them: EPSS predicts broad, near-term activity and misses targeted attacks, so a low score on a KEV entry does not mean safe to defer.` : "";
}

function explainAi(ctx, F) {
  const core = ctx.core;
  try {
    const rows = F.kevAi || [];
    const prods = kevProducts(F);
    fig("#tbl-kev", {
      titleEl: "#h-exploited",
      title: rows.length ? `Exploited AI-related vulnerabilities: ${num.format(rows.length)} CVEs across ${prods.length} product${prods.length === 1 ? "" : "s"}, ${num.format(F.kevAiThisYear)} added in ${F.year}` : null,
      subEl: "#kev-hint", sub: "AI-related CVEs in CISA's Known Exploited Vulnerabilities catalog, sorted by date added to KEV, newest first. AI relation = why the CVE counts as AI-related. Days to KEV = days from CVE publication to KEV addition.",
      how: "Each row is confirmed in-the-wild exploitation. EPSS = FIRST's estimated 30-day exploitation probability. Pitfall: KEV is a lower bound."
        + lowEpssNote(rows, ctx.epssPrior),
      so: prods.length ? `If you run ${listJoin(prods.map((p) => p.name))}, verify these CVEs are patched now — KEV status outranks any EPSS or CVSS score.` : null,
      src: srcLine(ctx, ["kev", "epss"]),
    });
  } catch (e) { /* skip */ }
  try {
    const ep = ctx.epss && ctx.epss.scores;
    if (ep) {
      const d = ctx.epss.dist && ctx.epss.dist.ai;
      fig("#tbl-epss", {
        titleEl: "#h-patch", title: d && d.n ? `${num.format(d.ge10)} of ${num.format(d.n)} AI-related CVEs from the last 12 months have an EPSS of 10% or more — these are the top ones not yet in KEV` : null,
        subEl: "#epss-hint", sub: "AI-related CVEs published in the last 12 months and not in CISA KEV, ranked by FIRST EPSS (estimated probability of exploitation activity in the next 30 days), highest first.",
        how: "EPSS is a model estimate (0–100%), not observed exploitation. AI relation = why it counts as AI-related; 'found by AI' alone never qualifies a CVE here.",
        so: "Order of work: the exploited table above first (confirmed exploitation, whatever its EPSS), then this list from the top.",
        src: srcLine(ctx, ["epss", "kev"]),
      });
    }
  } catch (e) { /* skip */ }
}

function explainDetail(ctx, F, S) {
  const core = ctx.core;
  try {
    const cc = core.cweCompare;
    if (cc && cc.ai && cc.all && cc.aiTotal && cc.allTotal) {
      const names = (ctx.sev && ctx.sev.cweNames) || {};
      let best = null;
      for (const [id, n] of Object.entries(cc.ai)) {
        const a = n / cc.aiTotal, b = (cc.all[id] || 0) / cc.allTotal;
        if (a >= 0.03 && b > 0 && (!best || a / b > best.r)) best = { id, a, b, r: a / b };
      }
      fig("#cwe-compare", {
        titleEl: "#h-cwe",
        title: best ? `${names[best.id] || best.id} is ${best.r.toFixed(1)} times more common in AI CVEs than in non-AI CVEs (${pct(best.a, 1)} vs ${pct(best.b, 1)})` : null,
        how: "Blue = share of AI CVEs with that CWE; grey = share of non-AI CVEs. Pitfall: only the first CWE of each record counts; '—' = not among the top CWEs overall.",
        so: best ? `Ask AI vendors and internal AI teams specifically about ${names[best.id] || best.id} defences.` : null,
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
  try {
    const ya = core.ytd && core.ytd.ai, yall = core.ytd && core.ytd.all;
    const ytd = ya ? { cur: ya.cur, prev: ya.prev } : null, all = yall ? { cur: yall.cur, prev: yall.prev } : null;
    fig("#chart-cves", {
      so: "AI is a growing slice of the patch workload: put AI tooling in the asset inventory so these CVEs reach an owner.",
      titleEl: "#h-issuance",
      title: ytd && all && all.cur && all.prev ? `AI's share of all CVEs: ${pct(ytd.cur / all.cur, 1)} so far in ${F.year} vs ${pct(ytd.prev / all.prev, 1)} by this date in ${F.prevYear}` : null,
      subEl: "#issuance-hint", sub: "AI-related CVEs as a % of all published CVEs, per month since 2018. Spikes are single-product bulk disclosures (e.g. TensorFlow 2021, OpenClaw 2026). Switch Mode to Count or Cumulative for absolute numbers (lines, not stacked).",
      after: "#ctl-cves",
      how: "Count = CVEs per period; Cumulative = running total; AI share % = AI ÷ all per period. Pitfall: the last period is partial.",
      src: srcLine(ctx, ["cve"]),
    });
  } catch (e) { /* skip */ }
  try {
    const cy = core.cnaYears && core.cnaYears[F.year];
    if (cy) {
      const tot = sumObj(cy);
      const top = Object.entries(cy).filter(([c]) => c !== "other").sort((a, b) => b[1] - a[1])[0];
      fig("#chart-cna", {
        so: "Part of the AI rise is who files CVEs: judge AI risk by exploitation and your own exposure, not by count alone.",
        titleEl: "#h-cna", title: cnaTitle(core.cnaYears, F, top, tot),
        how: "Stacked: each colour is one CVE Numbering Authority's AI CVEs that year (top 7 overall + other CNAs). Pitfall: one prolific new CNA raises counts without more vulnerable software.",
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
}


function explainPart1(ctx, F, S) {
  const core = ctx.core;
  const OL = originLabel(core);
  const L = core.landscape && core.landscape.all;
  try {
    const by = ttkBuckets((ctx.kev && ctx.kev.entries) || [], F.year)[F.year];
    if (by) {
      const n = sumObj(by), wk = (by.d1 || 0) + (by.w1 || 0);
      fig("#chart-ttk", {
        titleEl: "#h-ttk", title: (() => {
          const c = ttkCohort(ctx);
          return c && c.full && c.full.n >= 20 && c.prev ? `${pct(c.full.wk / c.full.n)} of exploited CVEs reach KEV within a week of publication, and the pace is ${Math.abs(c.cur.wk / c.cur.n - c.prev.wk / c.prev.n) < 0.05 ? "steady" : c.cur.wk / c.cur.n > c.prev.wk / c.prev.n ? "rising" : "falling"}`
            : n ? `${pct(wk / n)} of ${F.year}'s KEV additions came within a week of publication` : null;
        })(),
        subEl: "#ttk-hint", sub: `CISA KEV additions per year (by date added), 2022 → ${F.year} (${partialLabel(F)}), stacked by days from CVE publication to KEV addition.`,
        how: "Bars: KEV additions per year by days from CVE publication to KEV addition; red/orange = within a week, grey = old CVEs newly confirmed as exploited. The title uses cohorts instead: the level comes from CVEs published 13–24 months ago (fully followed up; recent CVEs that will be listed slowly are not listed yet), the trend compares the last 12 months with the year before at equal follow-up. Pitfall: this is time to KEV listing, not time to first exploitation; attacks often started earlier.",
        so: (() => { const c = ttkCohort(ctx); const share = c && c.full && c.full.n >= 20 ? c.full.wk / c.full.n : n ? wk / n : 0;
          return share >= 0.25 ? `A monthly patch cycle is too slow for ${pct(share)} of exploited CVEs: keep an emergency path that can ship a fix or mitigation within days.` : null; })(),
        src: srcLine(ctx, ["kev", "cve"]),
      });
    }
  } catch (e) { /* skip */ }
  try {
    const ents = (ctx.kev && ctx.kev.entries) || [];
    const yr = ents.filter((e) => String(e.added).startsWith(F.year));
    const rw = yr.filter((e) => e.ransomware).length;
    fig("#tbl-kevall", {
      titleEl: "#h-kevall", title: yr.length ? `Latest exploited vulnerabilities — ${num.format(yr.length)} added in ${F.year}, ${num.format(rw)} linked to ransomware` : null,
      subEl: "#kevall-hint", sub: "The 15 most recent CISA KEV additions, newest first. RANSOMWARE = CISA knows of ransomware use; AT DISCLOSURE = added within one day of the CVE's publication (a zero-day proxy, not confirmed zero-day exploitation).",
      how: "Every row is confirmed in-the-wild exploitation. EPSS = estimated chance of exploitation activity in the next 30 days.",
      so: "If you run any of these products, these come before everything else in the patch queue.",
      src: srcLine(ctx, ["kev", "epss"]),
    });
  } catch (e) { /* skip */ }
  try {
    const d = ctx.epss && ctx.epss.dist && ctx.epss.dist.all;
    fig("#tbl-next", {
      titleEl: "#h-next", title: d && d.n ? `${num.format(d.ge10)} of the last 12 months' ${num.format(d.n)} EPSS-scored CVEs are at 10% or more — the top ones are not in KEV yet` : null,
      subEl: "#next-hint", sub: "CVEs published in the last 12 months that are not in CISA KEV, ranked by FIRST EPSS (estimated probability of exploitation activity in the next 30 days), highest first.",
      how: "EPSS is a model estimate of exploitation activity in the next 30 days, not observed exploitation. It also misses real exploitation: many CVEs in KEV scored below 10% before they were listed.",
      so: (() => {
        if (!d || !d.n) return null;
        const st = signalStages(ctx);
        const miss = st && st.recall ? ` It is a ranking aid, not a safety net: the day before CISA listed them, ${pct(1 - st.recall.caught / st.recall.of)} of the CVEs confirmed exploited in the same period scored below 10% or had no score.` : "";
        return `Fewer than ${pct(Math.max(d.ge10 / d.n, 0.001), 1)} of new CVEs clear 10% EPSS: after KEV, work this list from the top, weighted by your exposure and asset criticality.${miss}`;
      })(),
      src: srcLine(ctx, ["epss", "kev", "cve"]),
    });
  } catch (e) { /* skip */ }
  try {
    const sy = L && L.sevYears;
    if (sy) {
      fig("#chart-sevall", {
        titleEl: "#h-sevall", title: (() => {
          // the Linux kernel CNA rates few of its CVEs, nearly all HIGH: lead with the share without it
          const sx = L.sevYearsXLinux, sy = L.sevYears;
          const hcOf = (o) => { if (!o) return null; const r = SEV_KEYS.reduce((t, k) => t + (o[k] || 0), 0); return r ? ((o.CRITICAL || 0) + (o.HIGH || 0)) / r : null; };
          const xc = sx && hcOf(sx[F.year]), xp = sx && hcOf(sx[F.prevYear]);
          if (fin(xc) && sy && sy[F.year]) {
            const lin = {}; for (const k of SEV_KEYS.concat("UNRATED")) lin[k] = (sy[F.year][k] || 0) - (sx[F.year][k] || 0);
            const lr = SEV_KEYS.reduce((t, k) => t + lin[k], 0), lt = lr + lin.UNRATED;
            return `${pct(xc)} of ${F.year}'s rated CVEs are HIGH or CRITICAL${fin(xp) ? ` (${pct(xp)} in ${F.prevYear})` : ""}, excluding the Linux kernel, which rates ${lt ? pct(lr / lt) : "few"} of its CVEs, nearly all HIGH`;
          }
          return S.hc && fin(S.hc.cur) ? `${pct(S.hc.cur)} of ${F.year}'s rated CVEs are HIGH or CRITICAL` + (fin(S.hc.prev) ? ` (${pct(S.hc.prev)} in ${F.prevYear})` : "") : null;
        })(),
        subEl: "#sevall-hint", sub: `Published CVEs per year, 2018 → ${F.year} (${partialLabel(F)}), stacked by CVSS severity from the CVE record (CNA, else CISA-ADP).`,
        how: "Segments add up to the year's CVEs, CRITICAL at the bottom, unrated on top. Severity is the vendor's CVSS base score: worst-case impact, not likelihood of attack.",
        so: S.hc && fin(S.hc.cur) && S.hc.cur >= 0.4 ? `A severity-based SLA ("all HIGH within 30 days") now covers ${S.hc.cur > 0.5 ? "more than half of" : "about half of"} new CVEs: tie remediation SLAs to exploitation and exposure instead.` : null,
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
  try {
    if (L) {
      const names = (ctx.sev && ctx.sev.cweNames) || {};
      const w = L.window || {};
      const span = w.cur ? `${w.cur[0]} to ${w.cur[1]}` : "the last 12 months";
      const cw = shareRiser(cweRows(L.cweTop, names), w, 100);
      fig("#cweall", {
        so: "Fund fixes that remove whole weakness classes (authorization checks, input handling, memory safety) instead of patching one CVE at a time.",
        titleEl: "#h-cweall", title: cw ? `Fastest-growing weakness: ${cw.label}, ${growthText(cw.gn, cw.gprev)} against ×${fmtX(cw.base)} for all CVEs${cw.ex ? ` (both without the year's ${surgeWord(L)})` : ""}`
          : baseX(w) ? `No top weakness class outgrew all CVEs (${baseX(w)})` : null,
        subEl: "#cweall-hint", sub: `CVEs per weakness class (first CWE in the record), ${span} vs the 12 months before. Top 10.`,
        how: `Bar = last 12 months, tick = the 12 months before. 'Fastest-growing' = largest rise in share of all CVEs, among classes with at least 100 CVEs the year before, computed without the year's ${surgeWord(L)} (${surgeDef(L)}). Pitfall: a CVE counts once, under its first CWE; many records have none.`,
        src: srcLine(ctx, ["cve"]),
      });
      const vr = exRows(vendorRows(L.vendorTop));
      const vb = shareRiser(vr, w, 100);
      fig("#vendall", {
        so: "Counts reflect product footprint and reporting practice: use them to plan vendor patch cadence, not to rank vendor security.",
        titleEl: "#h-vendall", title: vr.length ? `${vr[0].label} leads with ${num.format(vr[0].n)} CVEs` + (vb && vb !== vr[0] ? `; ${vb.label} grew fastest (${growthText(vb.gn, vb.gprev)} against ×${fmtX(vb.base)}${vb.ex ? `, without ${surgeWord(L)}` : ""})` : "") : null,
        subEl: "#vendall-hint", sub: `CVEs per vendor (first affected vendor in the record), ${span} vs the 12 months before. Top 10.`,
        how: "Bar = last 12 months, tick = the 12 months before. Pitfall: vendors that file their own CVEs (Linux, Microsoft, Oracle) look larger than vendors whose bugs go unreported.",
        src: srcLine(ctx, ["cve"]),
      });
      const cr = cnaRows(L.cnaTop);
      const cb = topRiser(cr);
      const sn = (L.surgeCnas || []).length, bulkAdd = fin(w.nx) ? (w.n - w.nx) - (w.prevN - w.prevNx) : null;
      fig("#cnaall", {
        titleEl: "#h-cnaall", title: sn && fin(bulkAdd) && w.prevNx
          ? `Who files moves the curve: ${sn} ${surgeWord(L)} added ${num.format(bulkAdd)} CVEs in the last 12 months; everyone else grew ${growthText(w.nx, w.prevNx)}`
          : cb ? `Who files moves the curve: ${cb.label} filed ${num.format(cb.n)} CVEs in the last 12 months (${growthText(cb.n, cb.prev)}, against ${baseX(w)} for all CVEs)` : null,
        subEl: "#cnaall-hint", sub: `CVEs per CVE Numbering Authority (assigner), ${span} vs the 12 months before: the year's ${surgeWord(L)} (${surgeDef(L)}) that rank in the top 12, and everyone else combined.`,
        how: "Bar = last 12 months, tick = the 12 months before. A CNA is whoever assigned the CVE id — a vendor, a bug-bounty platform or a coordinator.",
        so: cb && cb.n / Math.max(1, cb.prev) >= 3 ? "Before reading the surge as more vulnerable software, discount these filers: their growth is largely a change in who files CVEs and how many, not in how much software is vulnerable." : null,
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
}

function explainPart2(ctx, F, S) {
  const core = ctx.core;
  try {
    const ry = relYtd(core, F);
    if (ry) {
      const top = Object.entries(ry).sort((a, b) => b[1].cur - a[1].cur)[0];
      const yr = Object.keys(ry).map((id) => [id, ytdRel(core, id)]).filter(([, y]) => y && y.prev >= 20);
      const fast = yr.sort((a, b) => b[1].cur / b[1].prev - a[1].cur / a[1].prev)[0];
      fig("#rel-bars", {
        titleEl: "#h-rel", title: top ? `${ctx.relLabel(top[0])} account for ${S.aiShare && S.aiShare.n && top[1].cur / S.aiShare.n > 0.5 ? "most" : "the largest share of"} AI-related CVEs in ${F.year} (${num.format(top[1].cur)}${S.aiShare && S.aiShare.n ? `, ${pct(top[1].cur / S.aiShare.n)}` : ""})` + (fast && fast[0] !== top[0] ? `; ${lcFirst(ctx.relLabel(fast[0]))} grew fastest` : "") : null,
        subEl: "#rel-hint", sub: `AI-related CVEs published in ${F.year} (${partialLabel(F)}) by kind of AI relation. A CVE can carry several tags, so the bars add up to more than the AI-related total.`,
        how: (() => {
          const t = core.concentration && core.concentration[F.year] && (core.concentration[F.year].top || [])[0];
          const bulk = t && t.share >= 0.1 ? ` ${F.year} includes one bulk disclosure: ${t.product}, ${num.format(t.n)} CVEs (${pct(t.share)} of AI-related), mostly via ${prettyCna(t.cna)}.` : "";
          return `Bar = this year's count per relation; text = count · change on the same days last year (both counts when last year had fewer than 10), and without ${BULK_NAMES} where that differs. Pitfall: one project's batch of reports can dominate a relation.${bulk}`;
        })(),
        so: "Two different jobs: AI software and agents need asset inventory and patching like any software; AI features, weaknesses and compute need you to ask vendors how their AI is isolated.",
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
  try {
    const L = core.landscape && core.landscape.ai;
    if (L && L.originYears && L.years && L.years[F.year]) {
      const OL = originLabel(core);
      const n = L.years[F.year];
      const top = Object.entries(L.originYears).map(([id, by]) => [id, by[F.year] || 0]).sort((a, b) => b[1] - a[1])[0];
      fig("#chart-aiorigin", {
        so: "Most AI exposure arrives through open-source components: AI packages belong in dependency scanning and SBOMs.",
        titleEl: "#h-aiorigin", title: top && top[1] ? `${pct(top[1] / n)} of ${F.year}'s AI-related CVEs are in ${oShort(top[0], OL)}` : null,
        subEl: "#aiorigin-hint", sub: `AI-related CVEs per year, 2018 → ${F.year} (${partialLabel(F)}), stacked by origin — the same categories as Part 1.`,
        how: "Segments add up to each year's AI-related CVEs. This connects the two parts: e.g. open-source AI packages count under supply chain, Copilot under core platforms.",
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
}


/* Top-nav sub-menus: hovering (or tabbing to) a part lists its sections.
 * Short static names: the on-page titles are full takeaway sentences. */
const NAV_SUB = {
  brief: [],
  summary: [["kpis", "Key figures"], ["hero", "CVEs per year"], ["signal", "Signal vs noise"], ["where", "Where exploitation happens"]],
  exploit: [["kev-vendors", "Exploited by vendor"], ["ransom", "Ransomware-linked"], ["speed", "Time to KEV listing"], ["kev-latest", "Latest KEV additions"], ["zerodays", "Zero-days"], ["next", "Patch next"]],
  volume: [["sevyears", "Severity per year"], ["tops", "Top weaknesses, vendors & CNAs"], ["supply", "Supply chain"]],
  ai: [["ai-kpis", "Key figures"], ["exploited", "Exploited AI vulnerabilities"], ["ai-next", "AI patch next"], ["relations", "How CVEs relate to AI"], ["issuance", "AI share of all CVEs"], ["ai-origin", "Where AI CVEs come from"], ["breaks", "AI weakness classes"], ["cna", "Who reports AI CVEs"]],
  method: [],
};
function buildNavMenus() {
  for (const a of [...document.querySelectorAll(".topnav > a")]) {
    const items = (NAV_SUB[a.getAttribute("href").slice(1)] || []).filter(([id]) => document.getElementById(id));
    if (!items.length) continue;
    const wrap = h("span", { class: "navitem" });
    a.replaceWith(wrap);
    const menu = h("span", { class: "navsub" }, ...items.map(([id, label]) => h("a", { class: "sub", href: "#" + id, text: label })));
    wrap.append(a, menu);
    // a click inside the menu closes it (hover would otherwise keep it open)
    menu.addEventListener("click", () => { wrap.classList.add("shut"); });
    wrap.addEventListener("mouseleave", () => wrap.classList.remove("shut"));
  }
}

/* Long tables show their first rows; the rest sit behind one quiet toggle.
 * Rows stay in the DOM (filters and print still see them). */
const TABLE_CLIP = { "tbl-kevall": 5, "tbl-zd": 5, "tbl-next": 5, "tbl-kev": 5, "tbl-epss": 5, "tbl-ai": 8 };
function clipTables() {
  for (const [id, n] of Object.entries(TABLE_CLIP)) {
    const table = document.getElementById(id);
    if (!table) continue;
    const rows = [...table.querySelectorAll("tbody tr")];
    if (rows.length <= n + 2) continue;
    rows.slice(n).forEach((tr) => tr.classList.add("more"));
    table.classList.add("clip");
    const label = () => (table.classList.contains("open") ? "Show fewer" : `Show all ${rows.length} rows`);
    const btn = h("button", { type: "button", class: "showall", text: label() });
    btn.setAttribute("aria-expanded", "false");
    btn.setAttribute("aria-controls", id);
    btn.addEventListener("click", () => {
      const open = table.classList.toggle("open");
      btn.textContent = label();
      btn.setAttribute("aria-expanded", String(open));
      if (!open) table.scrollIntoView({ block: "nearest" });
    });
    table.after(btn);
    table._clipBtn = btn;
  }
}

/* ================= slide cards =================
 * Every chart or table is one self-contained card (takeaway title, visual,
 * "So what", visible source + date + site), so a screenshot can go straight
 * onto a slide. Panels holding several charts become a group of cards. */
function slideify() {
  const units = [];
  for (const p of document.querySelectorAll("main section.panel, main section.context, main .sumgrid > .panel")) {
    if (p.closest("#method")) continue;
    const subs = p.querySelectorAll(":scope > .sub, :scope > .duo > .sub, :scope > .duo > .panel");
    if (subs.length) { p.classList.add("slide-group"); units.push(...subs); } else units.push(p);
  }
  for (const u of units) {
    u.classList.add("slide");
    if (!u.querySelector("h2, h3")) {
      const gh = u.closest(".slide-group") && u.closest(".slide-group").querySelector(":scope > h2");
      if (gh) { u.prepend(gh); const hint = u.parentElement.closest(".slide-group").querySelector(":scope > p.hint"); if (hint) gh.after(hint); }
    }
    if (u.querySelector(".src")) continue;
    // borrow the group's source line, else a generic one
    const g = u.closest(".slide-group");
    const src = g && g.querySelector(".src");
    let foot = u.querySelector(":scope > .figfoot");
    if (!foot) { foot = h("div", { class: "figfoot" }); u.append(foot); }
    foot.append(h("p", { class: "src", text: src ? src.textContent : `Source: ${SITE}` }));
  }
}

/* ================= quiet layout: details behind an ⓘ =================
 * Each chart/table keeps its takeaway title, the visual and the "So what"
 * line. Subtitle, notes, "How to read" and the source line move into a panel
 * that opens on hover (mouse), on tap (touch) and on focus (keyboard). */
let infoSeq = 0;
function infoize() {
  const heads = document.querySelectorAll("main h2[id^='h-'], main h3[id^='h-'], main .headline");
  for (const t of heads) {
    if (t.closest("#method") || t.closest(".todo") || t.closest(".exploited-strip")) continue;
    const BLOCK = ".sub, .panel, section, .tier";
    const block = t.parentElement.closest(BLOCK) || t.parentElement;
    // lines that belong to this title's block, not to a nested sub-panel
    const items = [...block.querySelectorAll("p.hint, p.subhead, p.note, .figfoot > p.how")]
      .filter((el) => el.parentElement.closest(BLOCK) === block && !el.closest(".info-body") && el.textContent.trim() && !el.classList.contains("toplegend"));
    // a headline's info is only its own subhead
    const pick = t.matches(".headline") ? items.filter((el) => el.matches(".subhead")) : items.filter((el) => !el.matches(".subhead"));
    if (!pick.length) continue;
    const id = "info-" + (++infoSeq);
    const body = h("div", { class: "info-body", id, role: "note" });
    for (const el of pick) { el.classList.add("in-info"); body.append(el); }
    const btn = h("button", { type: "button", class: "info-btn", "aria-expanded": "false", "aria-controls": id, title: "What am I looking at?", text: "i" });
    btn.setAttribute("aria-label", "Details about this chart");
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const open = !body.classList.contains("open");
      document.querySelectorAll(".info-body.open").forEach((b) => { if (b !== body) { b.classList.remove("open"); const ob = document.querySelector(`[aria-controls="${b.id}"]`); if (ob) ob.setAttribute("aria-expanded", "false"); } });
      body.classList.toggle("open", open);
      btn.setAttribute("aria-expanded", String(open));
    });
    t.classList.add("has-info");
    t.append(btn);
    t.after(body);
    // drop the empty footer the moved lines leave behind
    for (const f of block.querySelectorAll(".figfoot")) if (!f.children.length) f.remove();
  }
  document.addEventListener("click", (e) => {
    if (e.target.closest && e.target.closest(".info-body")) return;
    document.querySelectorAll(".info-body.open").forEach((b) => b.classList.remove("open"));
    document.querySelectorAll(".info-btn[aria-expanded='true']").forEach((b) => b.setAttribute("aria-expanded", "false"));
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    document.querySelectorAll(".info-body.open").forEach((b) => b.classList.remove("open"));
  });
}

/* ================= boot ================= */
(async () => {
  const stamp = $("#stamp");
  const opt = (n) => loadJSON(n).catch(() => null);
  let core, meta, kev, ap, dl, sev, epss, mal, zd, epssPrior;
  try {
    [core, meta, kev, ap, dl, sev, epss, mal, zd, epssPrior] = await Promise.all([
      loadJSON("data.json"), opt("ai_meta.json"), opt("kev.json"), opt("ai_packages.json"),
      opt("downloads.json"), opt("severity.json"), opt("epss.json"), opt("malicious.json"), opt("zerodays.json"), opt("epss_prior.json"),
    ]);
  } catch (err) {
    stamp.textContent = "error: " + err.message;
    stamp.classList.add("err");
    return;
  }
  try {
    const gen = new Date(core.generatedAt);
    const ageH = (Date.now() - gen.getTime()) / 3600e3;
    const stale = ageH > 48 ? ` · data ${Math.round(ageH / 24)}d old — rebuild` : "";
    // no title bar: the stamp only speaks up when the data is stale (every card carries its own date)
    if (stale) { stamp.textContent = `Data as of ${gen.toISOString().slice(0, 10)}${stale}`; stamp.classList.add("err"); }
  } catch (e) { /* cards carry their own dates */ }

  const layers = layerList(core, meta);
  const rels = relList(core, meta);
  const ctx = { core, meta, kev, ap, dl, sev, epss, mal, zd, epssPrior, layers, label: makeLayerLabel(layers), metaOf: metaLookup(meta), rels, relLabel: makeRelLabel(rels) };
  let F = {};
  try { F = computeFacts(ctx); } catch (e) { F = { asOf: new Date().toISOString().slice(0, 10) }; F.year = F.asOf.slice(0, 4); F.prevYear = String(+F.year - 1); }
  ctx.F = F;
  let S = {};
  try { S = computeSurgeFacts(ctx, F); } catch (e) { S = {}; }
  // each panel renders independently: one bad data file must not blank the rest
  const panels = [
    // Part 1: all CVEs
    ["headline", () => buildHeadline(ctx, F, S)],
    ["bottom line", () => buildBottomLine(ctx, F, S)],
    ["KPIs", () => buildKpis(ctx, F, S)],
    ["signal vs noise", () => buildSignal(ctx)],
    ["brief", () => buildBrief(ctx, F, S)],
    ["hero chart", () => buildHeroChart(ctx, F)],
    ["where exploitation happens", () => buildWhere(ctx, F, S)],
    ["zero-days", () => { buildZeroDay(ctx); labelCells($("#tbl-zd")); }],
    ["time to KEV", () => buildTtk(ctx)],
    ["KEV by vendor", () => buildKevVendors(ctx, F)],
    ["ransomware", () => buildRansom(ctx, F)],
    ["latest exploited", () => { buildKevAll(ctx); labelCells($("#tbl-kevall")); }],
    ["patch next", () => { buildNext(ctx); labelCells($("#tbl-next")); }],
    ["severity per year", () => buildSevAll(ctx)],
    ["top lists", () => buildTops(ctx)],
    ["supply chain", () => buildSupply(ctx)],
    // Part 2: AI-related
    ["AI headline", () => buildAiHeadline(ctx, F, S)],
    ["AI KPIs", () => buildAiKpis(ctx, F, S)],
    ["AI relations", () => buildRelations(ctx, F)],
    ["CVE chart", () => buildMainChart(core)],
    ["AI by origin", () => buildAiOrigin(ctx)],
    ["exploited strip", () => buildKevChips(F)],
    ["what to do", () => buildTodo(ctx, F)],
    ["KEV table", () => { buildKevTable(F, ctx); labelCells($("#tbl-kev")); }],
    ["EPSS table", () => { buildEpssTable(ctx, F); labelCells($("#tbl-epss")); }],
    ["CWE compare", () => buildCweCompare(ctx)],
    ["CNA chart", () => buildCnaChart(ctx)],
    ["methodology", () => buildMethod(ctx)],
    ["framing: summary", () => explainSummary(ctx, F, S)],
    ["framing: risk", () => explainRisk(ctx, F, S)],
    ["framing: part 1", () => explainPart1(ctx, F, S)],
    ["framing: AI", () => explainAi(ctx, F)],
    ["framing: part 2", () => explainPart2(ctx, F, S)],
    ["framing: detail", () => explainDetail(ctx, F, S)],
  ];
  for (const [name, render] of panels) {
    try {
      render();
    } catch (err) {
      document.querySelector("main").prepend(h("p", { class: "err", text: `render error (${name}): ${err.message}` }));
    }
  }
  try { slideify(); } catch (err) { /* panels keep the plain layout */ }
  try { buildNavMenus(); } catch (err) { /* plain nav links still work */ }
  try { clipTables(); } catch (err) { /* tables simply stay full length */ }
  try { infoize(); } catch (err) { /* details simply stay inline */ }
  // canvas charts take their colours at draw time: redraw on a theme switch
  try { matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => { if (!FORCED_THEME) location.reload(); }); } catch (e) { /* old browsers keep the first theme */ }
  // Auto / Light / Dark: canvas charts take colours at draw time, so a switch reloads
  for (const b of document.querySelectorAll("[data-theme-set]")) {
    const v = b.getAttribute("data-theme-set");
    b.setAttribute("aria-pressed", String((FORCED_THEME || "auto") === v));
    b.addEventListener("click", () => {
      try { if (v === "auto") localStorage.removeItem("theme"); else localStorage.setItem("theme", v); } catch (e) { /* storage blocked */ }
      location.reload();
    });
  }
})();

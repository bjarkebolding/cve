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
const LIGHT = !!(window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches);
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
  plum: tok("c-plum", "#7a5a9a", "#4f3f7a"),
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
  mcp: P.sand,
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
const CAT_COLORS = [P.blue, P.sand, P.teal, P.mauve, P.sage, P.sky, P.neutral, P.plum];
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
  // severity share (record-based compare, else severity.json totals)
  try {
    const sc = core.severityCompare;
    const share = (o) => {
      if (!o) return null;
      const rated = SEV_KEYS.reduce((s, k) => s + (o[k] || 0), 0);
      return rated ? { hc: ((o.CRITICAL || 0) + (o.HIGH || 0)) / rated, rated, unrated: o.UNRATED || 0 } : null;
    };
    if (sc && sc.ai) {
      F.sevShare = { ai: share(sc.ai), all: share(sc.all), window: Array.isArray(sc.window) ? sc.window : null, src: "record" };
    } else if (sev && sev.totals) {
      F.sevShare = { ai: share(sev.totals), all: null, window: null, src: sev.source || "NVD" };
    }
    if (F.sevShare && !F.sevShare.ai) delete F.sevShare;
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
  edge: P.sand,
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
const REL_COLORS = {
  agent: P.sand,
  product: P.blue,
  feature: P.neutral,
  weakness: P.mauve,
  compute: P.sage,
  found: P.teal,
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
  found: "the CVE record credits an AI discovery tool, model or lab (Google Big Sleep, XBOW, depthfirst, ZeroPath, Claude/Anthropic, OpenAI …) or says an AI found it.",
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
    const sy = core.landscape && core.landscape.all && core.landscape.all.sevYears;
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
const lcFirst = (s) => (/^[A-Z][a-z]/.test(s) ? s[0].toLowerCase() + s.slice(1) : s);
const clean = (s) => (typeof s === "string" && s && !/NaN|undefined|null|Infinity/.test(s) ? s : null);

function buildHeadline(ctx, F, S) {
  const el = $("#headline"), sub = $("#subhead");
  const OL = originLabel(ctx.core);
  let head = null;
  try {
    const t = S.total;
    if (t && t.prev) {
      const r = t.cur / t.prev;
      head = r >= 1.15 ? `CVE disclosures are up ~${fmtX(r)}× on the same period last year: ${num.format(t.cur)} so far in ${F.year}.`
        : r >= 0.95 ? `CVE disclosures are running level with last year: ${num.format(t.cur)} so far in ${F.year}.`
        : `CVE disclosures are down ${pct(1 - r)} on the same period last year.`;
    } else if (t) head = `${num.format(t.cur)} CVEs published in ${F.year} so far.`;
  } catch (e) { head = null; }
  head = clean(head);
  if (head) el.textContent = head; else el.remove();

  const parts = [];
  const add = (fn) => { try { const s = clean(fn()); if (s) parts.push(s); } catch (e) { /* skip */ } };
  add(() => {
    const k = S.kev;
    if (!k || !k.cur) return null;
    const vs = k.prevSame ? ` (${num.format(k.prevSame)} by this date last year)` : "";
    const zd = fin(k.zd) ? `, ${num.format(k.zd)} of them exploited at disclosure` : "";
    return `CISA confirmed ${num.format(k.cur)} newly exploited vulnerabilities this year${vs}${zd}.`;
  });
  add(() => {
    const k = S.kev;
    if (!k || !k.cur || !k.origin) return null;
    const ranked = Object.entries(k.origin).sort((a, b) => b[1] - a[1]).slice(0, 3);
    const lead = ranked.reduce((t, [, n]) => t + n, 0);
    return `${listJoin(ranked.map(([id]) => oShort(id, OL)))} account for ${num.format(lead)} of them.`.replace(/^./, (c) => c.toUpperCase());
  });
  add(() => (S.hc && fin(S.hc.cur) ? `${pct(S.hc.cur)} of this year's rated CVEs are HIGH or CRITICAL${fin(S.hc.prev) ? ` (${pct(S.hc.prev)} in ${F.prevYear})` : ""}.` : null));
  // the KPI tiles carry these numbers: keep them one tap away, not on screen
  if (parts.length) { sub.textContent = parts.join(" "); sub.classList.add("hint"); } else sub.remove();
}

function kpiTiles(wrap, tiles, emptyMsg) {
  if (!tiles.length) { note(wrap, emptyMsg); return; }
  for (const x of tiles) {
    wrap.append(h("div", { class: "kpi" },
      h("div", { class: "k", text: x.k }),
      h("div", { class: "v" + (x.cls ? " " + x.cls : ""), text: x.v }),
      x.d ? h("div", { class: "d", text: x.d }) : null));
  }
}
function buildKpis(ctx, F, S) {
  const tiles = [];
  const t = S.total;
  if (t) tiles.push({ k: `CVEs published ${F.year} YTD`, v: num.format(t.cur),
    d: t.prev ? `×${(t.cur / t.prev).toFixed(1)} vs same period ${F.prevYear} (${num.format(t.prev)})` : `${num.format(t.prevFull)} in all of ${F.prevYear}` });
  const k = S.kev;
  if (k) tiles.push({ k: `Exploited (KEV) ${F.year}`, v: num.format(k.cur), cls: "warn",
    d: k.prevSame ? `${num.format(k.prevSame)} by this date in ${F.prevYear}` : "added to CISA KEV this year" });
  if (k && fin(k.zd)) {
    tiles.push({ k: `Zero-days ${F.year}`, v: num.format(k.zd), cls: "warn",
      d: ["exploited at disclosure", fin(k.zdPrevSame) ? `${num.format(k.zdPrevSame)} by this date ${F.prevYear}` : null].filter(Boolean).join(" · ") });
  }
  if (S.supply || fin(S.malYtd)) {
    tiles.push(S.supply
      ? { k: "Supply chain", v: num.format(S.supply.n), cls: "sc",
          d: "open-source CVEs" + (fin(S.malYtd) && S.malYtd ? ` · ${num.format(S.malYtd)} malicious packages` : "") }
      : { k: "Malicious packages", v: num.format(S.malYtd), cls: "sc", d: `${F.year} YTD, OSV MAL advisories` });
  }
  kpiTiles($("#kpis"), tiles, "Key indicators are not available for this data build.");
}

/* ================= executive brief: how to adjust ================= */
/* Five programme changes, each backed by this build's numbers. An item only
 * renders when its evidence exists, so the list never states a bare opinion. */
function buildBrief(ctx, F, S) {
  const ol = $("#brief-list");
  const items = [];
  const add = (fn) => { try { const r = fn(); if (r && clean(r.why)) items.push(r); } catch (e) { /* skip */ } };
  const OL = originLabel(ctx.core);
  add(() => {
    const t = S.total;
    if (!t || !t.prev) return null;
    const doy = Math.max(1, Math.round(daysBetween(F.year + "-01-01", F.asOf) + 1));
    return { act: "Size for the volume: automate intake and triage.", href: "#volume",
      why: `${num.format(t.cur)} CVEs so far in ${F.year}, ×${fmtX(t.cur / t.prev)} the same period of ${F.prevYear}: about ${num.format(Math.round(t.cur / doy))} a day. Manual review of every advisory does not scale.` };
  });
  add(() => {
    const k = S.kev, t = S.total;
    if (!k || !k.cur || !S.hc || !fin(S.hc.cur) || !t) return null;
    return { act: "Rank the patch queue by exploitation, not by CVSS.", href: "#next",
      why: `${pct(S.hc.cur)} of this year's rated CVEs are HIGH or CRITICAL, but only ${num.format(k.cur)} vulnerabilities were confirmed exploited (CISA KEV). Patch KEV first, then the highest EPSS scores.` };
  });
  add(() => {
    const ents = (ctx.kev && ctx.kev.entries || []).filter((e) => e && String(e.added).startsWith(F.year) && fin(e.daysToKev));
    if (ents.length < 10) return null;
    const week = ents.filter((e) => e.daysToKev <= 7).length;
    const edge = S.kev && S.kev.origin && S.kev.origin.edge;
    const tail = fin(edge) && edge ? ` ${oShort("edge", OL).replace(/^./, (c) => c.toUpperCase())} alone account for ${num.format(edge)}.` : "";
    return { act: "Patch internet-facing systems in days, not monthly cycles.", href: "#exploit",
      why: `${pct(week / ents.length)} of this year's newly exploited vulnerabilities were exploited within a week of disclosure.${tail} Keep an emergency-change path and reduce exposed management interfaces.` };
  });
  add(() => {
    if (!S.supply) return null;
    const mal = fin(S.malYtd) && S.malYtd ? ` and ${num.format(S.malYtd)} malicious packages were published` : "";
    return { act: "Control what enters the software supply chain.", href: "#supply",
      why: `${num.format(S.supply.n)} CVEs this year are in open-source projects and packages${mal}. Keep SBOMs current, pin versions and allow-list package sources.` };
  });
  add(() => {
    const a = S.aiShare;
    if (!a || !a.n) return null;
    const ry = relYtd(ctx.core, F);
    const ag = ry && ry.agent;
    const agent = ag && ag.cur && ag.prev && ag.cur > ag.prev ? ` MCP and agent CVEs are already ×${fmtX(ag.cur / ag.prev)} last year's total.` : "";
    const exp = S.kev && fin(S.kev.aiCur) ? `, ${num.format(S.kev.aiCur)} of them confirmed exploited` : "";
    return { act: "Bring AI agents, MCP servers and AI features into scope.", href: "#ai",
      why: `${num.format(a.n)} CVEs this year (${pct(a.n / a.of, 1)}) are AI-related${exp}.${agent} Inventory them, assign owners and limit what they can reach.` };
  });
  if (!items.length) { $("#brief").remove(); return; }
  for (const it of items) {
    ol.append(h("li", null,
      h("p", { class: "act" }, h("a", { href: it.href, text: it.act })),
      h("p", { class: "why", text: it.why })));
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
      h("span", { class: "hb-n", text: num.format(r.n) + (opts && opts.of ? ` · ${pct(r.n / opts.of)}` : "") })));
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
  if (k.origin) {
    const order = (originList(ctx.core) || Object.keys(ORIGIN_FALLBACK).map((id) => ({ id }))).map((o) => o.id);
    const rows = order.filter((id) => fin(k.origin[id])).map((id) => ({ label: OL(id), n: k.origin[id], color: ORIGIN_COLORS[id] || OTHER_COLOR }))
      .sort((a, b) => b.n - a.n);
    hbars(el, rows, { of: k.cur });
    if (hint) hint.textContent = `The ${num.format(k.cur)} vulnerabilities CISA added to its Known Exploited catalog in ${F.year}, by origin.`;
  } else {
    note(el, "Per-origin classification of KEV entries is not in this data build.");
  }
}

/* ================= TIER 2: exploitation by origin + zero-day proxy ================= */
function buildKevOrigin(ctx) {
  const el = $("#chart-kev-origin");
  const kev = ctx.kev;
  if (!kev) { note(el, "CISA KEV data is not available."); return; }
  const OL = originLabel(ctx.core);
  let by = kev.byYear && typeof kev.byYear === "object" ? kev.byYear : null;
  if (!by && Array.isArray(kev.entries)) {
    by = {};
    for (const e of kev.entries) {
      if (!e || !e.added) continue;
      const y = e.added.slice(0, 4);
      const b = by[y] || (by[y] = { added: 0, origin: {} });
      b.added += 1;
      const o = e.origin || (e.ai ? "ai" : "rest");
      b.origin[o] = (b.origin[o] || 0) + 1;
    }
  }
  const years = Object.keys(by || {}).filter((y) => /^\d{4}$/.test(y) && y >= "2022" && by[y] && by[y].origin).sort();
  if (!years.length) { note(el, "KEV per-year data is not available."); return; }
  const ids = new Set();
  for (const y of years) for (const id of Object.keys(by[y].origin)) ids.add(id);
  const order = [...(originList(ctx.core) || []).map((o) => o.id), ...Object.keys(ORIGIN_FALLBACK), "rest"];
  const present = [...new Set(order)].filter((id) => ids.has(id)).reverse();
  const groups = present.map((id) => ({
    label: id === "rest" ? "unclassified" : OL(id), color: ORIGIN_COLORS[id] || OTHER_COLOR,
    data: years.map((y) => by[y].origin[id] || 0),
  }));
  const cur = String(new Date(ctx.F.asOf + "T00:00:00Z").getUTCFullYear());
  const yLab = (v) => String(v) + (String(v) === cur ? "\nYTD" : "");
  stackedBars(el, {
    xs: years.map(Number), groups, height: 260, time: false, xLabel: "year", yLabel: "KEV additions per year",
    ariaLabel: "CISA KEV additions per year by origin", draw: yearNotes({ [cur]: `${cur} = ${partialLabel(ctx.F)}` }, false), xValues: tick(yLab), xIncrs: [1, 2, 5], xSpace: 34, xFmt: yLab, barMax: 70,
  });
  if (!kev.byYear || ids.has("rest")) {
    const hint = $("#kev-origin-hint");
    if (hint) hint.textContent += " Per-origin classification of KEV entries is not in this data build.";
  }
}
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
      xs: years.map(Number), groups: [{ label: "exploited at disclosure", color: P.red, data: years.map((y) => by[y]) }],
      height: 200, time: false, xLabel: "publication year", yLabel: "CVEs per year", legend: false,
      ariaLabel: "KEV entries exploited at disclosure (added within one day of publication), per CVE publication year",
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
    rows = zdj.recent.map((r) => ({ cve: r.cve, product: [r.vendor, r.product].filter(Boolean).join(" ").replace(/^(\S+) \1 /, "$1 "), origin: r.origin, date: r.date }));
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
    tbody.append(h("tr", null, h("td", { class: "nowrap" }, cveLink(r.cve)), h("td", { text: r.product || "—" }), oc, h("td", { class: "nowrap", text: r.date || "—" })));
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
  const cols = [P.blue, P.sand, P.mauve, P.teal];
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

/* ================= Part 1: speed of exploitation ================= */
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
    if (r.zeroDay) idCell.append(badge("0-DAY", "", "added to KEV within one day of CVE publication"));
    const sc = scores ? scores[r.cve] : null;
    tbody.append(h("tr", null, idCell,
      h("td", { text: r.product || "—", title: r.desc || null }),
      originCell(r.origin, OL),
      h("td", { class: "nowrap", text: r.added || "—" }),
      h("td", { class: "num", text: fin(r.daysToKev) ? num.format(r.daysToKev) : "—" }),
      h("td", { class: "num", text: scores ? epssText(sc) : "n/a", title: sc && fin(sc.pct) ? `percentile ${(100 * sc.pct).toFixed(1)}` : null })));
  }
}
function epssTopTable(tbody, rows, cols, cell) {
  if (!rows || !rows.length) { emptyRow(tbody, cols, "No EPSS ranking in this data build (needs the EPSS bulk file)."); return; }
  for (const r of rows) {
    tbody.append(h("tr", null,
      h("td", { class: "nowrap" }, cveLink(r.cve)),
      h("td", { text: r.product || "—" }),
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
const growthText = (n, prev) => (prev > 0 ? (n / prev >= 1.995 ? `×${n / prev >= 10 ? Math.round(n / prev) : (n / prev).toFixed(1)}` : `${n >= prev ? "+" : "−"}${Math.round(Math.abs(100 * (n / prev - 1)))}%`) : "new");
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
function cweRows(top, names, n) {
  return (top || []).slice(0, n || 10).map((r) => ({ label: names[r.id] ? `${names[r.id]} (${r.id})` : r.id, title: r.id, n: r.n, prev: r.prev }));
}
function vendorRows(top, n) { return (top || []).slice(0, n || 10).map((r) => ({ label: r.name || r.id, n: r.n, prev: r.prev })); }
function cnaRows(top, n) { return (top || []).slice(0, n || 10).map((r) => ({ label: prettyCna(r.id), title: r.id, n: r.n, prev: r.prev })); }
/* the row that grew most in absolute terms, among the shown rows */
const topRiser = (rows) => rows.reduce((b, r) => (r.n - (r.prev || 0) > (b ? b.n - (b.prev || 0) : 0) ? r : b), null);
function buildTops(ctx) {
  const L = ctx.core.landscape && ctx.core.landscape.all;
  const names = (ctx.sev && ctx.sev.cweNames) || {};
  const legend = h("p", { class: "hint toplegend", text: "Bar = last 12 months; tick = the 12 months before; text = count · change." });
  if (!L) { for (const id of ["#cweall", "#vendall", "#cnaall"]) note($(id), "Not in this data build."); return; }
  // Part 1 lists share one quiet colour: the ranking is the message
  topList($("#cweall"), cweRows(L.cweTop, names), { color: P.steel });
  topList($("#vendall"), vendorRows(L.vendorTop), { color: P.steel });
  topList($("#cnaall"), cnaRows(L.cnaTop), { color: P.steel });
  $("#tops").prepend(legend);
}

/* ================= Part 2: AI-related summary ================= */
/* CVEs this year that sit in an AI stack layer (AI software, agents, features) */
function layerYtd(core, F) {
  const lm = core.layerMonths;
  if (!lm || !Array.isArray(core.months)) return 0;
  let n = 0;
  for (const arr of Object.values(lm)) if (Array.isArray(arr)) core.months.forEach((m, i) => { if (m.startsWith(F.year)) n += arr[i] || 0; });
  return n;
}
function relYtd(core, F) {
  const ry = core.landscape && core.landscape.ai && core.landscape.ai.relYears;
  if (!ry) return null;
  return Object.fromEntries(Object.entries(ry).map(([id, by]) => [id, { cur: (by || {})[F.year] || 0, prev: (by || {})[F.prevYear] || 0 }]));
}
function buildAiHeadline(ctx, F, S) {
  const el = $("#ai-headline"), sub = $("#ai-subhead");
  let head = null;
  try {
    const a = S.aiShare;
    if (a && a.of) {
      const r = F.ytd && F.ytd.prev ? F.ytd.cur / F.ytd.prev : null;
      head = `${num.format(a.n)} of this year's ${num.format(a.of)} CVEs are AI-related (${pct(a.n / a.of, a.n / a.of < 0.1 ? 1 : 0)})`
        + (r && r >= 1.15 ? ` — ×${fmtX(r)} on the same period last year, against ×${fmtX(S.total.cur / S.total.prev)} for all CVEs.` : ".");
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
    return `Exploitation is still rare: ${num.format(k.aiCur)} of the ${num.format(k.cur)} vulnerabilities CISA added to KEV in ${F.year} are AI-related.`;
  });
  add(() => {
    const ry = relYtd(ctx.core, F);
    return ry && ry.found && ry.found.cur ? `AI is also finding bugs: ${num.format(ry.found.cur)} CVEs this year credit an AI tool or AI lab (${num.format(ry.found.prev)} in ${F.prevYear}).` : null;
  });
  if (parts.length) { sub.textContent = parts.join(" "); sub.classList.add("hint"); } else sub.remove();
}
function buildAiKpis(ctx, F, S) {
  const tiles = [];
  const a = S.aiShare;
  if (a && a.of) tiles.push({ k: `AI-related CVEs ${F.year} YTD`, v: num.format(a.n), cls: "ai",
    d: `${pct(a.n / a.of, 1)} of all CVEs` + (F.ytd && F.ytd.prev ? ` · ×${(F.ytd.cur / F.ytd.prev).toFixed(1)} vs same period ${F.prevYear}` : "") });
  const ry = relYtd(ctx.core, F);
  if (ry && ry.agent) tiles.push({ k: `MCP & agent CVEs ${F.year}`, v: num.format(ry.agent.cur), cls: "ai",
    d: `${num.format(ry.agent.prev)} in all of ${F.prevYear}` });
  const k = S.kev;
  if (k && F.kevAi) tiles.push({ k: `Exploited AI-related (KEV) ${F.year}`, v: num.format(k.aiCur), cls: "warn",
    d: `${pct(k.cur ? k.aiCur / k.cur : 0, 1)} of ${F.year} KEV additions · ${num.format(F.kevAi.length)} all time` });
  if (ry && ry.found) tiles.push({ k: `Found by AI ${F.year}`, v: num.format(ry.found.cur), cls: "sc",
    d: `CVEs crediting an AI tool or AI lab · ${num.format(ry.found.prev)} in ${F.prevYear}` });
  kpiTiles($("#ai-kpis"), tiles, "AI indicators are not available for this data build.");
}
function buildRelations(ctx, F) {
  const el = $("#rel-bars");
  const ry = relYtd(ctx.core, F);
  const RL = ctx.relLabel;
  if (!ry) { note(el, "AI relation tags are not in this data build (it predates them)."); note($("#chart-rel"), "Not available."); return; }
  const ids = (ctx.rels || []).map((r) => r.id).filter((id) => ry[id]);
  hbars(el, ids.map((id) => ({ label: RL(id), n: ry[id].cur, color: REL_COLORS[id] || OTHER_COLOR })).sort((a, b) => b.n - a.n));
  // per year, lines (multi-label: never stacked)
  const all = ctx.core.landscape.ai.relYears;
  const years = [...new Set(ids.flatMap((id) => Object.keys(all[id] || {})))].filter((y) => y >= "2018").sort();
  const cel = $("#chart-rel");
  if (!years.length) { note(cel, "No yearly counts."); return; }
  const cur = F.year;
  makeChart(cel, {
    height: 220,
    ariaLabel: "AI-related CVEs per year by relation, one line per relation (a CVE can count in several)",
    scales: { x: { time: false } },
    axes: [
      { space: 34, values: tick((v) => String(v) + (String(v) === cur ? "\nYTD" : "")), incrs: [1, 2, 5], size: 44 },
      { space: 36, label: "CVEs per year", values: tick(axisNum), size: 56 },
    ],
    series: [
      { label: "year", value: (u, v) => (v == null ? "" : String(v)) },
      ...ids.map((id) => ({ label: rShort(id), stroke: REL_COLORS[id] || OTHER_COLOR, width: 2, points: { show: true, size: 5 },
        value: (u, v) => (v == null ? "" : num.format(v)) })),
    ],
    legend: { show: true },
  }, [years.map(Number), ...ids.map((id) => years.map((y) => (all[id] || {})[y] || 0))]);
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
function buildVendAi(ctx) {
  const L = ctx.core.landscape && ctx.core.landscape.ai;
  topList($("#vendai"), L ? vendorRows(L.vendorTop) : null, { color: P.blue });
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
    const names = [];
    const seen = new Set(prods.map((p) => p.name.toLowerCase()));
    for (const r of top) {
      const n = shortProduct(r.product);
      if (n && !seen.has(n.toLowerCase()) && names.length < 3) { seen.add(n.toLowerCase()); names.push(n); }
    }
    return names.length ? `Next, check ${listJoin(names)}: they carry the highest exploit-probability (EPSS) AI-related CVEs of the last 12 months not yet in KEV.` : null;
  });
  add(() => {
    const lm = ctx.core.layerMonths;
    if (!lm || !Array.isArray(ctx.core.months)) return null;
    let best = null;
    for (const [id, arr] of Object.entries(lm)) {
      if (!Array.isArray(arr) || id === "other") continue;
      let cur = 0, prev = 0;
      ctx.core.months.forEach((m, i) => { if (m.startsWith(F.year)) cur += arr[i] || 0; if (m.startsWith(F.prevYear)) prev += arr[i] || 0; });
      if (!best || cur > best.cur) best = { id, cur, prev };
    }
    if (!best || !best.cur) return null;
    const layered = layerYtd(ctx.core, F);
    const tot = layered ? ` (${pct(best.cur / layered)} of CVEs in AI software)` : "";
    return `Inventory your ${ctx.label(best.id)}: the largest layer in ${F.year} with ${num.format(best.cur)} CVEs so far${tot}, vs ${num.format(best.prev)} in all of ${F.prevYear}.`;
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
      h("td", { text: r.product || "—", title: r.desc || null }),
      h("td", null, relTags(r.rels && r.rels.length ? r.rels : ["product"], ctx.relLabel)),
      h("td", { class: "nowrap", text: r.published || "—" }),
      h("td", { class: "nowrap", text: r.added || "—" }),
      h("td", { class: "num", text: fin(r.daysToKev) ? num.format(r.daysToKev) : "—" }),
      h("td", { class: "num", text: scores ? epssText(s) : "n/a", title: s && fin(s.pct) ? `percentile ${(100 * s.pct).toFixed(1)}` : null })));
  }
  const hint = $("#kev-hint");
  if (hint && ctx.kev && ctx.kev.generatedAt) {
    hint.textContent += ` Catalog fetched ${String(ctx.kev.generatedAt).slice(0, 10)}.`;
  }
}

/* ================= layer chart ================= */
function buildLayerChart(ctx) {
  const el = $("#chart-layers");
  const { core, layers } = ctx;
  if (!core.layerMonths || !Array.isArray(core.months) || !layers) {
    note(el, "Stack-layer breakdown is not available in this data build.");
    return;
  }
  const idx = new Map(core.months.map((m, i) => [m, i]));
  const last = core.months[core.months.length - 1];
  const ms = monthRange("2018-01", last);
  const groups = [...layers].reverse() // contract order is priority (mcp first); put framework/other at the bottom
    .filter((l) => Array.isArray(core.layerMonths[l.id]))
    .map((l) => ({
      label: l.label || l.id,
      color: LAYER_COLORS[l.id] || OTHER_COLOR,
      data: ms.map((m) => (idx.has(m) ? core.layerMonths[l.id][idx.get(m)] || 0 : 0)),
    }));
  if (!groups.length) { note(el, "Stack-layer breakdown is empty."); return; }
  stackedBars(el, {
    xs: ms.map(monthT), groups, height: 340, yLabel: "AI CVEs per month",
    ariaLabel: "AI-related CVEs per month since 2018, stacked by AI stack layer",
    draw: (() => { const F = ctx.F || {}; const n = bulkNotes(F); if (F.year) n[F.year] = (n[F.year] ? n[F.year] + " · " : "") + `${MONTHS[+F.asOf.slice(5, 7) - 1]} partial`; return yearNotes(n, true); })(), xFmt: (v) => new Date(v * 86400e3).toISOString().slice(0, 7), barMax: 14, monthly: true,
  });
  // replace the static TensorFlow note with the data's bulk-disclosure years
  const conc = core.concentration;
  const noteEl = $("#layers-note");
  if (noteEl && conc && typeof conc === "object") {
    const parts = Object.keys(conc).sort().map((y) => {
      const t = conc[y].top && conc[y].top[0];
      return t ? `${y}: ${t.product} ${(100 * t.share).toFixed(0)}% (${num.format(t.n)}, mostly via ${prettyCna(t.cna)})` : null;
    }).filter(Boolean);
    if (parts.length) {
      noteEl.textContent = `Bulk disclosures by a single product inflate some years — ${parts.join(" · ")}. `
        + "These are one project's batch of reports, not a rise across the AI stack. Click a layer in the legend to hide it.";
    }
  }
}

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
function sevBar(title, o) {
  const rated = SEV_KEYS.reduce((s, k) => s + (o[k] || 0), 0);
  const wrap = h("div", { class: "sevcmp" });
  wrap.append(h("div", { class: "sevcmp-h" },
    h("span", { class: "sevcmp-t", text: title }),
    h("span", { class: "sevcmp-n", text: `${num.format(rated)} rated` + (o.UNRATED ? ` · ${num.format(o.UNRATED)} unrated` : "") })));
  const bar = h("div", { class: "sevbar", role: "img",
    "aria-label": `${title}: ` + SEV_KEYS.map((k) => `${k} ${rated ? pct((o[k] || 0) / rated) : "0%"}`).join(", ") });
  const leg = h("div", { class: "sevleg" });
  for (const k of SEV_KEYS) {
    const share = rated ? (o[k] || 0) / rated : 0;
    const seg = h("span", { class: "seg " + k, title: `${k}: ${num.format(o[k] || 0)} (${pct(share, 1)})` });
    seg.style.width = (100 * share).toFixed(2) + "%";
    // no text inside the segments: the legend right below carries the shares
    bar.append(seg);
    leg.append(h("span", { class: "sevleg-i" }, h("span", { class: "sev " + k, text: k }), document.createTextNode(" " + pct(share, 1))));
  }
  wrap.append(bar, leg);
  return wrap;
}
function buildSevCompare(ctx) {
  const el = $("#sev-compare");
  const sc = ctx.core.severityCompare;
  if (!sc || !sc.ai) {
    note(el, "AI-vs-all severity comparison is not available in this data build.");
    return;
  }
  el.append(sevBar("AI-related CVEs", sc.ai));
  if (sc.all) el.append(sevBar("All CVEs", sc.all));
  const hint = $("#breaks-hint");
  if (hint) hint.textContent = (Array.isArray(sc.window) ? `Window: CVEs published ${sc.window[0]} to ${sc.window[1]}. ` : "") +
    "Same window for both sides; severity is the CVSS in the CVE record itself (CNA, else CISA-ADP; v3.1 preferred).";
}
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
      h("span", { class: "k-ai", text: "AI" }), h("span", { class: "k-all", text: "All CVEs" })));
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
    if (all) bars.append(mk("all", sAll, "All CVEs"));
    list.append(h("div", { class: "cwe-row" }, lab, bars));
  }
  el.append(list);
}
function buildSevChart(ctx) {
  const L = ctx.core.landscape && ctx.core.landscape.ai;
  sevYearsChart($("#chart-sev"), L && L.sevYears, { year: ctx.F.year, height: 220, yLabel: "AI-related CVEs per year",
    ariaLabel: "AI-related CVEs per year stacked by CVSS severity, CRITICAL at the bottom, unrated on top" });
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

/* ================= latest AI CVEs ================= */
function buildRecentAiTable(ctx) {
  const tbody = $("#tbl-ai tbody");
  const recent = Array.isArray(ctx.core.recentAi) ? ctx.core.recentAi : [];
  if (!recent.length) { emptyRow(tbody, 5, "No recent AI CVEs in this data build."); return; }
  const kevSet = new Set(((ctx.kev && ctx.kev.entries) || []).map((e) => e.cve));
  for (const r of recent) {
    if (!r || !r.id) continue;
    const m = ctx.metaOf(r.id) || {};
    const span = h("span", { class: "cveid" }, cveLink(r.id));
    if (kevSet.has(r.id)) span.append(badge("KEV", "", "in CISA Known Exploited Vulnerabilities"));
    if (r.cvss) {
      const t = [r.cvss.v ? `CVSS v${r.cvss.v}` : "CVSS", r.cvss.src ? `source ${String(r.cvss.src).toUpperCase()}` : "source NVD (primary)"].join(" · ");
      const sb = sevBadge(r.cvss.sev, r.cvss.score, t);
      if (sb) span.append(sb);
    }
    const cnaName = r.cnaName || "";
    const cna = cnaName || r.cna || "";
    const isEmail = cna.includes("@") && !cnaName;
    const tdCna = h("td", { class: "cna", "data-label": "CNA", text: cnaName || isEmail ? cna : cna.slice(0, 8), title: r.cna && r.cna !== cna ? r.cna : cna || null });
    if (isEmail || cnaName) tdCna.classList.add("nowrap");
    tbody.append(h("tr", null,
      h("td", null, span),
      h("td", { class: "nowrap pub", text: r.published ? r.published + "Z" : "—" }),
      relCell(r.rels || m.rels || (r.layer || m.layer ? ["product"] : []), r.product || m.product, ctx.relLabel),
      tdCna,
      h("td", { class: "desc", text: r.description || "(no English description)" })));
  }
}
function wireAiFilter() {
  const input = $("#ai-filter");
  if (!input) return;
  const rows = [...document.querySelectorAll("#tbl-ai tbody tr")];
  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    for (const tr of rows) tr.hidden = !!q && !tr.textContent.toLowerCase().includes(q);
    const t = $("#tbl-ai");
    t.classList.toggle("searching", !!q);
    if (t._clipBtn) t._clipBtn.hidden = !!q;
  });
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
  const groups = top.map((c, i) => ({ label: prettyCna(c), color: CAT_COLORS[i % CAT_COLORS.length], data: years.map((y) => (cy[y] || {})[c] || 0) }));
  groups.push({ label: "other CNAs", color: OTHER_COLOR, data: years.map((y) =>
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

/* ================= context: AI package advisories (OSV) ================= */
function buildAiPkgs(ctx) {
  const el = $("#chart-aipkgs");
  const ap = ctx.ap;
  if (!ap) { note(el, "Package advisory data is not available."); return; }
  const hint = $("#aipkgs-hint");
  const per = ap.perPackage || {};
  const nPk = Object.keys(per).length;
  const total = fin(ap.total) ? ap.total : null;
  const advs = Array.isArray(ap.advisories) ? ap.advisories : Array.isArray(ap.recent) ? ap.recent : [];
  const withFixed = advs.filter((a) => a && typeof a.fixed === "boolean");
  let s = total != null
    ? `${num.format(total)} unique advisories (deduplicated across packages) for ${num.format(nPk)} AI/ML packages, via OSV.dev.`
    : `${num.format(Object.values(per).reduce((t, p) => t + (p.count || 0), 0))} advisories for ${num.format(nPk)} AI/ML packages via OSV.dev (an advisory affecting several packages counts once per package).`;
  if (withFixed.length) {
    s += ` ${pct(withFixed.filter((a) => a.fixed).length / withFixed.length)} of the ${withFixed.length} ${ap.advisories ? "" : "most recent "}advisories list a fixed version.`;
  }
  hint.textContent = s;
  const keys = Object.keys(ap.months || {}).sort();
  if (keys.length) {
    const ms = monthRange(keys[0] < "2018-01" ? "2018-01" : keys[0], keys[keys.length - 1]);
    stackedBars(el, {
      xs: ms.map(monthT), groups: [{ label: "advisories", color: COLORS.pkgs, data: ms.map((m) => ap.months[m] || 0) }],
      height: 220, yLabel: "advisories per month", monthly: true, ariaLabel: "AI/ML package advisories per month (OSV)", xFmt: (v) => new Date(v * 86400e3).toISOString().slice(0, 7), barMax: 10,
    });
    const lg = el.querySelector(".u-legend");
    if (lg) lg.classList.add("compact");
  } else note(el, "No monthly advisory counts.");
  // recent advisories list
  const box = $("#adv-recent");
  const items = (ap.recent || []).slice(0, 8);
  if (!items.length) return;
  box.append(h("div", { class: "adv-head", text: `Recent advisories (${items.length} of ${ap.recent.length})` }));
  for (const it of items) {
    const row = h("div", { class: "adv-row" },
      h("span", { class: "adv-date", text: String(it.published || "").slice(0, 10) }),
      h("span", { class: "adv-pkg", text: it.package || it.id || "" }),
      h("span", { class: "adv-cve", text: it.cve || it.id || "" }),
      h("span", { class: "adv-sum", text: it.summary || "", title: it.summary || null }));
    if (typeof it.fixed === "boolean") row.querySelector(".adv-cve").append(badge(it.fixed ? "FIX" : "NO FIX", it.fixed ? "ok" : "", it.fixed ? "a fixed version is listed" : "no fixed version listed"));
    box.append(row);
  }
}

/* ================= context: adoption (npm, log scale) ================= */
function buildAdoptionChart(ctx) {
  const el = $("#chart-adoption");
  const dl = ctx.dl;
  const monthly = (dl && dl.npmMonthly) || {};
  const pkgs = ["openai", "ai", "langchain", "@huggingface/transformers"].filter((p) => monthly[p]);
  const monthSet = new Set();
  for (const p of pkgs) for (const m of Object.keys(monthly[p] || {})) monthSet.add(m);
  if (!monthSet.size) { note(el, "Download data is not available."); return; }
  const months = [...monthSet].sort();
  const colors = [COLORS.npm1, COLORS.npm2, COLORS.npm3, COLORS.npm4];
  const data = [months.map(monthT), ...pkgs.map((p) => months.map((m) => Math.log10(Math.max(1, (monthly[p] || {})[m] || 0))))];
  const LOGLAB = { 3: "1k", 4: "10k", 5: "100k", 6: "1M", 7: "10M", 8: "100M", 9: "1B" };
  makeChart(el, {
    height: 220,
    ariaLabel: "Monthly npm downloads of AI SDK packages, log scale (adoption context)",
    scales: { x: { time: true } },
    axes: [
      dayAxis(),
      { space: 36, label: "downloads per month (log scale)", size: 52, values: tick((v) => (Math.abs(v - Math.round(v)) < 1e-6 ? LOGLAB[Math.round(v)] || "" : "")) },
    ],
    series: [
      { label: "month", value: (u, v) => (v == null ? "—" : new Date(v * 86400e3).toISOString().slice(0, 7)) },
      ...pkgs.map((p, i) => ({ label: p, stroke: colors[i], width: 1.5, fill: null,
        value: (u, v) => (v == null ? "—" : compact(Math.round(10 ** v))) })),
    ],
    legend: { show: true },
  }, data);
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
const CNA_NAMES = { GitHub_M: "GitHub (advisories)", "@huntr_ai": "huntr (Protect AI)", huntr_ai: "huntr (Protect AI)", mitre: "MITRE", VulnCheck: "VulnCheck",
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
  return `Who files moves the curve: ${prettyCna(best.c)} assigned ${num.format(best.n)} AI CVEs in ${F.year} so far, up from ${before} in all of ${F.prevYear} — ${lead}`;
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
function srcLine(ctx, names) {
  const d = (x) => (x ? String(x).slice(0, 10) : null);
  const map = {
    cve: ["CVE List (cvelistV5)", d(ctx.core && ctx.core.generatedAt)],
    kev: ["CISA KEV", d(ctx.kev && ctx.kev.generatedAt)],
    epss: ["FIRST EPSS", ctx.epss && (ctx.epss.modelDate || d(ctx.epss.generatedAt))],
    osv: ["OSV.dev", d((ctx.ap && ctx.ap.generatedAt) || (ctx.mal && ctx.mal.generatedAt))],
    npm: ["npm downloads API", d(ctx.dl && ctx.dl.generatedAt)],
    zd: [ctx.zd && ctx.zd.source ? ctx.zd.source : "zero-day tracker", d(ctx.zd && ctx.zd.generatedAt)],
    sev: ["CVE record CVSS (CNA/ADP), NVD fallback", d(ctx.sev && ctx.sev.generatedAt)],
  };
  const parts = names.map((n) => map[n]).filter(Boolean);
  const dates = parts.map((p) => p[1]).filter(Boolean).sort();
  return "Source: " + parts.map((p) => p[0]).join(" + ") + (dates.length ? ` · data as of ${dates[dates.length - 1]}` : "");
}
/* like-for-like: complete months Jan..(M-1) of this year vs the same months last year */
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
function kevBacklogNote(kev) {
  try {
    const e = ((kev && kev.entries) || []).filter((x) => (x.added || "").startsWith("2022"));
    const known = e.filter((x) => x.published);
    if (known.length < 50) return "";
    const share = known.filter((x) => x.published < "2021").length / known.length;
    return share >= 0.5 ? ` 2022 is mostly catch-up: ${Math.round(100 * share)}% of its additions were CVEs published before 2021, not new 2022 exploitation.` : "";
  } catch (err) { return ""; }
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
  const notes = Object.fromEntries(Object.entries(o).map(([y, v]) => [y, `${v.eco} wave ×${v.mult} ↑ ${compact(tot(y))} (bar clipped)`]));
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
      px = Math.min(Math.max(px, u.bbox.left + w / 2 + 2), u.bbox.left + u.bbox.width - w / 2 - 2);
      const py = Math.max(u.bbox.top + 11 * dpr, u.valToPos(bv, "y", true) - 5 * dpr);
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
    if (core.originMonths && originList(core)) {
      for (const [id, arr] of Object.entries(core.originMonths)) {
        const r = ytdMonths(core, arr, F);
        if (r && r.prev >= 20 && (!best || r.cur / r.prev > best.r)) best = { id, r: r.cur / r.prev, ...r };
      }
    }
    const t = S.total;
    const title = t && t.prev
      ? `CVEs ${xr(t.cur, t.prev)} vs the same period last year` + (best ? ` — ${oShort(best.id, OL)} growing fastest (${xr(best.cur, best.prev)})` : "")
      : null;
    fig("#chart-hero", {
      titleEl: "#h-hero", title,
      subEl: "#hero-sub", sub: `Published CVEs per calendar year, 2018 → ${F.year} (${partialLabel(F)}), stacked by origin (what kind of software). Y-axis: CVEs per year.`,
      after: "#hero-note",
      how: "Each bar is one year's published CVE records; the coloured segments add up to the year's total. Pitfall: the last bar is a partial year, and CVE counts measure disclosure volume, not risk.",
      so: t && t.prev && t.cur / t.prev >= 1.3 ? "Triage capacity has to scale with volume: prioritise by exploitation (KEV), then EPSS, and only then by CVSS — a CVSS-first queue cannot keep up." : null,
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
          title = `${listJoin(lead.map(([id]) => oShort(id, OL)))} make up ${pct(n / k.cur)} of ${F.year}'s exploited vulnerabilities`; title = title[0].toUpperCase() + title.slice(1);
          so = `Keep emergency patching and attack-surface monitoring focused on ${listJoin(lead.map(([id]) => oShort(id, OL)))}.`;
        }
      }
      fig("#where-bars", {
        titleEl: "#h-where", title,
        subEl: "#where-hint", sub: `Vulnerabilities added to CISA KEV in ${F.year} (${partialLabel(F)}), by origin: count · share of the year's additions. Not stacked.`,
        how: "Bar length = KEV additions this year. Pitfall: KEV is a lower bound — only CISA-confirmed exploitation, weighted to products US agencies run.",
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
    fig("#chart-kev-origin", {
      titleEl: "#h-exploitation",
      title: k && k.cur ? `${num.format(k.cur)} exploited vulnerabilities added in ${F.year} so far` + (k.prevSame ? ` vs ${num.format(k.prevSame)} by this date in ${F.prevYear}` : "") : null,
      subEl: "#kev-origin-hint", sub: `CISA KEV additions per year (by date added), 2022 → ${F.year} (${partialLabel(F)}), stacked by origin. 2021 is omitted: the catalog launched in Nov 2021 with a ~300-entry backlog.`,
      how: "Each bar = vulnerabilities CISA added to KEV that year; segments add up to the total. Pitfall: KEV is a lower bound, and the latest bar is a partial year." + kevBacklogNote(ctx.kev),
      src: srcLine(ctx, ["kev"]),
    });
  } catch (e) { /* skip */ }
  try {
    const k = S.kev;
    let so = null;
    const ents = ((ctx.kev && ctx.kev.entries) || []).filter((e) => e.zeroDay && String(e.published || "").startsWith(F.year));
    if (ents.length && ents.every((e) => e.origin)) {
      const c = {};
      for (const e of ents) c[e.origin] = (c[e.origin] || 0) + 1;
      const top = Object.entries(c).sort((a, b) => b[1] - a[1])[0];
      if (top) so = `${num.format(top[1])} of ${num.format(ents.length)} were ${oShort(top[0], OL)} — for these there is no patch window; harden and monitor them, and pre-stage emergency patching.`;
    }
    fig("#chart-zeroday", {
      titleEl: "#h-zd",
      title: k && fin(k.zd) ? `${num.format(k.zd)} CVEs published in ${F.year} were exploited at disclosure` + (fin(k.zdPrevSame) && k.zdPrevSame ? ` (${num.format(k.zdPrevSame)} by this date in ${F.prevYear})` : "") : null,
      subEl: "#zd-hint", sub: `KEV entries added ≤1 day after the CVE was published, per CVE publication year, 2022 → ${F.year} (${partialLabel(F)}). Not stacked.`,
      how: "A proxy for zero-days: it misses exploitation CISA confirms later, so recent years still fill in.",
      so, src: srcLine(ctx, ctx.zd ? ["kev", "zd"] : ["kev"]),
    });
    fig("#tbl-zd", {
      subEl: "#zd-list-hint", sub: ctx.zd && ctx.zd.recent ? `Latest in-the-wild zero-days, newest first (${ctx.zd.source || "tracker"}).` : "Latest KEV entries added ≤1 day after publication, newest first; date = added to KEV.",
      src: srcLine(ctx, ctx.zd ? ["zd"] : ["kev"]),
    });
  } catch (e) { /* skip */ }
  try {
    const sc = core.originMonths && ytdMonths(core, core.originMonths.supplychain, F);
    fig("#chart-supply", {
      titleEl: "#h-supply-cves",
      title: sc && sc.prev ? `Open-source CVEs ${xr(sc.cur, sc.prev)}: ${num.format(sc.cur)} in ${sc.label} ${F.year} vs ${num.format(sc.prev)} in ${sc.label} ${F.prevYear}` : null,
      subEl: "#supply-hint", sub: `CVEs in open-source projects and packages (registry packages + GitHub-assigned OSS records), per year, 2018 → ${F.year} (${partialLabel(F)}). Not stacked.`,
      how: "Each bar = open-source CVEs published that year (registry packages plus GitHub-assigned OSS projects, AI packages included). Pitfall: much of the recent jump comes from GitHub's CNA (GitHub_M) issuing far more CVEs — partly a reporting change, not only more vulnerable code.",
      so: sc && sc.prev && sc.cur / sc.prev >= 1.3 ? "Whatever the reporting share, the fix volume is real — make sure SCA/dependency scanning and OSS patching cover every build pipeline." : null,
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
          .map(([y, o]) => `${y} is ${o.mult}× a typical year, almost all ${o.eco} — a mass spam/campaign wave that flattens the other years; `)
          .join("") || "") + "one report can cover many package versions.",
        so: cur ? "Block or quarantine newly published packages in your package proxy and pin dependencies — malicious uploads now arrive by the thousand." : null,
        src: srcLine(ctx, ["osv"]),
      });
    }
  } catch (e) { /* skip */ }
}

/* " N of M show EPSS under 10% despite confirmed exploitation …" — the trap
 * of reading a low EPSS on a KEV entry as "safe to defer" */
function lowEpssNote(rows, epss) {
  const sc = epss && epss.scores;
  if (!sc || !rows || !rows.length) return "";
  const scored = rows.filter((r) => sc[r.cve] && fin(sc[r.cve].epss));
  const low = scored.filter((r) => sc[r.cve].epss < 0.1).length;
  return low ? ` ${low} of ${scored.length} show EPSS under 10% despite confirmed exploitation: EPSS predicts broad, near-term activity and misses targeted attacks, so a low score on a KEV entry does not mean safe to defer.` : "";
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
        + lowEpssNote(rows, ctx.epss),
      so: prods.length ? `If you run ${listJoin(prods.map((p) => p.name))}, verify these CVEs are patched now — KEV status outranks any EPSS or CVSS score.` : null,
      src: srcLine(ctx, ["kev", "epss"]),
    });
  } catch (e) { /* skip */ }
  try {
    const lm = core.layerMonths;
    if (lm && ctx.layers) {
      let big = null;
      for (const [id, arr] of Object.entries(lm)) {
        if (id === "other" || !Array.isArray(arr)) continue;
        const cur = core.months.reduce((s, m, i) => s + (m.startsWith(F.year) ? arr[i] || 0 : 0), 0);
        if (!big || cur > big.cur) big = { id, cur };
      }
      fig("#chart-layers", {
        titleEl: "#h-layers",
        title: big && big.cur && layerYtd(core, F) ? `${ctx.label(big.id)} is the largest AI layer: ${num.format(big.cur)} of ${num.format(layerYtd(core, F))} CVEs in AI software in ${F.year} (${pct(big.cur / layerYtd(core, F))})` : null,
        subEl: "#layers-hint", sub: `CVEs in AI software, MCP agents and AI features per month, 2018 → ${F.year} (${partialLabel(F)}; the last month is partial), stacked by AI stack layer. Excludes CVEs that are AI-related only as a weakness, compute or found-by-AI. Click a legend entry to hide a layer.`,
        after: "#layers-note",
        how: "Each bar = AI CVEs published that month; segments add up to the month's total. Pitfall: one project's batch disclosure can dominate a year (labelled on the chart).",
        so: big && big.cur ? `Inventory where ${lcFirst(ctx.label(big.id))} run in your estate — that is where most new AI CVEs land.` : null,
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
  try {
    const ep = ctx.epss && ctx.epss.scores;
    if (ep) {
      const d = ctx.epss.dist && ctx.epss.dist.ai;
      fig("#tbl-epss", {
        titleEl: "#h-patch", title: d && d.n ? `${num.format(d.ge10)} of ${num.format(d.n)} AI-related CVEs from the last 12 months have an EPSS of 10% or more — these are the top ones not yet in KEV` : null,
        subEl: "#epss-hint", sub: "AI-related CVEs published in the last 12 months and not in CISA KEV, ranked by FIRST EPSS (estimated probability of exploitation activity in the next 30 days), highest first.",
        how: "EPSS is a model estimate (0–100%), not observed exploitation. AI relation = why it counts as AI-related; 'found by AI' rows are ordinary software whose bug an AI tool or lab reported.",
        so: "Order of work: the exploited table above first (confirmed exploitation, whatever its EPSS), then this list from the top.",
        src: srcLine(ctx, ["epss", "kev"]),
      });
    }
  } catch (e) { /* skip */ }
}

function explainDetail(ctx, F, S) {
  const core = ctx.core;
  try {
    const sc = core.severityCompare;
    if (sc && sc.ai && F.sevShare && F.sevShare.ai) {
      fig("#sev-compare", {
        titleEl: "#h-sevcmp",
        title: `${pct(F.sevShare.ai.hc)} of AI CVEs are HIGH/CRITICAL` + (F.sevShare.all ? ` vs ${pct(F.sevShare.all.hc)} of all CVEs` : ""),
        subEl: "#sevcmp-sub", sub: `Share of rated CVEs by CVSS severity, published ${Array.isArray(sc.window) ? sc.window.join(" to ") : "in the window"}; 100% bars, AI vs all.`,
        how: "Severity is the vendor's CVSS base score, not risk; unrated CVEs are excluded from the percentages.",
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
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
        title: best ? `${names[best.id] || best.id} is ${best.r.toFixed(1)}× more common in AI CVEs (${pct(best.a, 1)} vs ${pct(best.b, 1)})` : null,
        how: "Blue = share of AI CVEs with that CWE; grey = share of all CVEs. Pitfall: only the first CWE of each record counts; '—' = not among the top CWEs overall.",
        so: best ? `Ask AI vendors and internal AI teams specifically about ${names[best.id] || best.id} defences.` : null,
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
  try {
    const sy = core.landscape && core.landscape.ai && core.landscape.ai.sevYears;
    const o = sy && sy[F.year];
    if (o) {
      const r = SEV_KEYS.reduce((t, k) => t + (o[k] || 0), 0), hc = (o.CRITICAL || 0) + (o.HIGH || 0);
      fig("#chart-sev", {
        titleEl: "#h-sevmix", title: r ? `${num.format(hc)} HIGH/CRITICAL AI-related CVEs in ${F.year} so far (${pct(hc / r)} of ${num.format(r)} rated)` : null,
        subEl: "#sev-hint", sub: `AI-related CVEs per year, 2018 → ${F.year} (${partialLabel(F)}), stacked by CVSS severity from the CVE record.`,
        how: "Segments add up to the year's AI-related CVEs, CRITICAL at the bottom, unrated on top. Severity is the vendor's CVSS, not risk.",
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
  try {
    const ytd = ytdMonths(core, core.aiMonths, F), all = ytdMonths(core, core.counts, F);
    fig("#chart-cves", {
      titleEl: "#h-issuance",
      title: ytd && all && all.cur && all.prev ? `AI's share of all CVEs: ${pct(ytd.cur / all.cur, 1)} in ${ytd.label} ${F.year} vs ${pct(ytd.prev / all.prev, 1)} a year earlier` : null,
      subEl: "#issuance-hint", sub: "AI-related CVEs as a % of all published CVEs, per month since 2018. Spikes are single-product bulk disclosures (e.g. TensorFlow 2021, OpenClaw 2026). Switch Mode to Count or Cumulative for absolute numbers (lines, not stacked).",
      after: "#ctl-cves",
      how: "Count = CVEs per period; Cumulative = running total; AI share % = AI ÷ all per period. Pitfall: the last period is partial.",
      src: srcLine(ctx, ["cve"]),
    });
  } catch (e) { /* skip */ }
  try {
    fig("#tbl-ai", { subEl: "#latest-hint", sub: "Last 30 AI-related published records, newest first. AI relation = why it counts (hover a tag); KEV = also in CISA's exploited catalog; severity badge = record CVSS (hover for version and source).", src: srcLine(ctx, ["cve", "kev"]) });
  } catch (e) { /* skip */ }
  try {
    const cy = core.cnaYears && core.cnaYears[F.year];
    if (cy) {
      const tot = sumObj(cy);
      const top = Object.entries(cy).filter(([c]) => c !== "other").sort((a, b) => b[1] - a[1])[0];
      fig("#chart-cna", {
        titleEl: "#h-cna", title: cnaTitle(core.cnaYears, F, top, tot),
        how: "Stacked: each colour is one CVE Numbering Authority's AI CVEs that year (top 7 overall + other CNAs). Pitfall: one prolific new CNA raises counts without more vulnerable software.",
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
  try {
    const ap = ctx.ap;
    if (ap && ap.months) {
      const curM = +F.asOf.slice(5, 7) - 1;
      let a = 0, b = 0;
      for (const [m, n] of Object.entries(ap.months)) {
        if (+m.slice(5, 7) > Math.max(1, curM)) continue;
        if (m.startsWith(F.year)) a += n; if (m.startsWith(F.prevYear)) b += n;
      }
      fig("#chart-aipkgs", {
        titleEl: "#h-aipkgs", title: a && b ? `AI package advisories ${xr(a, b)} like-for-like (${num.format(a)} vs ${num.format(b)}, Jan–${MONTHS[Math.max(1, curM) - 1]})` : null,
        after: "#adv-recent",
        how: "Each bar = OSV advisories for AI/ML packages published that month. Pitfall: one advisory can name several packages.",
        src: srcLine(ctx, ["osv"]),
      });
    }
  } catch (e) { /* skip */ }
  try {
    const m = ctx.dl && ctx.dl.npmMonthly && ctx.dl.npmMonthly.openai;
    if (m) {
      const ks = Object.keys(m).sort();
      const full = ks.slice(0, -1); // drop the partial current month
      const last = full[full.length - 1], yAgo = full.find((x) => x === ymAdd(last, -12));
      fig("#chart-adoption", {
        titleEl: "#h-adoption",
        title: yAgo && m[yAgo] ? `openai SDK downloads ${xr(m[last], m[yAgo])} in 12 months (log scale)` : "Adoption context: npm AI SDK downloads (log scale)",
        subEl: "#adoption-hint", sub: "Monthly npm downloads per package, log scale (each gridline = 10×). Adoption context only — not attack surface, not used in any count above.",
        how: "Lines are not stacked; a straight rising line on a log scale means steady exponential growth. The last month is partial.",
        src: srcLine(ctx, ["npm"]),
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
        titleEl: "#h-ttk", title: n ? `${pct(wk / n)} of ${F.year}'s KEV additions were exploited within a week of disclosure` : null,
        subEl: "#ttk-hint", sub: `CISA KEV additions per year (by date added), 2022 → ${F.year} (${partialLabel(F)}), stacked by days from CVE publication to KEV addition.`,
        how: "Red/orange = exploited within a week of the CVE going public; grey = old CVEs newly confirmed as exploited. Pitfall: KEV dates are when CISA confirmed it, so true exploitation often started earlier.",
        so: n && wk / n >= 0.25 ? "A monthly patch cycle is too slow for a quarter or more of exploited bugs: keep an emergency path that can ship a fix or mitigation within days." : null,
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
      subEl: "#kevall-hint", sub: "The 15 most recent CISA KEV additions, newest first. RANSOMWARE = CISA knows of ransomware use; 0-DAY = added within one day of the CVE's publication.",
      how: "Every row is confirmed in-the-wild exploitation. EPSS = estimated chance of exploitation activity in the next 30 days.",
      so: "If you run any of these products, these come before everything else in the patch queue.",
      src: srcLine(ctx, ["kev", "epss"]),
    });
  } catch (e) { /* skip */ }
  try {
    const d = ctx.epss && ctx.epss.dist && ctx.epss.dist.all;
    fig("#tbl-next", {
      titleEl: "#h-next", title: d && d.n ? `${num.format(d.ge10)} of the last 12 months' ${num.format(d.n)} CVEs have an EPSS of 10% or more — the top ones are not in KEV yet` : null,
      subEl: "#next-hint", sub: "CVEs published in the last 12 months that are not in CISA KEV, ranked by FIRST EPSS (estimated probability of exploitation activity in the next 30 days), highest first.",
      how: "EPSS is a model estimate, not observed exploitation; a high score means attackers are likely already probing for it.",
      so: d && d.n ? `Fewer than ${pct(Math.max(d.ge10 / d.n, 0.001), 1)} of new CVEs clear 10% EPSS — patching that slice after KEV covers most near-term exploitation at a fraction of the volume.` : null,
      src: srcLine(ctx, ["epss", "kev", "cve"]),
    });
  } catch (e) { /* skip */ }
  try {
    const sy = L && L.sevYears;
    if (sy) {
      fig("#chart-sevall", {
        titleEl: "#h-sevall", title: S.hc && fin(S.hc.cur) ? `${pct(S.hc.cur)} of ${F.year}'s rated CVEs are HIGH or CRITICAL` + (fin(S.hc.prev) ? ` (${pct(S.hc.prev)} in ${F.prevYear})` : "") + ` — ${num.format(S.hc.crit)} CRITICAL so far` : null,
        subEl: "#sevall-hint", sub: `Published CVEs per year, 2018 → ${F.year} (${partialLabel(F)}), stacked by CVSS severity from the CVE record (CNA, else CISA-ADP).`,
        how: "Segments add up to the year's CVEs, CRITICAL at the bottom, unrated on top. Severity is the vendor's CVSS base score: worst-case impact, not likelihood of attack.",
        so: S.hc && fin(S.hc.cur) && S.hc.cur >= 0.4 ? "With this many HIGH/CRITICAL CVEs, severity alone cannot order the queue — use KEV and EPSS first." : null,
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
  try {
    if (L) {
      const names = (ctx.sev && ctx.sev.cweNames) || {};
      const w = L.window || {};
      const span = w.cur ? `${w.cur[0]} to ${w.cur[1]}` : "the last 12 months";
      const cw = topRiser(cweRows(L.cweTop, names));
      fig("#cweall", {
        titleEl: "#h-cweall", title: cw ? `Fastest-growing weakness: ${cw.label}, ${growthText(cw.n, cw.prev)}` : null,
        subEl: "#cweall-hint", sub: `CVEs per weakness class (first CWE in the record), ${span} vs the 12 months before. Top 10.`,
        how: "Bar = last 12 months, tick = the 12 months before. Pitfall: a CVE counts once, under its first CWE; many records have none.",
        src: srcLine(ctx, ["cve"]),
      });
      const vr = vendorRows(L.vendorTop);
      const vb = topRiser(vr);
      fig("#vendall", {
        titleEl: "#h-vendall", title: vr.length ? `${vr[0].label} leads with ${num.format(vr[0].n)} CVEs` + (vb && vb !== vr[0] ? ` — ${vb.label} grew most (${growthText(vb.n, vb.prev)})` : "") : null,
        subEl: "#vendall-hint", sub: `CVEs per vendor (first affected vendor in the record), ${span} vs the 12 months before. Top 10.`,
        how: "Bar = last 12 months, tick = the 12 months before. Pitfall: vendors that file their own CVEs (Linux, Microsoft, Oracle) look larger than vendors whose bugs go unreported.",
        src: srcLine(ctx, ["cve"]),
      });
      const cr = cnaRows(L.cnaTop);
      const cb = topRiser(cr);
      fig("#cnaall", {
        titleEl: "#h-cnaall", title: cb ? `Who files moves the curve: ${cb.label} filed ${num.format(cb.n)} CVEs in the last 12 months (${growthText(cb.n, cb.prev)})` : null,
        subEl: "#cnaall-hint", sub: `CVEs per CVE Numbering Authority (assigner), ${span} vs the 12 months before. Top 10.`,
        how: "Bar = last 12 months, tick = the 12 months before. A CNA is whoever assigned the CVE id — a vendor, a bug-bounty platform or a coordinator.",
        so: cb && cb.n / Math.max(1, cb.prev) >= 3 ? "Before reading the surge as more vulnerable software, discount the new bulk filers: their growth is a reporting change." : null,
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
      const fast = Object.entries(ry).filter(([, v]) => v.prev >= 20).sort((a, b) => b[1].cur / b[1].prev - a[1].cur / a[1].prev)[0];
      fig("#rel-bars", {
        titleEl: "#h-rel", title: top ? `${ctx.relLabel(top[0])} account for most AI-related CVEs in ${F.year} (${num.format(top[1].cur)})` + (fast && fast[0] !== top[0] ? `; ${lcFirst(ctx.relLabel(fast[0]))} grew fastest` : "") : null,
        subEl: "#rel-hint", sub: `AI-related CVEs published in ${F.year} (${partialLabel(F)}) by kind of AI relation. A CVE can carry several tags, so the bars add up to more than the AI-related total.`,
        after: "#chart-rel",
        how: "Left: this year's count per relation. Right: the same per year, one line each (click a legend entry to hide a line and rescale). Pitfall: the last year is partial.",
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
        titleEl: "#h-aiorigin", title: top && top[1] ? `${pct(top[1] / n)} of ${F.year}'s AI-related CVEs are in ${oShort(top[0], OL)}` : null,
        subEl: "#aiorigin-hint", sub: `AI-related CVEs per year, 2018 → ${F.year} (${partialLabel(F)}), stacked by origin — the same categories as Part 1.`,
        how: "Segments add up to each year's AI-related CVEs. This connects the two parts: e.g. open-source AI packages count under supply chain, Copilot under core platforms.",
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
  try {
    const L = core.landscape && core.landscape.ai;
    if (L) {
      const vr = vendorRows(L.vendorTop);
      const vb = topRiser(vr);
      fig("#vendai", {
        titleEl: "#h-vendai", title: vr.length ? `${vr[0].label} leads AI-related CVEs with ${num.format(vr[0].n)} in the last 12 months` + (vb && vb !== vr[0] ? `; ${vb.label} grew most` : "") : null,
        how: "Bar = last 12 months, tick = the 12 months before; text = count · change. 'new' = none the year before.",
        src: srcLine(ctx, ["cve"]),
      });
    }
  } catch (e) { /* skip */ }
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

/* ================= quiet layout: details behind an ⓘ =================
 * Each chart/table keeps its takeaway title, the visual and the "So what"
 * line. Subtitle, notes, "How to read" and the source line move into a panel
 * that opens on hover (mouse), on tap (touch) and on focus (keyboard). */
let infoSeq = 0;
function infoize() {
  const heads = document.querySelectorAll("main h2[id^='h-'], main h3[id^='h-'], main p.headline");
  for (const t of heads) {
    if (t.closest("#method") || t.closest(".todo") || t.closest(".exploited-strip")) continue;
    const BLOCK = ".sub, .panel, section, .tier";
    const block = t.parentElement.closest(BLOCK) || t.parentElement;
    // lines that belong to this title's block, not to a nested sub-panel
    const items = [...block.querySelectorAll("p.hint, p.subhead, p.note, .figfoot > p.how, .figfoot > p.src")]
      .filter((el) => el.parentElement.closest(BLOCK) === block && !el.closest(".info-body") && el.textContent.trim() && !el.classList.contains("toplegend"));
    // a headline's info is only its own subhead
    const pick = t.matches("p.headline") ? items.filter((el) => el.matches(".subhead")) : items.filter((el) => !el.matches(".subhead"));
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
  let core, meta, kev, ap, dl, sev, epss, mal, zd;
  try {
    [core, meta, kev, ap, dl, sev, epss, mal, zd] = await Promise.all([
      loadJSON("data.json"), opt("ai_meta.json"), opt("kev.json"), opt("ai_packages.json"),
      opt("downloads.json"), opt("severity.json"), opt("epss.json"), opt("malicious.json"), opt("zerodays.json"),
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
    stamp.textContent = `data as of ${gen.toUTCString()} · ` +
      (kev && kev.generatedAt ? `KEV ${String(kev.generatedAt).slice(0, 10)} · ` : "") +
      (epss && epss.modelDate ? `EPSS ${epss.modelDate} · ` : "") + "rebuilt daily" + stale;
    if (stale) stamp.classList.add("err");
  } catch (e) { stamp.textContent = "data loaded"; }

  const layers = layerList(core, meta);
  const rels = relList(core, meta);
  const ctx = { core, meta, kev, ap, dl, sev, epss, mal, zd, layers, label: makeLayerLabel(layers), metaOf: metaLookup(meta), rels, relLabel: makeRelLabel(rels) };
  let F = {};
  try { F = computeFacts(ctx); } catch (e) { F = { asOf: new Date().toISOString().slice(0, 10) }; F.year = F.asOf.slice(0, 4); F.prevYear = String(+F.year - 1); }
  ctx.F = F;
  let S = {};
  try { S = computeSurgeFacts(ctx, F); } catch (e) { S = {}; }
  // each panel renders independently: one bad data file must not blank the rest
  const panels = [
    // Part 1: all CVEs
    ["headline", () => buildHeadline(ctx, F, S)],
    ["KPIs", () => buildKpis(ctx, F, S)],
    ["brief", () => buildBrief(ctx, F, S)],
    ["hero chart", () => buildHeroChart(ctx, F)],
    ["where exploitation happens", () => buildWhere(ctx, F, S)],
    ["KEV by origin", () => buildKevOrigin(ctx)],
    ["zero-days", () => { buildZeroDay(ctx); labelCells($("#tbl-zd")); }],
    ["time to KEV", () => buildTtk(ctx)],
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
    ["severity compare", () => buildSevCompare(ctx)],
    ["CWE compare", () => buildCweCompare(ctx)],
    ["AI vendors", () => buildVendAi(ctx)],
    ["severity chart", () => buildSevChart(ctx)],
    ["layer chart", () => buildLayerChart(ctx)],
    ["AI CVE table", () => { buildRecentAiTable(ctx); wireAiFilter(); }],
    ["CNA chart", () => buildCnaChart(ctx)],
    ["AI packages", () => buildAiPkgs(ctx)],
    ["adoption", () => buildAdoptionChart(ctx)],
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
  try { clipTables(); } catch (err) { /* tables simply stay full length */ }
  try { infoize(); } catch (err) { /* details simply stay inline */ }
  // canvas charts take their colours at draw time: redraw on a theme switch
  try { matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => location.reload()); } catch (e) { /* old browsers keep the first theme */ }
})();

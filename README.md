# AI × Cybersecurity dashboard

A static, self-hosted dashboard showing **how AI is changing the cybersecurity
landscape** across time scales — hourly, daily, weekly, monthly, yearly — and
its impact (exploitation, attack-surface growth, adoption).

No server, no database, no third-party runtime dependency: six JSON data files
plus one page. The only JS runtime on the page is a self-hosted copy of
[uPlot](https://uplot.org) (vendored in `vendor/`).

![status](https://img.shields.io/badge/data-rebuilt%20daily-blue)

## What it shows

| Panel | What | Source |
|---|---|---|
| Stat cards | Totals, AI share, month projection, KEV, package advisories, adoption | all sources |
| CVE issuance | All vs AI-related per day/week/month/year; count / cumulative / AI share % | `cvelistV5` |
| Hourly activity | New CVEs per hour (40d) + record updates per hour (30d) | `cvelistV5` + `deltaLog.json` |
| AI package vulns | Advisories per month for AI/ML packages (PyPI + npm) | OSV.dev |
| AI CVE severity mix | Stacked CRITICAL/HIGH/MEDIUM/LOW per month over the whole AI set | cvelistV5 + NVD CVSS |
| Top CWEs of AI CVEs | The 12 most common weakness classes behind AI CVEs (NVD) | cvelistV5 + NVD |
| AI adoption | Monthly npm downloads of AI SDKs (log scale) | npm downloads API |
| Latest AI CVEs | Feed of the last 30 AI-matched CVEs, CNA + CVSS severity + KEV cross-ref | `cvelistV5` + NVD + KEV |
| KEV timeline | KEV additions per month (all products, since Nov 2021) + ransomware stat | CISA KEV |
| KEV (AI) | CISA Known-Exploited entries matching AI keywords | CISA KEV |

## Data sources (all public, keyless)

1. **`CVEProject/cvelistV5`** (git) — the *official* CVE list in CVE-JSON-5.
   One JSON file per CVE under `cves/<year>/<prefix>xxx/`, synced upstream
   ~every 7 minutes. We clone it depth-1 + partial (blobless) + sparse
   (~4.5 GB working tree). Each record's `cveMetadata` carries
   `state`, `datePublished`, `dateReserved` (hour precision) — the core of
   every chart. `cves/deltaLog.json` is a 30-day rolling log of every sync
   (new/updated CVE ids) → hourly activity.
   *This is the same source as cve.0xosprey.com, and the best source for
   raw CVE counts: it is the list itself, not a derived index.*
2. **CISA KEV** (single JSON) — known-exploited-vulnerabilities catalog.
3. **OSV.dev** (API) — package security advisories (GitHub Security, PyPI,
   npm, …) for a curated list of 24 PyPI + 9 npm AI/ML packages.
4. **npm downloads API** + **pypistats** — adoption / attack-surface proxies.
5. **NVD API 2.0** (enrichment only) — `sourceIdentifier` for CNA names and
   primary **CVSS severity/score** for the 30-entry feed (badges); full-text
   keyword counts on the AI card; and a full **CVSS join over the entire AI
   set** (one `cveId` per request — NVD only honors the first of a multi-cveId query — ≈2250 requests, cached in `cvss.json`,
   incremental afterwards) → the severity-mix chart. NVD is a *derived*
   source (it lags the CVE list), so it's used for enrichment, never for the
   core counts.

### Why not just NVD for everything?

NVD's `keywordSearch` (e.g. “large language model” → ~200 CVEs) is useful,
but NVD is a secondary index: records arrive after the CVE list, counts drift
vs the official list, and full-text search can't see `dateReserved` (only
published records). `cvelistV5` is the primary source and is also what the
reference site uses.

## “AI-related” — methodology

A CVE counts as AI-related if a case-insensitive keyword set matches its
English description **or** its affected vendor/product/packageURL. The set
covers ML terminology (“machine learning”, “neural”, “LLM”, “prompt
injection”, …), AI frameworks (PyTorch, TensorFlow, Hugging Face, ONNX, …)
and package names (`transformers`, `vllm`, `openai`, …) with word-boundary
matching so e.g. `jax` does **not** match “AJAX” or “JAX-WS”. It is a
heuristic: expect a small error both ways (roughly 0.1–0.5% of all CVEs).
Tune `AI_PATTERNS` / `AI_PACKAGES` in `build.py`.

## Pipeline

```
build.py     cvelistV5 (git)  →  data/data.json        (+ data/ai_meta.json, data/cache.json)
sources.py   KEV, OSV, NVD, npm/pypistats → data/{kev,ai_packages,nvd,downloads,severity}.json
index.html   static page (CSP-locked) reading data/*.json via same-origin fetch
```

- First run clones the repo (~4.5 GB) and parses all ~414k records (~1 min).
  Parsed `(state, published, reserved, isAi)` rows are cached in
  `data/cache.json`.
- Later runs `git fetch` only the changed files (a few MB) and re-parse just
  those (~6 s) — the repo publishes ~100 changed files a day.
- Set `CVE_CLONE_DIR` to relocate the clone (CI uses the runner temp dir).
- NVD lookups for the 30-entry feed are cached in `data/orgs.json`.
- `build.py` also emits `data/ai_meta.json` (every AI CVE id + publish date),
  which `sources.py` uses for the incremental NVD CVSS join (cached in
  `data/cvss.json`, aggregated to `data/severity.json`). First CVSS run is
  ~2250 NVD requests (~50 min anonymous); later runs only fetch new AI CVEs.

### Run it

```bash
python3 build.py      # incremental (full on first run; --full to force)
python3 sources.py    # KEV/OSV/NVD/downloads ~1.5 min + AI CVSS join
                      #   (first CVSS run ~50 min; CVSS_LIMIT=20 for a quick slice)
python3 -m http.server 8080
open http://localhost:8080
```

Dev loop: `python3 test_build.py` (unit tests, no network),
`./tools/check.sh` (headless-Chrome smoke test: data + render + no overflow;
needs Chrome, set `CHROME` env if needed), and
`python3 tools/cdp_probe.py <url> "<js-expression>"` (ad-hoc DOM probe).

## Hosting (public)

The site is fully static — `index.html`, `css/`, `js/`, `vendor/uPlot.*`,
`data/*.json`. Anything static works (GitHub Pages, Cloudflare Pages,
Netlify, a reverse proxy).

**GitHub Pages + daily rebuild**: `.github/workflows/daily.yml` is wired for
it — a cron job rebuilds the data, commits `data/`, and the push triggers
the Pages deploy of a clean `dist/` (no clone, no caches). Enable Pages with
“GitHub Actions” as the source.

**Any host**: serve the repo root and set these headers:

```
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cache-Control: public, max-age=3600   (for data/*.json)
```

## Security posture

- **CSP**: `default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors
  'none'` — no inline JS/CSS, no CDNs, no `eval`, no remote fetches.
  The page works offline once loaded.
- All dynamic text is inserted via `textContent` (no `innerHTML` with data).
- External links open in a new tab with `rel="noopener"`.
- The only runtime JS is vendored uPlot (51 KB, pinned 1.6.32), loaded with a
  Subresource-Integrity hash (`integrity="sha384-..."`).
- Data files are the same origin; nothing leaves the browser.

## Chart rendering notes (uPlot 1.6)

How each graph is actually built — useful if you are poking at `js/app.js` or
the rendered DOM:

- **X-axis data units differ per chart.** The time charts (cves, severity, KEV,
  AI packages, adoption) index x in **days from epoch** (e.g. 20727 =
  2026-10-23); the hourly chart uses **seconds from epoch**. uPlot's `time`
  scale does not convert units — it passes the *raw data units* through to the
  axis `values` formatter and only uses them for positioning — so each chart's
  formatter converts to a `Date` with its own multiplier (`86400e3` for days,
  `1e3` for seconds).
- **Label formatter is `axes[].values`, not `ticks`.** `values:
  (self, vals) => [..labels]` receives the tick values (in data units) and
  returns one string per tick (empty string hides the label). `ticks` only
  styles the tick marks. (The app wraps this as the `tick(fn)` helper.)
- **Label density is span-aware.** Long spans get year-only labels (e.g.
  "2004, 2009, 2014…" across 27 years); short spans get "YYYY-MM" or
  "MM-DD". This lives in the per-chart `values` closures and `monthTick()`.
- **The hourly chart uses seconds**, because uPlot's time-scale tick *placement*
  (a discrete increment list of clean day/month steps) assumes
  second-magnitude values; hour-magnitude values produced only ~1 misplaced
  tick. At a 41-day second-scale range it places midnight-aligned ticks every
  5 days (verified: 09-13, 09-18, 09-23…).
- **y2 "updates" series**: the hourly chart plots record-updates on a second
  y-scale (`y2`) whose range is `max*3` — i.e. the line is drawn at 1/3 scale
  and the cursor tooltip shows true counts. The axis is hidden.
- **Sizing**: uPlot takes a fixed `width` (no `clientWidth` reading
  internally). `makeChart` measures the *host element's* `clientWidth`
  (not the panel's — the panel's includes its padding, which used to make the
  canvas 20 px too wide on mobile) and a `ResizeObserver` re-applies
  `setSize` when the layout width changes by more than 2 px. The host on the
  instance is `u.root` (1.6.x exposes no `u.el`).
- **No `setOptions` in 1.6.x**: state changes (granularity, mode, series
  toggles) go through `setData` / `setSeries(i, {show})`; axis `label` is
  mutated directly on `u.axes[n]`.
- **Legends**: uPlot 1.6.32 legends are clickable — the series *label*
  cell (`th`) toggles the series natively (the row/table itself is not the
  target). The main chart mirrors that toggle into its custom checkboxes +
  state via a delegated click listener on `.u-legend` (bound on a rAF: the
  legend DOM only exists after the first layout frame). The hourly chart
  shows a cursor-driven `.htip` text line instead; the severity chart keeps
  its legend off (a stacked mix shouldn't be partially toggled).
- **Headless verification**: `tools/cdp_probe.py` drives headless Chrome over
  CDP; the charts expose themselves as `document.querySelector("#chart-*")._u`
  (uPlot instance), whose `axes[n]._values` is the exact label array uPlot
  rendered. Probe with a fresh `CDP_PROFILE` — a persistent profile will
  serve stale `js/app.js` from its heuristic HTTP cache.

## Layout

```
index.html            the page (CSP meta, markup)
css/style.css         dark, responsive layout
js/app.js             charts + tables (uPlot, defensive)
vendor/uPlot.*        pinned uPlot 1.6.32 (self-hosted)
build.py              cvelistV5 → data/data.json + data/ai_meta.json
sources.py            KEV / OSV / NVD / npm / pypistats → data/*.json (+ severity.json, cvss.json cache)
test_build.py         unit tests for the heuristics + parser
tools/check.sh        headless smoke test (data + render + overflow)
tools/cdp_probe.py    headless-Chrome probe helper (dev only)
tools/check_expr.js   JS assertions used by check.sh
data/                 generated JSON (committed; caches gitignored)
.github/workflows/    daily rebuild + Pages deploy
```

## Ideas / extensions

- **PyPI download history** via the public BigQuery
  `pypi.file_downloads` dataset (needs a GCP service account) for a log-scale
  PyPI mirror of the npm adoption chart.
- **CNA org names** at scale: the CVE Services orgs API; per-CVE NVD
  `sourceIdentifier` is used today for the 30-entry feed only.
- **arXiv cs.CR + ML paper counts** as a research-activity proxy.
- **HuggingFace model count** as an AI-surface proxy (API needs paging).

## Caveats

- “AI-related” is a keyword heuristic (see methodology).
- NVD-based enrichment lags the CVE list by hours–days.
- `deltaLog.json` covers only 30 days (upstream rolling window).
- npm downloads count = package installs, not unique users.

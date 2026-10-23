# AI × Cybersecurity dashboard

A static, self-hosted dashboard showing **how AI is changing the cybersecurity
landscape** across time scales — hourly, daily, weekly, monthly, yearly — and
its impact (exploitation, attack-surface growth, adoption).

No server, no database, no third-party runtime dependency: five JSON data files
plus one page. The only JS runtime on the page is a self-hosted copy of
[uPlot](https://uplot.org) (vendored in `vendor/`).

![status](https://img.shields.io/badge/data-rebuilt%20daily-blue)

## What it shows

| Panel | What | Source |
|---|---|---|
| Stat cards | Totals, AI share, month projection, KEV, package advisories, adoption | all sources |
| CVE issuance | All vs AI-related CVEs per day/week/month/year, count/cumulative | `cvelistV5` |
| Hourly activity | New CVEs per hour (40d) + record updates per hour (30d) | `cvelistV5` + `deltaLog.json` |
| AI package vulns | Advisories per month for AI/ML packages (PyPI + npm) | OSV.dev |
| AI adoption | Monthly npm downloads of AI SDKs (log scale) | npm downloads API |
| Latest AI CVEs | Feed of the last 30 AI-matched CVEs, CNA + KEV cross-ref | `cvelistV5` + NVD + KEV |
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
5. **NVD API 2.0** (used lightly) — `sourceIdentifier` for CNA names in the
   feed; full-text keyword counts shown on the AI card. NVD is a *derived*
   source (it lags the CVE list), so it's used for enrichment, not counts.

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
build.py     cvelistV5 (git)  →  data/data.json        (+ data/cache.json)
sources.py   KEV, OSV, NVD, npm/pypistats → data/{kev,ai_packages,nvd,downloads}.json
index.html   static page (CSP-locked) reading data/*.json via same-origin fetch
```

- First run clones the repo (~4.5 GB) and parses all ~414k records (~1 min).
  Parsed `(state, published, reserved, isAi)` rows are cached in
  `data/cache.json`.
- Later runs `git fetch` only the changed files (a few MB) and re-parse just
  those (~6 s) — the repo publishes ~100 changed files a day.
- Set `CVE_CLONE_DIR` to relocate the clone (CI uses the runner temp dir).
- NVD lookups for the 30-entry feed are cached in `data/orgs.json`.

### Run it

```bash
python3 build.py      # incremental (full on first run; --full to force)
python3 sources.py    # ~1.5 min (NVD rate limits included)
python3 -m http.server 8080
open http://localhost:8080
```

Dev loop: `python3 test_build.py` (unit tests, no network) and
`python3 tools/cdp_probe.py <url> "<js-expression>"` (headless-Chrome DOM
probe; set `CHROME` env if needed).

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
- The only runtime JS is vendored uPlot (51 KB, pinned 1.6.32).
- Data files are the same origin; nothing leaves the browser.

## Layout

```
index.html            the page (CSP meta, markup)
css/style.css         dark, responsive layout
js/app.js             charts + tables (uPlot, defensive)
vendor/uPlot.*        pinned uPlot 1.6.32 (self-hosted)
build.py              cvelistV5 → data/data.json
sources.py            KEV / OSV / NVD / npm / pypistats → data/*.json
test_build.py         unit tests for the heuristics + parser
tools/cdp_probe.py    headless-Chrome probe helper (dev only)
data/                 generated JSON (committed; caches gitignored)
.github/workflows/    daily rebuild + Pages deploy
```

## Ideas / extensions

- **CVSS severity split** of AI CVEs: join the 2k AI records with NVD
  (≈500 requests with a free API key, 50 req/30 s) and chart
  critical/high/medium/low per month.
- **CWE distribution** for AI CVEs (same join) — “AI software breaks in
  different ways”.
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

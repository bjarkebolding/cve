# The vulnerability surge — and how much of it is AI

A static, self-hosted dashboard for security leaders, in two halves.
**Part 1** gives the complete picture of *all* CVEs: volume, exploitation
(CISA KEV), zero-days, speed of exploitation, what to patch next, severity,
weakness classes, vendors, who files, supply chain. **Part 2** answers which
of those are **AI-related** — and how: AI software, MCP agents, AI features
in mainstream products, AI-specific weaknesses, AI compute, and bugs found by
AI. Rebuilt daily from public data.

The page reads top-down from executive summary to analyst detail:

1. **All CVEs** — headline, four KPI tiles (CVEs, exploited, zero-days,
   supply chain), CVEs per year by origin, where exploitation happens.
2. **Exploitation** — KEV by origin, zero-day proxy, days from disclosure to
   exploitation, latest exploited, recent zero-days, patch next (EPSS).
3. **Volume** — severity per year; top CWEs, vendors and CNAs (last 12 months
   vs the 12 before); open-source CVEs and malicious packages.
4. **AI-related** — the same questions for the AI slice: relations, share of
   all CVEs, origins, exploited AI-related CVEs, patch next, severity/CWE vs
   all, vendors, stack layers, latest, who reports, context.
5. **Method** — definitions, measured accuracy, caveats.

Every chart follows one standard: the title states the takeaway (computed
from the data), the subtitle says what is plotted (measure, unit, grain,
window), axes carry units, and each chart has a *How to read* line with
its main pitfall, a *So what* line where the data supports an action, and a
source line with its data date. Comparisons are like-for-like (year-to-date
vs the same period last year). Outliers are detected and annotated from the
data (bulk disclosures, spam waves, catalog backlogs) rather than hardcoded.

No server, no database, no third-party runtime dependency: a handful of JSON
data files plus one page. The only JS runtime on the page is a self-hosted
copy of [uPlot](https://uplot.org) (vendored in `vendor/`).

![status](https://img.shields.io/badge/data-rebuilt%20daily-blue)

## What it shows

| Section | What | Source |
|---|---|---|
| Section | What | Source |
|---|---|---|
| **Part 1** headline + KPIs | CVEs YTD (× same period last year), exploited (KEV) YTD, zero-days (KEV proxy + Project Zero), supply chain; HIGH/CRITICAL share; no AI framing | all |
| CVEs by origin | CVEs per year since 2018, stacked by origin; partial year marked; CNA-surge caveat | `cvelistV5` |
| Where exploitation happens | KEV additions this year by origin (count · share) | CISA KEV |
| Exploitation by origin | KEV additions per year by origin (2022+; 2022 backlog quantified) | CISA KEV |
| Zero-days + speed | Exploited-at-disclosure proxy per year; KEV additions by days-to-KEV bucket; recent in-the-wild zero-days | KEV, Google Project Zero |
| Latest exploited / patch next | 15 newest KEV additions (ransomware, 0-day, EPSS); top EPSS CVEs of the last 12 months not yet in KEV | KEV, EPSS |
| Severity, CWE, vendors, CNAs | Severity per year; top 10 CWEs / vendors / assigners, last 12 months vs the 12 before | `cvelistV5` |
| Supply chain | Open-source CVEs per year; malicious packages per year by registry (outlier years clipped + labelled) | `cvelistV5`, OSV |
| **Part 2** headline + KPIs | AI-related CVEs YTD (share, ×), MCP & agent CVEs, exploited AI-related, found by AI | all |
| How CVEs relate to AI | AI-related CVEs this year per relation; per year (lines — tags overlap) | `cvelistV5` |
| AI share, AI by origin | AI % of all CVEs per period; AI-related CVEs per year by Part 1 origin | `cvelistV5` |
| Exploited / patch next (AI) | AI-related KEV entries with relation, days-to-KEV, EPSS; top EPSS AI-related CVEs not in KEV | KEV, EPSS |
| AI vs all, vendors, layers | Severity + CWE vs all CVEs; top AI vendors; AI severity per year; stack layers per month | `cvelistV5` |
| Latest, who reports, context | Last 30 AI-related CVEs (filterable); AI CVEs per CNA; OSV AI package advisories; npm downloads | `cvelistV5`, KEV, OSV, npm |
| Method | Origins, AI relations, layers, zero-day proxy, measured precision/recall, severity rule, caveats | `data.json` |

## Data sources (all public, keyless)

1. **`CVEProject/cvelistV5`** (git) — the *official* CVE list in CVE-JSON-5.
   One JSON file per CVE under `cves/<year>/<N>xxx/`, synced upstream ~every
   7 minutes. Cloned depth-1 + blobless + sparse (~4.5 GB). It is the primary
   source for everything: counts, dates, origin, the AI flag, assigner,
   affected product, CWE and — for ~96% of AI CVEs — severity (the CNA's own
   CVSS, or CISA's ADP "Vulnrichment" score).
2. **CISA KEV** — known-exploited-vulnerabilities catalog (a *lower bound* of
   exploitation: it only lists what CISA has confirmed). Every entry gets an
   origin, its CVE publication date, days-to-KEV and the zero-day flag.
3. **Google Project Zero "0day In the Wild"** — public tracker of confirmed
   in-the-wild zero-days (keyless CSV export of the published sheet's "All"
   tab; skipped gracefully if its columns change).
4. **FIRST EPSS** — the daily bulk CSV of scores for every CVE (~3 MB gz):
   scores for every AI-related CVE and KEV entry, plus "patch next"
   rankings over all CVEs of the last 12 months that are not in KEV (falls
   back to `api.first.org` for the AI + KEV scores only).
5. **OSV.dev** — (a) package advisories for ~74 AI packages across PyPI, npm
   and Go, with `PYSEC-*`/`GHSA-*` duplicates merged; (b) **malicious
   packages**: `MAL-*` ids counted per ecosystem from the per-ecosystem
   `modified_id.csv` index in OSV's public GCS bucket (~11 MB, no zips).
6. **npm downloads API** + **pypistats** — adoption context only.
7. **NVD API 2.0** — severity *fallback* only, for AI CVEs whose record has
   no CVSS (CVSS v3.1 → v4.0 → v3.0; never v2), cached in `cvss.json`;
   unscored CVEs are re-checked for 90 days. NVD lags the CVE list, so it is
   never used for counts.

## Origins — where a CVE comes from

Each published CVE gets exactly one origin (`build.py` → `ORIGINS`) — what
kind of software it is, **regardless of AI** (an AI tool on PyPI is supply
chain; Copilot is a core platform). First match wins:

| id | Origin | Rule (summary) |
|---|---|---|
| `plugin` | Web CMS plugins & themes | WordPress/Joomla/Drupal plugin/theme/extension (Wordfence, Patchstack, WPScan CNAs; wordpress.org/drupal.org collection URLs; `pkg:wordpress-*`) |
| `supplychain` | Open-source projects & packages | registry packageURL/collectionURL (npm, PyPI, Maven, Go, Cargo, Composer, RubyGems, NuGet, …) or OSS CNAs (GitHub, PSF, Go, OpenJS, EEF, CPANSec) |
| `edge` | Network & security edge devices | firewalls, VPN/SSL gateways, routers, load balancers (Fortinet, Ivanti Connect Secure, Citrix ADC/Gateway, PAN-OS, Cisco ASA/FTD/IOS, SonicWall, Juniper, F5 BIG-IP, …) |
| `platform` | OS, browsers & core platforms | Microsoft, Apple, Google Android/Chrome, Linux kernel, Mozilla, mobile chipsets, VMware ESXi/vCenter |
| `other` | Enterprise & other software | everything else — mostly Oracle, Adobe, IBM, SAP, Atlassian, Apache, PHP web apps |

Sampled precision (2024–26): plugin 25/25, supply chain 25/25, edge ~93%,
platform ~93%. `plugin` is evaluated before `supplychain` so WordPress
packages stay plugins. **Caveat:** the supply-chain jump in 2026 is largely
GitHub's CNA issuing far more CVEs (~2.6k → 12k) — partly a reporting change.

**Zero-day proxy** — a KEV entry whose CVE was published ≤1 day before CISA
added it (or after) counts as *exploited at disclosure*; bucketed by CVE
publication year. It misses exploitation CISA confirms later, so recent years
fill in over time. Project Zero's tracker is shown alongside as a stricter,
smaller count of confirmed in-the-wild zero-days.

## “AI-related” — methodology (Part 2)

A CVE is AI-related when at least one **AI relation** other than `found`
applies (`build.py` → `AI_RELATIONS`, `is_ai_risk`; multi-label tags, not
exclusive buckets). `found` alone (an AI tool found a bug in curl or OpenSSL)
measures who discovers bugs, not AI attack surface: it is reported across all
CVEs (`landscape.all.relYears.found`, KEV `found` flag) and never makes a CVE
AI-related on its own.

| id | Relation | Rule (summary) |
|---|---|---|
| `agent` | MCP servers & AI agents | AI stack layer = `mcp` (below) |
| `product` | AI software & ML libraries | any other AI layer (or an AI-cloud match from a non-mainstream vendor) |
| `feature` | AI assistants in mainstream software | AI-cloud layer from Microsoft/Google/Amazon/Apple/…, or a named built-in assistant (Copilot, Gemini, Apple Intelligence, Einstein, Now Assist, GitLab Duo, …) |
| `weakness` | AI-specific weakness | CWE-1426/1427, or prompt injection, LLM/model jailbreak, system-prompt leak, model poisoning, unsafe ML-model loading, unhandled LLM output |
| `compute` | AI compute: GPU & accelerator stack | NVIDIA GPU driver/CUDA/vGPU/DGX/HGX/Container Toolkit/BlueField, AMD Instinct/ROCm, Intel Gaudi (includes consumer GPU drivers: one driver branch) |
| `found` | Found by AI tools or AI labs | the record's credits name an AI tool/model/lab (Big Sleep, XBOW, AISLE, depthfirst, ZeroPath, Claude/Anthropic, OpenAI …) or the description says an AI found it; "Claude" alone needs model/lab context (it is also a first name) |

Linux kernel records only take `found` (their commit text names unrelated
drivers). KEV and Project Zero entries take their relations from the parse
cache (`lookup_records`); only CVEs missing from the CVE list fall back to
matching CISA's text.

The AI-software matcher behind `agent`, `product` and `feature` parses each
record as full JSON and matches, case-insensitively:

- a curated **product/vendor list** of the AI stack against affected
  vendor/product/packageURL (CNA entries of the record's own vendor plus
  CISA ADP entries; downstream distro entries — Red Hat, SUSE, Debian,
  Ubuntu — are skipped, since they list "OpenShift AI" etc. as bundles for
  unrelated library bugs), and distinctive names in the English description;
- **MCP / agent** terms ("Model Context Protocol", MCP servers, AI agents);
- **AI cloud assistants** (Copilot, Azure OpenAI, Bedrock, Vertex AI, …);
- generic **AI terminology** ("machine learning", "large language model",
  "prompt injection", …).

Generic framework package names (`jax`, `torch`, `accelerate`, …) only
count in package URLs or with AI context, so "Jax Guestbook" or BlackBerry
"Torch" no longer match; Linux kernel records are never AI.
Each CVE the matcher flags gets one **stack layer** (first match in priority order):

| id | Layer |
|---|---|
| `mcp` | MCP servers & agent tools |
| `gateway` | LLM gateways & proxies |
| `inference` | Inference & model serving |
| `mlops` | MLOps & ML platforms |
| `llmapp` | LLM apps & orchestration |
| `model` | Model files & loading |
| `cloud` | AI cloud services & assistants |
| `framework` | ML frameworks & libraries |
| `other` | Other AI-related (generic terminology only) |

**Measured accuracy** — `tools/ai_labels.json` is a hand-labeled stratified
sample (290 records: flagged / AI-looking-but-unflagged / random);
`python3 tools/eval_ai.py` scores the current matcher against it, and the
result is published in `data.json` → `evaluation` and on the page. Precision
is ~99% (for the AI-software matcher; the weakness, compute and found-by-AI
rules are audited by sampling, not part of this set). Population-weighted recall is ~50% but highly uncertain (it hinges
on a single miss in the 383k-record random stratum), so treat every AI count
as a **lower bound**. Re-label and re-run when the matcher changes.

**Bulk disclosures** — single products sometimes dominate a year
(TensorFlow: 84–97% of AI CVEs in 2020–22; OpenClaw: ~16% of 2026, almost
all assigned by VulnCheck). `data.json` → `concentration` detects these
(≥10% of a year and ≥25 CVEs) and the page annotates them.

**Severity rule** (per CVE, first available): CNA CVSS v3.1 → CNA v4.0 → CNA
v3.0 → CISA-ADP v3.1 → NVD (v3.1 → v4.0 → v3.0). The source is recorded
(`sevSrc`) and shown on the page. CVSS is severity, not risk — the page pairs
it with KEV and EPSS.

## Pipeline

```
build.py     cvelistV5 (git) → data/data.json (incl. `landscape.all` / `landscape.ai`:
               the same aggregates for every CVE and for the AI-related slice),
               data/ai_meta.json   (+ data/cache.json)
sources.py   KEV, Project Zero, OSV (advisories + malicious), EPSS, npm/pypistats, NVD fallback
               → data/{kev,zerodays,malicious,epss,ai_packages,downloads,severity}.json
                 (+ data/cvss.json cache)
index.html   static page (CSP-locked) reading data/*.json via same-origin fetch
```

- First run clones the repo (~4.5 GB) and parses all ~414k records with a
  process pool (~30 s on 8 cores). Parsed rows are cached in
  `data/cache.json`, tagged with `PARSER_VERSION` — bump it in `build.py`
  when the matcher or extracted fields change, and the next run re-parses all.
- Later runs `git fetch` only the changed files and re-parse just those (~6 s).
- `CVE_CLONE_DIR` relocates the clone (CI uses the runner temp dir);
  `CVE_DATA_DIR` redirects every data file both scripts read/write (handy for
  experiments without touching `data/`).
- `sources.py` options: `SOURCES_ONLY=kev,zerodays,malicious,epss,osv,downloads,cvss` runs a
  subset; `CVSS_LIMIT=20` caps NVD requests; `NVD_API_KEY` (free) raises the
  NVD rate limit ~10×.

### Run it

```bash
python3 build.py      # incremental (full on first run; --full to force)
python3 sources.py    # KEV / EPSS / OSV / downloads + NVD fallback (~2–10 min)
python3 -m http.server 8080
open http://localhost:8080
```

Dev loop: `python3 test_build.py` and `python3 test_sources.py` (unit tests,
no network), `python3 tools/eval_ai.py` (matcher precision/recall),
`./tools/check.sh` (headless-Chrome smoke test at desktop and phone width:
data + render + no overflow; needs Chrome, set `CHROME` env if needed), and
`python3 tools/cdp_probe.py <url> "<js-expression>"` (ad-hoc DOM probe).

## Hosting (public)

The site is fully static — `index.html`, `css/`, `js/`, `vendor/uPlot.*`,
`data/*.json`. Anything static works (GitHub Pages, Cloudflare Pages,
Netlify, a reverse proxy).

**GitHub Pages + daily rebuild**: `.github/workflows/daily.yml` is wired for
it — a cron job runs the unit tests, rebuilds the data, commits `data/`, and
deploys a clean `dist/` (no clone, no caches) to Pages — every run deploys,
since a push made with `GITHUB_TOKEN` doesn't trigger another workflow. Enable
Pages with “GitHub Actions” as the source. Optionally add an `NVD_API_KEY`
repository secret ([free key](https://nvd.nist.gov/developers/request-an-api-key))
to speed up the NVD steps.

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

- **X-axis is days from epoch** on every time chart (e.g. 20727 =
  2026-10-23). uPlot's `time` scale assumes *seconds* for tick placement and
  passes raw data units to the label formatter, so the app places ticks
  itself: `dayAxis()` supplies `axes[].splits` on clean boundaries (Jan 1,
  first of month, or day, depending on span) and a matching `values`
  formatter (at most one label per year, so long spans never repeat a year).
- **Label formatter is `axes[].values`, not `ticks`.** `values:
  (self, vals) => [..labels]` receives the tick values (in data units) and
  returns one string per tick (empty string hides the label). `ticks` only
  styles the tick marks. (The app wraps this as the `tick(fn)` helper.)
- **Stacked bars are hand-made**: uPlot 1.6 has no stacking, so
  `stackedBars()` draws each series with `uPlot.paths.bars` from 0 to its
  *cumulative* height, topmost layer first, so lower layers overpaint the
  bottoms of the bars above. Legend/cursor values show raw counts; hiding a
  series in the legend re-stacks. On narrow screens, monthly bars thinner
  than ~3 px are re-bucketed to quarters, then years (`coarsenMonthly()`).
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
  legend DOM only exists after the first layout frame).
- **Headless verification**: `tools/cdp_probe.py` drives headless Chrome over
  CDP; the charts expose themselves as `document.querySelector("#chart-*")._u`
  (uPlot instance), whose `axes[n]._values` is the exact label array uPlot
  rendered. Probe with a fresh `CDP_PROFILE` — a persistent profile will
  serve stale `js/app.js` from its heuristic HTTP cache.

## Layout

```
index.html            the page (CSP meta, markup)
css/style.css         neutral light/dark theme (colour tokens), responsive layout
js/app.js             charts + tables (uPlot, defensive)
favicon.svg           site icon
vendor/uPlot.*        pinned uPlot 1.6.32 (self-hosted)
build.py              cvelistV5 → data/data.json + data/ai_meta.json (AI matcher, layers, severity)
sources.py            KEV / Project Zero / OSV / EPSS / npm / pypistats / NVD fallback → data/*.json
test_build.py         unit tests: matcher, parser, severity, aggregation
test_sources.py       unit tests: KEV, EPSS, OSV dedupe/fix, severity fallback
tools/ai_labels.json  hand-labeled sample for measuring the matcher
tools/eval_ai.py      precision/recall of the matcher against ai_labels.json
tools/check.sh        headless smoke test (data + render + overflow)
tools/sanity.py       every figure on the page recomputed from data/*.json and cross-checked (run before shipping)
tools/cdp_probe.py    headless-Chrome probe helper (dev only)
tools/check_expr.js   JS assertions used by check.sh
data/                 generated JSON (committed; caches gitignored)
.github/workflows/    daily rebuild + Pages deploy
```

## Ideas / extensions

- **"Check your stack"**: paste a `requirements.txt` / `package.json` and
  match it in the browser against OSV advisories with fixed versions (needs
  OSV affected ranges kept in `ai_packages.json`).
- **Malicious AI packages** (OSV `MAL-*` records) and malicious models — a
  large real-world AI supply-chain risk that CVEs don't cover.
- **OWASP Top 10 for LLM Apps / MITRE ATLAS** mapping of AI CVEs.
- **VulnCheck KEV** (free token) as a wider exploitation signal than CISA KEV.
- **Internet exposure** of default-unauthenticated AI servers (needs a
  Shodan/Censys key).

## Caveats

- Origins are vendor/product/package rules — sampled precision 93–100%,
  but edge and platform boundaries are judgment calls (see Origins).
- The zero-day proxy undercounts recent years (CISA confirms some
  exploitation later); malicious-package counts include mass spam waves
  (npm 2025) — the page clips and labels such outlier years.
- “AI-related” is a product/keyword heuristic — precise, but recall is
  uncertain, so counts are a lower bound (see methodology).
- Single-product bulk disclosures (TensorFlow 2020–22, OpenClaw 2026) and
  new CNAs move the curve; read trends with the page's annotations.
- CISA KEV is a lower bound of exploitation; EPSS is a model estimate.
- NVD (severity fallback) lags the CVE list by hours–days.
- npm downloads count package installs (largely CI), not users or exposure.

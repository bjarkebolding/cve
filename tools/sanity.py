#!/usr/bin/env python3
"""Sanity check: every number on the page, recomputed independently.

Two layers:
  1. data   - internal consistency of data/*.json (totals add up, subsets stay
              subsets, nested bands stay nested, dates are fresh, growth is
              plausible).
  2. page   - the rendered page (headless Chrome) is read back and each figure
              is compared with an independent recomputation from the data, and
              with the same figure elsewhere on the page.

Run before calling a change ready:  python3 tools/sanity.py [url]
Exit 1 on any FAIL; WARN lines need a human look but do not fail.
"""
import datetime as dt
import json
import os
import re
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")
sys.path.insert(0, os.path.join(BASE, "tools"))

fails, warns, oks = [], [], 0


def check(cond, msg, warn=False):
    global oks
    if cond:
        oks += 1
    elif warn:
        warns.append(msg)
    else:
        fails.append(msg)


def load(name):
    with open(os.path.join(DATA, name)) as f:
        return json.load(f)


def num(s):
    """'86,796' / '7.4%' / '×2.2' -> float (None if no number)."""
    m = re.search(r"-?\d[\d,]*\.?\d*", s or "")
    return float(m.group(0).replace(",", "")) if m else None


# ---------------------------------------------------------------- 1. data
d, kev, epss, meta = load("data.json"), load("kev.json"), load("epss.json"), load("ai_meta.json")
zd = load("zerodays.json") if os.path.exists(os.path.join(DATA, "zerodays.json")) else None
asof = d["generatedAt"][:10]
year, prev = asof[:4], str(int(asof[:4]) - 1)
md = asof[5:]
today = dt.date.today().isoformat()

check(sum(d["counts"]) == d["total"], f"data: sum(counts) {sum(d['counts'])} != total {d['total']}")
check(sum(d["aiMonths"]) == d["aiTotal"], f"data: sum(aiMonths) {sum(d['aiMonths'])} != aiTotal {d['aiTotal']}")
check(all(a <= c for a, c in zip(d["aiMonths"], d["counts"])), "data: a month has more AI-related than all CVEs")
L = d["landscape"]
check(L["all"]["total"] == d["total"], f"data: landscape.all.total {L['all']['total']} != total {d['total']}")
check(L["ai"]["total"] == d["aiTotal"], f"data: landscape.ai.total {L['ai']['total']} != aiTotal {d['aiTotal']}")
check(len(meta["ids"]) == d["aiTotal"], f"data: ai_meta has {len(meta['ids'])} ids, aiTotal {d['aiTotal']}")
only_found = [k for k, v in meta["ids"].items() if set(v.get("rels") or []) <= {"found"}]
check(not only_found, f"data: {len(only_found)} AI-related ids carry only 'found' (e.g. {only_found[:3]})")
for rel, by in L["ai"]["relYears"].items():
    allby = L["all"]["relYears"].get(rel, {})
    bad = [y for y, n in by.items() if n > allby.get(y, 0)]
    check(not bad, f"data: relYears.ai[{rel}] exceeds relYears.all in {bad}")
for o, arr in d["originMonths"].items():
    check(len(arr) == len(d["months"]), f"data: originMonths[{o}] not aligned")
check(sum(sum(a) for a in d["originMonths"].values()) == d["total"], "data: origins do not sum to total")
w = L["all"]["window"]
sw = L["all"].get("sevWindow") or {}
check(sum(sw.values()) == w["n"], f"data: sevWindow sums to {sum(sw.values())}, window n {w['n']}")
check(asof >= (dt.date.fromisoformat(today) - dt.timedelta(days=3)).isoformat(), f"data: generatedAt {asof} is stale", warn=True)
future = [m for m, c in zip(d["months"], d["counts"]) if m > today[:7] and c]
check(not future, f"data: CVEs dated in future months {future}")

# year-to-date (day precision, same rule as the page)
ytd = sum(c for day, c in zip(d["days"], d["dayCounts"]) if day.startswith(year) and day[5:] <= md)
ytd_prev = sum(c for day, c in zip(d["days"], d["dayCounts"]) if day.startswith(prev) and day[5:] <= md)
ratio = ytd / ytd_prev if ytd_prev else None
check(ratio is None or 0.3 < ratio < 6, f"data: YTD growth ×{ratio:.2f} implausible", warn=True)

ents = kev["entries"]
check(len({e["cve"] for e in ents}) == len(ents), "kev: duplicate CVE entries")
check(all(e["ai"] == bool(set(e.get("rels") or []) - {"found"}) for e in ents if e["ai"]),
      "kev: an ai-flagged entry has no AI-risk relation")
check(all(not e["ai"] for e in ents if set(e.get("rels") or []) <= {"found"} and e.get("found")),
      "kev: a found-only entry is flagged AI")
kev_cur = [e for e in ents if e["added"].startswith(year)]
kev_prev_same = [e for e in ents if e["added"].startswith(prev) and e["added"][5:] <= md]
zd_cur = [e for e in ents if e.get("zeroDay") and str(e.get("published") or "").startswith(year)]
check(len(zd_cur) <= len(kev_cur) + 50, "kev: more zero-days than KEV additions", warn=True)
check(all((e.get("daysToKev") is None) or e["daysToKev"] > -400 for e in ents), "kev: daysToKev far negative")
check(all(e["added"] <= today for e in ents), "kev: dateAdded in the future")

dist = epss.get("dist") or {}
for k in ("all", "ai"):
    x = dist.get(k)
    if x:
        check(x["ge50"] <= x["ge10"] <= x["n"], f"epss: dist.{k} bands not nested {x}")
check(dist.get("ai", {}).get("n", 0) <= dist.get("all", {}).get("n", 0), "epss: AI cohort larger than all")
kev_ids = {e["cve"] for e in ents}
top = epss.get("top") or {}
check(not [r for r in top.get("all", []) if r["cve"] in kev_ids], "epss: patch-next list contains KEV entries")
check(all(set(r.get("rels") or []) - {"found"} for r in top.get("ai", [])), "epss: AI patch-next row without an AI-risk relation")
check(all(a["epss"] >= b["epss"] for a, b in zip(top.get("all", []), top.get("all", [])[1:])), "epss: patch-next not sorted by EPSS")

if zd:
    check(zd.get("aiTotal", 0) <= zd.get("total", 0), "zerodays: AI total exceeds total")

# one window for every title ratio: the build's YTD block must match the day series
y = d.get("ytd")
check(y is not None, "data: no ytd block (titles would mix windows)")
if y:
    check(y["all"]["cur"] == ytd and y["all"]["prev"] == ytd_prev,
          f"data: ytd.all {y['all']['cur']}/{y['all']['prev']} != day series {ytd}/{ytd_prev}")
    check(sum(o["cur"] for o in y["origins"].values()) == y["all"]["cur"], "data: ytd origins do not sum to all")
    rise = y["all"]["cur"] - y["all"]["prev"]
    bulk_share = (y["all"]["bulkCur"] - y["all"]["bulkPrev"]) / rise if rise > 0 else 0

# AI vs non-AI comparison: disjoint sides that together cover every CVE in the window
scmp = d.get("severityCompare") or {}
if scmp.get("window") and scmp.get("allIs") == "non-AI":
    wa, wb = scmp["window"]
    in_win = sum(c for m, c in zip(d["months"], d["counts"]) if wa <= m <= wb)
    sides = sum(scmp["ai"].values()) + sum(scmp["all"].values())
    check(sides == in_win, f"data: severityCompare sides {sides} != CVEs in window {in_win}")
    ai_win = sum(c for m, c in zip(d["months"], d["aiMonths"]) if wa <= m <= wb)
    check(sum(scmp["ai"].values()) == ai_win, f"data: severityCompare AI side {sum(scmp['ai'].values())} != AI-related in window {ai_win}")
else:
    check(False, "data: severityCompare must compare AI with non-AI CVEs")

# independent recomputation of the headline figures the page shows
exp = {
    "cves_ytd": ytd, "cves_ratio": round(ratio, 1) if ratio else None,
    "kev_cur": len(kev_cur), "kev_prev_same": len(kev_prev_same), "zd_cur": len(zd_cur),
    "signal_base": w["n"], "signal_hc": sw.get("CRITICAL", 0) + sw.get("HIGH", 0),
    "signal_epss": dist.get("all", {}).get("ge10"),
    "signal_kev": sum(1 for e in ents if e.get("published") and w["cur"][0] <= e["published"] <= w["cur"][1]),
    "supply_kev_cur": sum(1 for e in kev_cur if e.get("origin") == "supplychain"),
    "ai_ytd": sum(c for day, c in zip(d["aiDays"], d["aiDayCounts"]) if day.startswith(year) and day[5:] <= md),
    "ai_kev_cur": sum(1 for e in kev_cur if e["ai"]),
    "found_cur": L["all"]["relYears"].get("found", {}).get(year, 0),
}

# ---------------------------------------------------------------- 2. page
url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/"
EXPR = r"""(() => {
  const t = (q) => { const e = document.querySelector(q); return e ? e.textContent : ""; };
  const tiles = (q) => [...document.querySelectorAll(q + " .kpi")].map((k) => ({ k: t.call(null, "x") || k.querySelector(".k").textContent,
    v: k.querySelector(".v").textContent, delta: (k.querySelector(".delta") || {}).textContent || "", d: (k.querySelector(".d") || {}).textContent || "" }));
  const sig = [...document.querySelectorAll("#signal-bars .sig-row")].map((r) => r.querySelector(".sig-n b").textContent);
  const threats = [...document.querySelectorAll("#threat-cards .threat")].map((c) => ({ name: c.querySelector(".th-name").textContent,
    v: (c.querySelector(".v") || {}).textContent || "", unit: (c.querySelector(".th-unit") || {}).textContent || "" }));
  return JSON.stringify({ tiles: tiles("#kpis"), aiTiles: tiles("#ai-kpis"), sig, threats,
    headline: t("#headline"), kevVendTitle: t("#h-kevvend"), cweTitle: t("#h-cweall"), issTitle: t("#h-issuance"), ransomTitle: t("#h-ransom"), ttkTitle: t("#h-ttk"), kevVendTop: t("#kevvend-bars .hb-n"), heroTitle: t("#h-hero"), aiHeadline: t("#ai-headline"), signalTitle: t("#h-signal"),
    brief: [...document.querySelectorAll("#brief-list li")].map((l) => l.textContent),
    body: document.querySelector("main").innerText.slice(0, 200000) });
})()"""
page = None
try:
    import cdp_probe as cdp
    os.environ["CDP_PROFILE"] = tempfile.mkdtemp(prefix="sanity-")
    out, exc = cdp.run(url, EXPR, wait=8)
    check(not exc, f"page: JS exceptions {exc}")
    page = json.loads(out) if out else None
except Exception as err:  # no Chrome / server: data layer still counts
    warns.append(f"page: not checked ({err})")

if page:
    T = {x["k"]: x for x in page["tiles"]}
    def tile(prefix):
        return next((x for k, x in T.items() if k.startswith(prefix)), None)
    a = tile("CVEs published")
    check(a and num(a["v"]) == exp["cves_ytd"], f"page: CVE tile {a and a['v']} != data {exp['cves_ytd']}")
    check(a and num(a["delta"]) == exp["cves_ratio"], f"page: CVE tile delta {a and a['delta']} != ×{exp['cves_ratio']}")
    check(f"{exp['cves_ytd']:,}" in page["headline"], f"page: headline does not state {exp['cves_ytd']:,}")
    if y and bulk_share >= 0.3:  # a growth headline driven by bulk filers must say so
        check("without" in page["headline"] and "without" in page["heroTitle"],
              f"page: {bulk_share:.0%} of the CVE rise is bulk filing, but the headline/hero title do not show growth without it")
    # the KEV-proxy tile must not be called "zero-days", and must cite Project Zero beside it
    check(not tile("Zero-days"), "page: KEV at-disclosure proxy labelled 'Zero-days'")
    if zd and zd.get("byYear", {}).get(year) is not None:
        zt = tile("Exploited at disclosure")
        check(zt and f"Project Zero: {zd['byYear'][year]:,}" in zt["d"], "page: at-disclosure tile lacks the Project Zero count")
    # no ×N growth multiple on a base below 10
    for t_ in page["tiles"] + page["aiTiles"]:
        mb = re.search(r"([\d,]+) by this date", t_.get("d") or "")
        if "×" in (t_.get("delta") or "") and mb:
            check(num(mb.group(1)) >= 10, f"page: tile {t_['k']!r} shows {t_['delta']} on a base of {mb.group(1)}")
    if y and y.get("ai") and y["ai"]["prev"] - y["ai"]["bulkPrev"] > 0:
        rax = round((y["ai"]["cur"] - y["ai"]["bulkCur"]) / (y["ai"]["prev"] - y["ai"]["bulkPrev"]), 1)
        check(f"×{rax}" in page["aiHeadline"], f"page: AI headline lacks growth without bulk filers ×{rax}")
    if y and y.get("rels", {}).get("agent"):
        ag = y["rels"]["agent"]
        mt = next((x for kk, x in {t_["k"]: t_ for t_ in page["aiTiles"]}.items() if kk.startswith("MCP")), None)
        check(mt and num(mt["v"]) == ag["cur"] and f"{ag['prev']:,} by this date" in mt["d"],
              f"page: MCP tile {mt and (mt['v'], mt['d'])} != one-window {ag['cur']}/{ag['prev']}")
    if y and y.get("ai"):
        sh = f"{100 * y['ai']['cur'] / y['all']['cur']:.1f}%"
        check(sh in page.get("issTitle", "") and sh in json.dumps(page["aiTiles"]), f"page: AI share {sh} not identical on tile and issuance title")
    # ransomware share over settled years (the newest two still fill in)
    st_years = [str(yy) for yy in range(2021, int(year) - 1)]
    rn = sum(1 for e in ents if e["added"][:4] in st_years)
    rr = sum(1 for e in ents if e["added"][:4] in st_years and e.get("ransomware"))
    if rn:
        check(f"About {round(100 * rr / rn)}%" in page.get("ransomTitle", ""), f"page: ransomware title {page.get('ransomTitle')!r} != {round(100 * rr / rn)}% settled share")
    W = L["all"]["window"]
    # speed: one cohort (published in the 12-month window, in KEV), same figure on card and Brief
    co = [e for e in ents if e.get("published") and W["cur"][0] <= e["published"] <= W["cur"][1] and e.get("daysToKev") is not None]
    if len(co) >= 20:
        wk = f"{round(100 * sum(1 for e in co if e['daysToKev'] <= 7) / len(co))}%"
        check(page.get("ttkTitle", "").startswith(wk), f"page: speed card {page.get('ttkTitle')!r} != cohort {wk}")
        check(any(b.startswith("Patch internet-facing") and wk in b for b in page["brief"]), f"page: Brief speed item does not use the cohort {wk}")
        # the earlier cohort must have equal follow-up (KEV additions made by the end of its window)
        pv = [e for e in ents if e.get("published") and W["prev"][0] <= e["published"] <= W["prev"][1] and e.get("daysToKev") is not None and e["added"] <= W["prev"][1]]
        if pv:
            pw = f"({round(100 * sum(1 for e in pv if e['daysToKev'] <= 7) / len(pv))}% the 12 months before, same follow-up)"
            check(pw in page.get("ttkTitle", ""), f"page: speed card prior cohort should read {pw}: {page.get('ttkTitle')!r}")
    old3 = sum(1 for e in kev_cur if (e.get("daysToKev") or 0) > 1095)
    if old3:
        check(any(b.startswith("Re-check the whole estate") and f"{old3:,} (" in b for b in page["brief"]),
              f"page: Brief old-CVE action should state {old3} CVEs over three years old")
    import datetime as _dt, statistics as _st
    dls = [(_dt.date.fromisoformat(e["due"]) - _dt.date.fromisoformat(e["added"])).days for e in kev_cur if e.get("due")]
    if len(dls) >= 20:
        med = _st.median(dls)
        mtxt = "under a day" if med < 1 else "1 day" if med == 1 else f"{int(med) if med == int(med) else med} days"
        check(any(b.startswith("Patch internet-facing") and f"median of {mtxt} to fix" in b for b in page["brief"]),
              f"page: Brief should state CISA's median deadline {mtxt}")
    # a year-on-year share change must not be called a rise unless it is statistically significant
    import math as _m
    pk = [e for e in ents if e["added"].startswith(prev)]
    a_, b_ = sum(e.get("origin") == "supplychain" for e in kev_cur), sum(e.get("origin") == "supplychain" for e in pk)
    if kev_cur and pk:
        pp = (a_ + b_) / (len(kev_cur) + len(pk)); se = _m.sqrt(pp * (1 - pp) * (1 / len(kev_cur) + 1 / len(pk))) or 1
        z = (a_ / len(kev_cur) - b_ / len(pk)) / se
        sup = next((b for b in page["brief"] if b.startswith("Control what enters")), "")
        if abs(z) < 1.96:
            check("up from" not in sup, f"page: supply-chain Brief calls a non-significant change (z={z:.2f}) a rise")
    k = tile("Exploited (")
    check(k and num(k["v"]) == exp["kev_cur"], f"page: KEV tile {k and k['v']} != data {exp['kev_cur']}")
    check(k and f"{exp['kev_prev_same']:,}" in k["d"], f"page: KEV tile comparison {k and k['d']} != {exp['kev_prev_same']}")
    z = tile("Exploited at disclosure")
    check(z and num(z["v"]) == exp["zd_cur"], f"page: zero-day tile {z and z['v']} != data {exp['zd_cur']}")
    # the same growth figure must read the same everywhere
    xs = set(re.findall(r"[×x](\d+\.\d)", page["heroTitle"]))
    sc = tile("Open-source")
    check(not sc or not xs or num(sc["delta"]) in {float(v) for v in xs},
          f"page: supply tile delta {sc and sc['delta']} vs hero title {page['heroTitle']!r}")
    sc_ = epss.get("scores") or {}
    coh = [e for e in ents if e.get("published") and w["cur"][0] <= e["published"] <= w["cur"][1] and e["cve"] in sc_]
    if len(coh) >= 20:
        caught = sum(1 for e in coh if sc_[e["cve"]]["epss"] >= 0.1)
        check(f"only {caught:,} of the {len(coh):,} confirmed-exploited" in page["body"],
              f"page: EPSS recall {caught}/{len(coh)} not stated on the signal card")
    check("likely to be exploited" not in page["body"].lower(), "page: EPSS described as 'likely to be exploited'")
    from collections import Counter
    vc = Counter((e.get("vendor") or "").strip().lower() for e in kev_cur)
    top3 = sorted(vc.items(), key=lambda t: (-t[1], t[0]))[:3]
    if top3 and exp["kev_cur"]:
        share = round(100 * sum(n for _, n in top3) / exp["kev_cur"])
        check(page.get("kevVendTitle", "").find(f"{share}%") >= 0,
              f"page: vendor card title {page.get('kevVendTitle')!r} != top-3 share {share}%")
        check(num(page.get("kevVendTop", "")) == top3[0][1], f"page: top vendor count {page.get('kevVendTop')} != {top3[0][1]}")
    # "fastest-growing" = largest rise in share of all CVEs (base >= 100), not the largest raw increase
    W = L["all"]["window"]
    rel = [(r["n"] / W["n"]) / (r["prev"] / W["prevN"]) for r in L["all"]["cweTop"] if r.get("prev", 0) >= 100]
    best = max(((rv, r["id"]) for rv, r in zip(rel, [r for r in L["all"]["cweTop"] if r.get("prev", 0) >= 100])), default=None)
    if best and best[0] > 1.05:
        check(best[1] in page.get("cweTitle", ""), f"page: fastest-growing weakness title {page.get('cweTitle')!r} should name {best[1]}")
    sig = [num(v) for v in page["sig"]]
    want = [exp["signal_base"], exp["signal_hc"], exp["signal_epss"], exp["signal_kev"]]
    check(sig == want, f"page: signal bars {sig} != data {want}")
    check(sig == sorted(sig, reverse=True), f"page: signal stages not decreasing {sig}", warn=True)
    th = {x["name"]: x for x in page["threats"]}
    s = th.get("Software supply chain")
    if s and exp["kev_cur"]:
        pct_exp = round(100 * exp["supply_kev_cur"] / exp["kev_cur"], 1)
        check(num(s["v"]) == pct_exp, f"page: supply threat {s['v']} != {pct_exp}%")
        check(f"({exp['supply_kev_cur']} of {exp['kev_cur']})" in s["unit"], f"page: supply threat unit {s['unit']!r}")
    A = {x["k"]: x for x in page["aiTiles"]}
    ai = next((x for kk, x in A.items() if kk.startswith("AI-related CVEs")), None)
    check(ai and num(ai["v"]) == exp["ai_ytd"], f"page: AI tile {ai and ai['v']} != data {exp['ai_ytd']}")
    check(ai and ai["v"] in page["aiHeadline"], f"page: AI headline does not repeat the AI tile {ai and ai['v']}")
    ak = next((x for kk, x in A.items() if kk.startswith("Exploited AI")), None)
    check(ak and num(ak["v"]) == exp["ai_kev_cur"], f"page: exploited-AI tile {ak and ak['v']} != data {exp['ai_kev_cur']}")
    app = th.get("AI application compromise")
    check(not app or not ak or num(app["v"]) <= num(ak["v"]), "page: AI-app threat count exceeds exploited-AI tile")
    fd = next((x for kk, x in A.items() if kk.startswith("Found by AI")), None)
    check(fd and num(fd["v"]) == exp["found_cur"], f"page: found-by-AI tile {fd and fd['v']} != data {exp['found_cur']}")
    body = page["body"]
    check(not re.search(r"\b(NaN|undefined|Infinity)\b|\[object", body), "page: NaN/undefined in text")
    check(not re.search(r"(?<![\d.])0\.0%|×0\.0\b", body), "page: a 0.0% / ×0.0 figure (check the denominator)", warn=True)
    neg = re.findall(r"[^\d\s]\s?-\d[\d,]* (?:CVEs|vulnerabilities)", body)
    check(not neg, f"page: negative counts {neg[:3]}")
    # "most" means a majority: a sentence that says "most" and gives its own share must give > 50%
    for sent in re.split(r"(?<=[.;])\s", body):
        if re.search(r"\b(account for|make up|is) most\b|\bmost new AI CVEs\b", sent):
            shares = [float(x) for x in re.findall(r"\((?:[\d,]+, )?(\d+(?:\.\d+)?)%\)", sent)]
            check(not shares or max(shares) > 50, f"page: 'most' with only {shares}%: {sent[:90]!r}")
    suffix = re.findall(r"\d×", body)
    check(not suffix, f"page: {len(suffix)} multiples written as 'N×' (use '×N' or 'N times')")
    years = {int(y) for y in re.findall(r"\b(20\d\d)\b", body)}
    check(max(years) <= int(year) + 1, f"page: mentions year {max(years)} beyond {year}")

print(f"sanity: {oks} ok, {len(warns)} warn, {len(fails)} fail  (data as of {asof})")
for w_ in warns:
    print("  WARN", w_)
for f_ in fails:
    print("  FAIL", f_)
sys.exit(1 if fails else 0)

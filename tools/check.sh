#!/bin/bash
# Smoke test: data files valid + page renders headlessly at desktop and phone
# width (no JS errors, every chart whose data exists draws ink, no horizontal
# overflow, no NaN/undefined text, removed panels stay removed, Part 1 / Part 2
# + method in order, headline + KPI tiles present).
# Requires Chrome (set CHROME env). Runs against the repo root.
set -u
cd "$(dirname "$0")/.."

fail=0
for f in data/data.json data/ai_meta.json data/kev.json data/severity.json; do
  if [ ! -f "$f" ]; then echo "MISSING $f"; fail=1; continue; fi
  python3 -c "import json; json.load(open('$f'))" || { echo "BAD JSON $f"; fail=1; }
done
# optional (newer pipeline) — must be valid JSON when present
for f in data/epss.json data/malicious.json data/zerodays.json; do
  if [ -f "$f" ]; then python3 -c "import json; json.load(open('$f'))" || { echo "BAD JSON $f"; fail=1; }
  else echo "  note: $f not present (EPSS panel will show 'not available')"; fi
done
python3 - <<'PY' || fail=1
import json
d = json.load(open("data/data.json"))
assert d["total"] > 300000, f"total={d['total']}"
assert d["aiTotal"] > 100, f"aiTotal={d['aiTotal']}"
assert len(d["months"]) > 300
lm = d.get("layerMonths")
if lm is not None:
    assert d.get("layers"), "layerMonths without layers"
    for k, v in lm.items():
        assert len(v) == len(d["months"]), f"layerMonths[{k}] not aligned with months"
om = d.get("originMonths")
if om is not None:
    assert d.get("origins"), "originMonths without origins"
    for k, v in om.items():
        assert len(v) == len(d["months"]), f"originMonths[{k}] not aligned with months"
new = [k for k in ("layers", "layerMonths", "cnaYears", "severityCompare", "cweCompare", "evaluation", "origins", "originMonths", "originYears", "concentration") if k in d]
print(f"  data.json ok: {d['total']} total, {d['aiTotal']} AI, {len(d['months'])} months; new keys: {', '.join(new) or 'none'}")
PY

CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
PORT="${PORT:-8999}"
# free the port, then serve until it answers
pkill -f "http.server $PORT" 2>/dev/null
python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
srv=$!
trap "kill $srv 2>/dev/null" EXIT
for _ in $(seq 1 20); do
  curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/" && break
  sleep 0.5
done

python3 - <<PY || fail=1
import sys, json, os, tempfile
sys.path.insert(0, "tools")
import cdp_probe as cdp
bad_any = False
for label, mobile in (("desktop", None), ("phone 390px", True)):
    # fresh profile per run: a persistent one serves stale js from cache
    os.environ["CDP_PROFILE"] = tempfile.mkdtemp(prefix="cdp-check-")
    out, exc = cdp.run("http://127.0.0.1:$PORT/", open("tools/check_expr.js").read(), wait=8, mobile=mobile)
    print(f"  [{label}]", out)
    print("   exceptions:", exc if exc else "none")
    if not out:
        bad_any = True
        continue
    d = json.loads(out)
    problems = []
    if exc: problems.append("exceptions")
    if d["overflow"] > 0: problems.append(f"horizontal overflow {d['overflow']}px")
    if [k for k in d["inks"] if k.endswith(":0%")]: problems.append("blank chart")
    if d["missing"]: problems.append(f"charts missing although data exists: {d['missing']}")
    if d["removed"]: problems.append(f"removed panels present: {d['removed']}")
    if len(d["headline"]) < 20: problems.append("no headline statement")
    if d["kpis"] < 2: problems.append(f"only {d['kpis']} KPI tiles")
    if d["tiers"] != 5 or not d["tierOrder"]: problems.append("section structure (summary/exploit/volume/ai/method) missing or out of order")
    if d.get("textOverflow"): problems.append(f"text spills out of its card: {d['textOverflow']}")
    if d["navLinks"] != 6: problems.append("top nav links broken")
    if d.get("slides", 0) < 20 or d.get("slideGaps"): problems.append(f"slide cards incomplete: {d.get('slideGaps')} (of {d.get('slides')})")
    if d.get("briefItems", 0) < 4: problems.append(f"executive brief has {d.get('briefItems', 0)} items")
    if d.get("navSub", 0) < 15 or d.get("navSub") != d.get("navSubAll"): problems.append("nav sub-menu links missing or broken")
    if d.get("aiKpis", 0) < 2: problems.append("Part 2 KPI tiles missing")
    if d.get("kevAllRows", 0) < 5: problems.append("latest-exploited table < 5 rows")
    if d.get("topRows", 0) < 15: problems.append("top CWE/vendor/CNA lists missing")
    if d.get("part1Ai"): problems.append("Part 1 summary mentions AI")
    if d["err"] != "no": problems.append("render error: " + d["err"])
    if d["badText"]: problems.append(f"bad text {d['badText']}")
    if d["badLinks"]: problems.append(f"{d['badLinks']} external links without target=_blank rel=noopener")
    if not d.get("defaultRange2018"): problems.append("main chart default range is not 2018+")
    if d.get("shareLabel") != "AI share of CVEs (%)" or d.get("countLabel") != "CVEs per month": problems.append("share/count mode labels")
    ticks = d.get("shareYLabel") or []
    if len(ticks) < 2 or not all("%" in t for t in ticks if t): problems.append("share-mode y ticks")
    if d.get("kevAiFlagged") is not None and d.get("kevAiRows") != d.get("kevAiFlagged"): problems.append("KEV table != AI-flagged KEV entries")
    if problems:
        print("   FAIL:", "; ".join(problems))
        bad_any = True
sys.exit(1 if bad_any else 0)
PY

if [ $fail -eq 0 ]; then echo "SMOKE PASS"; else echo "SMOKE FAIL"; fi
exit $fail

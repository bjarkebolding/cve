#!/bin/bash
# Smoke test: data files valid + page renders headlessly (no JS errors,
# charts draw, no horizontal overflow). Requires Chrome (set CHROME env).
set -u
cd "$(dirname "$0")/.."

fail=0
for f in data/data.json data/ai_meta.json data/kev.json data/ai_packages.json data/downloads.json data/nvd.json data/severity.json; do
  if [ ! -f "$f" ]; then echo "MISSING $f"; fail=1; continue; fi
  python3 -c "import json; json.load(open('$f'))" || { echo "BAD JSON $f"; fail=1; }
done
python3 - <<'EOF' || fail=1
import json
d = json.load(open("data/data.json"))
assert d["total"] > 300000, f"total={d['total']}"
assert d["aiTotal"] > 100, f"aiTotal={d['aiTotal']}"
assert len(d["months"]) > 300
print(f"  data.json ok: {d['total']} total, {d['aiTotal']} AI, {len(d['months'])} months")
EOF

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

python3 - <<EOF || fail=1
import sys, json
sys.path.insert(0, "tools")
import cdp_probe as cdp
out, exc = cdp.run("http://127.0.0.1:$PORT/", open("tools/check_expr.js").read(), wait=8)
print("  ", out)
print("  exceptions:", exc if exc else "none")
d = json.loads(out) if isinstance(out, str) else out
bad = [k for k in d["inks"] if k.endswith(":zero")]
share_ok = d.get("shareLabel") == "AI share of CVEs (%)" and d.get("countLabel") == "CVEs / month"
if exc or d["overflow"] or bad or d["rows"] < 5 or d["err"] == "yes" or not share_ok:
    sys.exit(1)
EOF

if [ $fail -eq 0 ]; then echo "SMOKE PASS"; else echo "SMOKE FAIL"; fi
exit $fail

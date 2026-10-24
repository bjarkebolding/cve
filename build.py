#!/usr/bin/env python3
"""
Build data/data.json from the official CVE list (CVEProject/cvelistV5).

Pipeline:
  1. Clone cvelistV5 (depth 1, partial/blobless, sparse on `cves/`) into
     ./vendor/cvelistV5 (override location with env CVE_CLONE_DIR).
     First run downloads ~4.5GB; later `git fetch` pulls only changed files.
  2. Parse every cves/<year>/<prefix>xxx/*.json, extracting cveMetadata
     (state, datePublished, dateReserved) plus an AI-ness flag: English
     description, affected vendor/product and packageURLs are matched
     against a list of AI/ML keywords. Parsed rows are cached in
     data/cache.json so incremental runs only re-parse git-changed files.
  3. Emit data/data.json (schema-compatible with https://cve.0xosprey.com/data.json
     plus AI series, hourly buckets and a recent-AI-CVE feed), and
     data/ai_meta.json (every AI CVE id + publish date, used by sources.py
     for the incremental NVD CVSS/CWE join).

Usage:
  python3 build.py               # build (first run: full; later: incremental)
  python3 build.py --full        # force re-parsing every file
  python3 build.py --delete-clone
"""

import argparse
import calendar
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict

REPO = "https://github.com/CVEProject/cvelistV5"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_ORG_SLICE = 6.5  # NVD anonymous rate limit: 5 req / 30s
BASE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(BASE, "vendor")
CLONE = os.environ.get("CVE_CLONE_DIR") or os.path.join(VENDOR, "cvelistV5")
DATADIR = os.path.join(BASE, "data")
CACHE = os.path.join(DATADIR, "cache.json")
LAST_HEAD = os.path.join(DATADIR, "last_head.txt")
OUT = os.path.join(DATADIR, "data.json")
ORGS = os.path.join(DATADIR, "orgs.json")  # cveId -> NVD sourceIdentifier (org email)

META_RE = re.compile(r'"cveMetadata"\s*:\s*\{')
DESC_RE = re.compile(
    r'"descriptions"\s*:\s*\[\s*\{\s*"lang"\s*:\s*"en"\s*,\s*"value"\s*:\s*"([^"]*)"',
    re.S)
SCAN_WINDOW = 32 * 1024  # cveMetadata found within 32KB for 99.9%+ of records
HOURS_KEEP = 40 * 24     # keep hourly buckets for the last N hours

# --- AI / ML detection ------------------------------------------------------
# Word-boundary, case-insensitive patterns applied to: english description +
# affected vendor/product + packageURLs (lowercased, truncated). Tuned so the
# false-positive rate stays low (e.g. no bare "ai", no bare "token").
AI_PATTERNS = [
    r"machine learning", r"deep learning", r"neural net", r"\bnlp\b",
    r"natural language", r"large language model", r"\bllms?\b",
    r"\bgpt[-\d]", r"generative ai", r"artificial intelligence",
    r"\bai model", r"\bai models", r"prompt injection", r"model poisoning",
    r"diffusion model", r"foundation model", r"computer vision",
    r"speech recognition", r"recommendation system", r"\btransformers?\b",
    r"pytorch", r"tensorflow", r"hugging ?face", r"\bonnx\b", r"openvino",
    r"scikit-learn", r"xgboost", r"lightgbm", r"\bkeras\b", r"paddlepaddle",
    r"stable diffusion", r"mlflow", r"\bvllm\b", r"\bllama\b",
    r"\bjax\b.*\bmodel\b", r"fine-tun", r"fine tun", r"embedding model",
]
AI_RE = re.compile("|".join(AI_PATTERNS), re.IGNORECASE)
# Package names that are unambiguously AI tooling (matched in packageURL /
# affected product strings), regardless of description text.
AI_PACKAGES = {
    "transformers", "torch", "pytorch", "tensorflow", "onnxruntime", "onnx",
    "keras", "jax", "jaxlib", "diffusers", "tokenizers", "huggingface_hub",
    "safetensors", "accelerate", "peft", "bitsandbytes", "openai",
    "langchain", "langchain-core", "chromadb", "sentence-transformers",
    "vllm", "llama-cpp-python", "llama-index", "mlflow", "paddlepaddle",
    "xgboost", "lightgbm", "scikit-learn", "onnxconverter-common",
    "timm", "yolov5", "ultralytics", "gradio", "stablediffusion",
    "stable-baselines3", "tensorflowjs", "onnxruntime-node", "js-tiktoken",
    "@huggingface/transformers", "@tensorflow/tfjs",
}
# Boundary-aware so e.g. "jax" does not match "AJAXSearchPro" or "JAX-WS".
AI_PKG_RES = [
    re.compile(r"(?<![a-z0-9@/])" + re.escape(p) + r"(?![a-z0-9_-])", re.I)
    for p in AI_PACKAGES
]


def is_ai_blob(blob):
    if not blob:
        return False
    if AI_RE.search(blob):
        return True
    b = blob.lower()
    return any(rx.search(b) for rx in AI_PKG_RES)


def sh(cmd, cwd=None):
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    p = subprocess.run(cmd, cwd=cwd)
    if p.returncode != 0:
        raise SystemExit(f"command failed ({p.returncode}): {' '.join(cmd)}")


def sync_repo():
    """Clone (first time) or pull (afterwards). Returns set of changed
    cves/*.json paths, or None if a full re-scan is required."""
    if os.path.exists(os.path.join(CLONE, ".git")):
        prev_head = ""
        if os.path.exists(LAST_HEAD):
            prev_head = open(LAST_HEAD).read().strip()
        sh(["git", "fetch", "--depth", "1", "origin", "main"], cwd=CLONE)
        sh(["git", "reset", "--hard", "origin/main"], cwd=CLONE)
        new_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=CLONE,
                                  capture_output=True, text=True).stdout.strip()
        changed = None
        if prev_head:
            diff = subprocess.run(
                ["git", "diff", "--name-status", prev_head, new_head, "--", "cves"],
                cwd=CLONE, capture_output=True, text=True,
            )
            if diff.returncode == 0:
                changed = set()
                for line in diff.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[0] in ("A", "M", "D"):
                        changed.add(os.path.join(CLONE, parts[1]))
        with open(LAST_HEAD, "w") as f:
            f.write(new_head)
        if changed is not None:
            print(f"pull: {len(changed)} file(s) changed", file=sys.stderr)
        else:
            print("pull: previous HEAD object unavailable -> full re-scan", file=sys.stderr)
        return changed
    os.makedirs(os.path.dirname(CLONE), exist_ok=True)
    sh(["git", "clone", "--depth", "1", "--filter=blob:none", "--no-checkout", REPO, CLONE])
    sh(["git", "-C", CLONE, "sparse-checkout", "set", "cves"])
    sh(["git", "-C", CLONE, "checkout"])
    return None  # first clone: full scan


def _cna_blob(path, head):
    """Small blob of CNA affected vendor/product + packageURLs, for AI matching."""
    try:
        m = re.search(r'"containers"\s*:\s*\{\s*"cna"\s*:', head)
        if not m:
            return ""
        seg = head[m.start():m.start() + 6000]
        parts = re.findall(r'"(?:vendor|product|packageURL)"\s*:\s*"([^"]*)"', seg)
        return " ".join(parts)
    except Exception:
        return ""


def parse_file(path):
    """Extract (cve_id, state, pubISO, resISO, is_ai) from one CVE record."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            head = f.read(SCAN_WINDOW)
            m = META_RE.search(head)
            if not m:  # older records may place metadata further in
                head += f.read()
                m = META_RE.search(head)
            if not m:
                return None
            i = m.end() - 1  # opening brace of cveMetadata
            depth = 0
            for j in range(i, len(head)):
                c = head[j]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            meta = json.loads(head[i:j + 1])
                        except json.JSONDecodeError:
                            return None
                        cid = meta.get("cveID") or meta.get("cveId") or ""
                        # AI signal: english description + cna affected/purls
                        dm = DESC_RE.search(head)
                        desc = dm.group(1)[:800] if dm else ""
                        blob = desc + " " + _cna_blob(path, head)
                        return (
                            cid,
                            (meta.get("state") or "").upper(),
                            meta.get("datePublished") or "",
                            meta.get("dateReserved") or "",
                            is_ai_blob(blob),
                        )
    except OSError:
        return None
    return None


def nvd_enrich(cve_id):
    """NVD (sourceIdentifier, severity, baseScore) for one CVE; None fields if absent."""
    url = f"{NVD_API}?cveId={urllib.parse.quote(cve_id)}&resultsPerPage=1"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cve-ai-dashboard/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read())
        v = d.get("vulnerabilities") or []
        if not v:
            return None, None, None
        cve = v[0]["cve"]
        src = cve.get("sourceIdentifier") or None
        sev, score = None, None
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = metrics.get(key)
            if not m:
                continue
            prim = next((x for x in m if x.get("type") == "Primary"), m[0])
            data = prim.get("cvssData") or {}
            sev = (data.get("baseSeverity") or "").upper() or None
            score = data.get("baseScore")
            break
        return src, sev, score
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, OSError) as err:
        print(f"NVD {cve_id}: {err}", file=sys.stderr)
        return None, None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="re-parse every file")
    ap.add_argument("--delete-clone", action="store_true")
    args = ap.parse_args()

    os.makedirs(DATADIR, exist_ok=True)

    changed = sync_repo()

    cache = {}
    if os.path.exists(CACHE) and not args.full:
        with open(CACHE, "r") as f:
            cache = json.load(f)
        if any(len(v) != 4 for v in list(cache.values())[:20]):
            print("cache format changed -> full re-parse", file=sys.stderr)
            cache = {}
            args.full = True
        else:
            print(f"cache: {len(cache)} records", file=sys.stderr)

    incremental = isinstance(changed, set)
    records = {}       # cve id -> [state, pubISO, resISO, isAi]
    to_parse = []

    if incremental and not args.full:
        records = {k: list(v) for k, v in cache.items()}
        for path in changed:
            base = os.path.basename(path)
            if base in ("delta.json", "deltaLog.json"):
                continue
            name = base[:-5]
            if not os.path.exists(path):
                records.pop(name, None)
            else:
                to_parse.append(path)
    else:
        cves_root = os.path.join(CLONE, "cves")
        for year in sorted(os.listdir(cves_root)):
            ydir = os.path.join(cves_root, year)
            if not os.path.isdir(ydir):
                continue
            for root, _dirs, files in os.walk(ydir):
                for name in files:
                    if not name.endswith(".json"):
                        continue
                    if name in cache and not args.full:
                        records[name] = cache[name]
                    else:
                        to_parse.append(os.path.join(root, name))

    print(f"parsing {len(to_parse)} file(s)...", file=sys.stderr)
    done = 0
    for path in to_parse:
        r = parse_file(path)
        done += 1
        if done % 25000 == 0:
            print(f"  {done}/{len(to_parse)}", file=sys.stderr)
        if r:
            cid, state, pub, res, ai = r
            if cid:
                records[cid] = [state, pub, res, ai]

    # --- aggregate ------------------------------------------------------------
    today = dt.datetime.now(dt.timezone.utc).date()
    hours_keep_from = today - dt.timedelta(days=HOURS_KEEP // 24)

    pub_days = defaultdict(int)
    ai_days = defaultdict(int)
    hours = defaultdict(int)
    ai_hours = defaultdict(int)
    ai_meta = {}  # cid -> published date (for NVD CVSS enrichment downstream)
    published_total = ai_total = rejected_total = 0
    recent_ai = []  # (published_iso, id, cna_org)

    for cid, (state, pub, res, ai) in records.items():
        if state == "PUBLISHED" and pub:
            day = pub[:10]
            pub_days[day] += 1
            published_total += 1
            if day >= hours_keep_from.isoformat():
                hours[pub[:13]] += 1  # "YYYY-MM-DDTHH"
            if ai:
                ai_days[day] += 1
                ai_total += 1
                ai_meta[cid] = day
                if day >= hours_keep_from.isoformat():
                    ai_hours[pub[:13]] += 1
                if pub[:10] >= (today - dt.timedelta(days=30)).isoformat():
                    recent_ai.append((pub, cid))
        elif state == "REJECTED":
            rejected_total += 1

    # recent AI CVE feed: re-read the last 30d of AI records for descriptions
    recent_ai.sort(reverse=True)
    recent_ai = recent_ai[:30]
    feed = []
    if recent_ai:
        # map id -> file path for quick re-read
        cves_root = os.path.join(CLONE, "cves")
        for pub, cid in recent_ai:
            y = pub[0:4]
            # locate file in the <prefix>xxx subdir
            cand = None
            try:
                for d in os.listdir(os.path.join(cves_root, y)):
                    cand = os.path.join(cves_root, y, d, cid + ".json")
                    if os.path.exists(cand):
                        break
            except OSError:
                pass
            desc, cna = "", ""
            if cand:
                try:
                    s = open(cand, encoding="utf-8").read()
                    dm = DESC_RE.search(s)
                    if dm:
                        desc = re.sub(r"\s+", " ", dm.group(1))[:240]
                    om = re.search(r'"assignerOrgId"\s*:\s*"([^"]*)"', s)
                    cna = om.group(1) if om else ""
                except OSError:
                    pass
            feed.append({
                "id": cid,
                "published": pub[:16].replace("T", " "),
                "description": desc,
                "cna": cna,
            })

    # resolve CNA org emails + CVSS severity via NVD (cached in data/orgs.json)
    orgs = {}
    if os.path.exists(ORGS):
        try:
            raw = json.load(open(ORGS))
            # v1 format: {cve: "email"} -> migrate to v2 (not done: refetch for CVSS)
            orgs = {k: (v if isinstance(v, dict)
                        else {"src": v, "sev": None, "score": None, "done": False})
                    for k, v in raw.items()}
        except json.JSONDecodeError:
            orgs = {}
    changed_orgs = False
    for entry in feed:
        cid = entry["id"]
        cached = orgs.get(cid)
        if cached and cached.get("done"):
            if cached.get("src"):
                entry["cna"] = cached["src"]
            if cached.get("sev"):
                entry["cvss"] = {"sev": cached["sev"], "score": cached.get("score")}
            continue
        uid = entry["cna"]
        if not uid or len(uid) < 30:  # not a UUID -> nothing to resolve
            continue
        src, sev, score = nvd_enrich(cid)
        time.sleep(NVD_ORG_SLICE)
        rec = {"src": src or (cached or {}).get("src"),
               "sev": sev or (cached or {}).get("sev"),
               "score": score or (cached or {}).get("score"),
               "done": bool(src or sev)}
        if rec["done"]:
            orgs[cid] = rec
            changed_orgs = True
        if rec["src"]:
            entry["cna"] = rec["src"]
        if rec["sev"]:
            entry["cvss"] = {"sev": rec["sev"], "score": rec["score"]}
    if changed_orgs:
        with open(ORGS, "w") as f:
            json.dump(orgs, f)

    # --- deltaLog: hourly new/updated activity, last 30 days --------------------
    delta_hour_new = defaultdict(int)
    delta_hour_upd = defaultdict(int)
    delta_path = os.path.join(CLONE, "cves", "deltaLog.json")
    if os.path.exists(delta_path):
        try:
            with open(delta_path) as f:
                dlog = json.load(f)
            cutoff = (today - dt.timedelta(days=31)).isoformat()
            for e in dlog:
                ft = e.get("fetchTime", "")[:13]
                if ft[:10] < cutoff:
                    continue
                delta_hour_new[ft] += len(e.get("new") or [])
                delta_hour_upd[ft] += len(e.get("updated") or [])
        except (json.JSONDecodeError, OSError) as err:
            print(f"deltaLog: {err}", file=sys.stderr)

    # --- months / projection -----------------------------------------------------
    month_counts = defaultdict(int)
    ai_month_counts = defaultdict(int)
    for d, c in pub_days.items():
        month_counts[d[:7]] += c
    for d, c in ai_days.items():
        ai_month_counts[d[:7]] += c
    months = sorted(month_counts)
    counts = [month_counts[m] for m in months]

    daily = {}
    last12 = set(months[-12:])
    for month in sorted(m for m in month_counts if m in last12):
        daily[month] = sorted(
            (int(d[8:]), pub_days[d]) for d in pub_days if d[:7] == month
        )

    projection = None
    if months:
        last_month = months[-1]
        y, m = int(last_month[:4]), int(last_month[5:7])
        cur_days = {d: c for d, c in pub_days.items() if d[:7] == last_month}
        last_day = max(int(d[8:]) for d in cur_days)
        so_far = sum(c for d, c in cur_days.items() if int(d[8:]) <= last_day)
        fracs = []
        for py in range(y - 12, y):
            total = sum(c for d, c in pub_days.items() if d[:4] == str(py))
            if total == 0:
                continue
            cum = sum(c for d, c in pub_days.items()
                      if d[:4] == str(py) and int(d[8:]) <= last_day)
            fracs.append(cum / total)
        if len(fracs) >= 4:
            fracs.sort()
            mid = len(fracs) // 2
            med = fracs[mid] if len(fracs) % 2 else (fracs[mid - 1] + fracs[mid]) / 2
            if med > 0.02:
                projection = {
                    "month": last_month, "day": last_day,
                    "daysInMonth": calendar.monthrange(y, m)[1],
                    "soFar": so_far, "medianFraction": round(med, 4),
                    "projected": round(so_far / med),
                    "method": "soFar / median(cumulative fraction by same day, last 12 complete months)",
                }

    payload = {
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": "CVEProject/cvelistV5 (PUBLISHED records, by datePublished day)",
        "total": published_total,
        "aiTotal": ai_total,
        "rejectedTotal": rejected_total,
        "months": months,
        "counts": counts,
        "aiMonths": [ai_month_counts.get(m, 0) for m in months],
        "days": sorted(pub_days),
        "dayCounts": [pub_days[d] for d in sorted(pub_days)],
        "aiDays": sorted(ai_days),
        "aiDayCounts": [ai_days[d] for d in sorted(ai_days)],
        "hours": dict(sorted(hours.items())),
        "aiHours": dict(sorted(ai_hours.items())),
        "deltaHourNew": dict(sorted(delta_hour_new.items())),
        "deltaHourUpdated": dict(sorted(delta_hour_upd.items())),
        "daily": daily,
        "recentAi": feed,
        "projection": projection,
    }

    with open(OUT, "w") as f:
        json.dump(payload, f)
    with open(CACHE, "w") as f:
        json.dump(records, f)
    with open(os.path.join(DATADIR, "ai_meta.json"), "w") as f:
        json.dump({"generatedAt": payload["generatedAt"], "ids": dict(sorted(ai_meta.items()))}, f)

    print(f"wrote {OUT}", file=sys.stderr)
    print(f"  {published_total} published ({ai_total} AI-related), "
          f"{rejected_total} rejected, {len(months)} months since {months[0]}",
          file=sys.stderr)

    if args.delete_clone:
        shutil.rmtree(CLONE, ignore_errors=True)
        print("deleted clone", file=sys.stderr)


if __name__ == "__main__":
    main()

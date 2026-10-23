#!/usr/bin/env python3
"""
Fetch auxiliary public sources for the AI x cybersecurity dashboard:

  data/kev.json           CISA Known Exploited Vulnerabilities (full list,
                          AI-related entries flagged) -- "exploited in the wild"
  data/ai_packages.json   Vulnerabilities in AI/ML software packages via OSV.dev
                          (PyPI + npm), with CVE aliases, severities, monthly
                          publication series
  data/downloads.json     Adoption / attack-surface proxy: npm download history
                          (daily -> monthly) for AI npm packages + pypistats
                          snapshots for PyPI AI packages

All sources are free, keyless and rate-limit friendly. Each is wrapped in its
own try/except: one failing source never blocks the others.
"""

import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
DATADIR = os.path.join(BASE, "data")
CVSS_CACHE = os.path.join(DATADIR, "cvss.json")
UA = {"User-Agent": "cve-ai-dashboard/1.0 (research script)"}

# --- AI package universe ----------------------------------------------------
PYPI_PKGS = [
    "transformers", "torch", "tensorflow", "onnxruntime", "onnx",
    "scikit-learn", "xgboost", "lightgbm", "keras", "jax",
    "huggingface_hub", "tokenizers", "diffusers", "safetensors", "openai",
    "langchain", "chromadb", "sentence-transformers", "vllm",
    "llama-cpp-python", "mlflow", "gradio", "ultralytics", "paddlepaddle",
]
NPM_PKGS = [
    "openai", "langchain", "@tensorflow/tfjs", "@huggingface/transformers",
    "onnxruntime-node", "js-tiktoken", "@google/generative-ai", "ollama", "ai",
]


def get(url, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def post(url, payload, timeout=30):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={
        **UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def write_json(name, obj):
    path = os.path.join(DATADIR, name)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)
    print(f"wrote {path} ({os.path.getsize(path)} bytes)", file=sys.stderr)


def is_ai_text(text):
    """Same heuristic as build.py for the CVE list."""
    try:
        sys.path.insert(0, BASE)
        from build import is_ai_blob
        return is_ai_blob(text or "")
    except Exception:
        return bool(re.search(r"machine learning|neural|llm|gpt|transformer",
                              (text or ""), re.I))


# --- 1. CISA KEV -------------------------------------------------------------
def fetch_kev():
    raw = json.loads(get("https://www.cisa.gov/sites/default/files/feeds/"
                        "known_exploited_vulnerabilities.json"))
    entries = []
    ai = 0
    for v in raw["vulnerabilities"]:
        text = " ".join([v.get("vendorProject", ""), v.get("product", ""),
                         v.get("vulnerabilityName", ""),
                         v.get("shortDescription", "")])
        flag = is_ai_text(text)
        ai += int(flag)
        entries.append({
            "cve": v.get("cveID", ""),
            "added": (v.get("dateAdded") or "")[:10],
            "product": f'{v.get("vendorProject", "")} {v.get("product", "")}'.strip(),
            "desc": (v.get("shortDescription") or "")[:200],
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            "ai": flag,
        })
    entries.sort(key=lambda e: e["added"], reverse=True)
    write_json("kev.json", {
        "generatedAt": now_iso(),
        "source": "CISA Known Exploited Vulnerabilities catalog",
        "total": len(entries),
        "aiCount": ai,
        "ransomwareCount": sum(1 for e in entries if e["ransomware"]),
        "entries": entries,
    })


# --- 2. OSV.dev AI package vulnerabilities -----------------------------------
def osv_query(name, ecosystem):
    return json.loads(post("https://api.osv.dev/v1/query",
                           {"package": {"name": name, "ecosystem": ecosystem}}))


def fetch_osv():
    by_month = {}
    per_package = {}
    recent = []
    for pkg, eco in [(p, "PyPI") for p in PYPI_PKGS] + [(p, "npm") for p in NPM_PKGS]:
        try:
            d = osv_query(pkg, eco)
        except (urllib.error.URLError, json.JSONDecodeError) as err:
            print(f"OSV {eco}:{pkg}: {err}", file=sys.stderr)
            continue
        vulns = d.get("vulns", [])
        n = len(vulns)
        per_package[pkg] = {"ecosystem": eco, "count": n,
                            "latest": max((v.get("published") or "")[:10]
                                          for v in vulns) if vulns else None}
        for v in vulns:
            pub = v.get("published") or v.get("modified") or ""
            if not pub:
                continue
            month = pub[:7]
            by_month[month] = by_month.get(month, 0) + 1
            sev = ""
            for s in v.get("severity") or []:
                if s.get("type", "").startswith("CVSS"):
                    sev = s.get("score", "")
                    break
            recent.append({
                "id": v.get("id", ""),
                "cve": next((a for a in v.get("aliases") or []
                             if a.startswith("CVE-")), ""),
                "package": f"{eco}:{pkg}",
                "published": (pub or "")[:10],
                "summary": re.sub(r"\s+", " ", v.get("summary") or "")[:160],
                "severity": sev,
            })
        time.sleep(0.4)
    recent.sort(key=lambda r: r["published"], reverse=True)
    write_json("ai_packages.json", {
        "generatedAt": now_iso(),
        "source": "OSV.dev (GitHub Security Advisories, PyPI, etc.)",
        "months": dict(sorted(by_month.items())),
        "perPackage": per_package,
        "recent": recent[:40],
    })


# --- 3b. NVD full-text keyword counts ----------------------------------------
def nvd_count(keyword):
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=1")
    d = json.loads(get(url))
    return d.get("totalResults", 0)


def fetch_nvd_counts():
    out = {"generatedAt": now_iso(),
           "source": "NVD API 2.0 full-text keywordSearch (derived source; lags the CVE list)"}
    for key, kw in [("machineLearning", "machine learning"),
                    ("neuralNetwork", "neural network"),
                    ("llm", "large language model")]:
        out[key] = nvd_count(kw)
        time.sleep(7)  # anonymous: 5 req / 30s
    write_json("nvd.json", out)


# --- 4. Adoption proxies (npm downloads + pypistats) --------------------------
def fetch_downloads():
    out = {"generatedAt": now_iso(), "npmMonthly": {}, "npmLastWeek": {},
           "pypi": {}}
    start = "2023-01-01"
    end = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    for pkg in NPM_PKGS:
        try:
            d = json.loads(get(f"https://api.npmjs.org/downloads/range/"
                               f"{start}:{end}/{urllib.parse.quote(pkg)}"))
            months = {}
            for row in d.get("downloads", []):
                m = row["day"][:7]
                months[m] = months.get(m, 0) + row["downloads"]
            out["npmMonthly"][pkg] = dict(sorted(months.items()))
            try:
                lw = json.loads(get(
                    f"https://api.npmjs.org/downloads/point/last-week/"
                    f"{urllib.parse.quote(pkg)}"))
                out["npmLastWeek"][pkg] = lw.get("downloads", 0)
            except (urllib.error.URLError, json.JSONDecodeError):
                pass
            time.sleep(0.3)
        except (urllib.error.URLError, json.JSONDecodeError) as err:
            print(f"npm {pkg}: {err}", file=sys.stderr)
    for pkg in PYPI_PKGS:
        try:
            d = json.loads(get(f"https://pypistats.org/api/packages/{pkg}/recent"))
            out["pypi"][pkg] = d.get("data", {})
            time.sleep(0.3)
        except (urllib.error.URLError, json.JSONDecodeError) as err:
            print(f"pypi {pkg}: {err}", file=sys.stderr)
    write_json("downloads.json", out)


# --- 5. NVD CVSS severity for the whole AI set (incremental) ----------------
def _primary_cvss(cve):
    """(severity, score, cwe_id, cwe_label) from a NVD CVE object."""
    metrics = cve.get("metrics") or {}
    sev, score = None, None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = metrics.get(key)
        if not m:
            continue
        prim = next((x for x in m if x.get("type") == "Primary"), m[0])
        data = prim.get("cvssData") or {}
        sev = (data.get("baseSeverity") or "").upper() or None
        score = data.get("baseScore")
        break
    if sev is None and score is not None:  # old V2 records often lack baseSeverity
        sev = ("CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0
               else "MEDIUM" if score >= 4.0 else "LOW")
    cwe_id, cwe_label = None, None
    for w in cve.get("weaknesses") or []:
        for wd in w.get("description") or []:
            txt = (wd.get("description") or "").strip()
            if txt.startswith("CWE-"):
                cwe_label = txt
                cwe_id = txt.split(":")[0].strip()
                break
        if cwe_id:
            break
    if cwe_id is None:
        text = " ".join((d.get("value") or "") for d in cve.get("descriptions") or [])
        m = re.search(r"\(CWE-(\d+)\)", text)
        if m:
            cwe_id = f"CWE-{m.group(1)}"
            cwe_label = cwe_id
    return sev, score, cwe_id, cwe_label


def fetch_cvss(limit=0):
    """Fetch primary CVSS for every AI CVE (NVD, 1 cveId per request, cached).

    Writes data/cvss.json (cache) and data/severity.json (chart payload).
    First run: ~2250 requests (~50 min anonymous). Later runs: incremental.
    """
    meta_path = os.path.join(DATADIR, "ai_meta.json")
    if not os.path.exists(meta_path):
        print("ai_meta.json missing (run build.py first)", file=sys.stderr)
        return
    meta = json.load(open(meta_path))["ids"]  # {cve: "YYYY-MM-DD"}
    cache = {}
    if os.path.exists(CVSS_CACHE):
        try:
            cache = json.load(open(CVSS_CACHE))
        except json.JSONDecodeError:
            cache = {}
    todo = [c for c in meta if not (cache.get(c) or {}).get("done")]
    if limit:
        todo = todo[:limit]
    # NOTE: NVD only honors the FIRST cveId of a multi-cveId query (verified
    # empirically), so we fetch one CVE per request.
    for i, cid in enumerate(todo):
        if i % 50 == 0 and i:
            tmp = CVSS_CACHE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(cache, f)
            os.replace(tmp, CVSS_CACHE)
        d = None
        for attempt in (1, 2):
            try:
                d = json.loads(get("https://services.nvd.nist.gov/rest/json/cves/2.0"
                                   f"?cveId={urllib.parse.quote(cid)}&resultsPerPage=1"))
                break
            except (urllib.error.URLError, json.JSONDecodeError, OSError) as err:
                print(f"NVD {cid}: {err} (attempt {attempt})", file=sys.stderr)
                time.sleep(30)
        if d is None:
            break  # resume next run
        found = False
        for v in d.get("vulnerabilities") or []:
            cve = v["cve"]
            if cve.get("id") != cid:
                continue
            found = True
            sev, score, cwe_id, cwe_label = _primary_cvss(cve)
            cache[cid] = {"sev": sev, "score": score, "cwe": cwe_id,
                          "cweLabel": cwe_label, "done": True}
        if not found:  # not in NVD yet -> retry next run
            cache[cid] = {"sev": None, "score": None, "cwe": None,
                          "cweLabel": None, "done": False}
        if i + 1 < len(todo):
            time.sleep(6.5)  # anonymous: 5 req / 30 s
    with open(CVSS_CACHE + ".tmp", "w") as f:
        json.dump(cache, f)
    os.replace(CVSS_CACHE + ".tmp", CVSS_CACHE)

    # aggregate -> severity.json (+ CWE counts)
    by_month = {}
    totals = {}
    cwe_counts = {}
    cwe_names = {}
    rated = 0
    for cid, day in meta.items():
        rec = cache.get(cid) or {}
        sev = rec.get("sev")
        if rec.get("cwe"):
            c = rec["cwe"]
            cwe_counts[c] = cwe_counts.get(c, 0) + 1
            if rec.get("cweLabel"):
                cwe_names[c] = rec["cweLabel"]
        if not sev:
            continue
        rated += 1
        totals[sev] = totals.get(sev, 0) + 1
        row = by_month.setdefault(day[:7], {})
        row[sev] = row.get(sev, 0) + 1
    months = []
    if by_month:
        first, last = min(by_month), max(by_month)
        y, m = int(first[:4]), int(first[5:7])
        while f"{y:04d}-{m:02d}" <= last:
            ym = f"{y:04d}-{m:02d}"
            row = by_month.get(ym, {})
            months.append({"m": ym,
                           "CRITICAL": row.get("CRITICAL", 0),
                           "HIGH": row.get("HIGH", 0),
                           "MEDIUM": row.get("MEDIUM", 0),
                           "LOW": row.get("LOW", 0)})
            m += 1
            if m > 12:
                m, y = 1, y + 1
    write_json("severity.json", {
        "generatedAt": now_iso(),
        "source": "NVD API 2.0 primary CVSS over the AI-related CVE set (cvelistV5)",
        "aiTotal": len(meta),
        "rated": rated,
        "totals": totals,
        "cwe": dict(sorted(cwe_counts.items(), key=lambda kv: -kv[1])),
        "cweNames": cwe_names,
        "months": months,
    })


def main():
    os.makedirs(DATADIR, exist_ok=True)
    tasks = [("KEV", fetch_kev), ("OSV AI packages", fetch_osv),
             ("NVD counts", fetch_nvd_counts),
             ("downloads", fetch_downloads),
             ("AI CVSS", lambda: fetch_cvss(
                 limit=int(os.environ.get("CVSS_LIMIT", 0))))]
    failed = 0
    for name, fn in tasks:
        try:
            fn()
        except Exception as err:
            failed += 1
            print(f"!! {name}: {err}", file=sys.stderr)
    raise SystemExit(1 if failed == len(tasks) else 0)


if __name__ == "__main__":
    main()

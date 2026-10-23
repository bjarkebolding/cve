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


def main():
    os.makedirs(DATADIR, exist_ok=True)
    tasks = [("KEV", fetch_kev), ("OSV AI packages", fetch_osv),
             ("NVD counts", fetch_nvd_counts),
             ("downloads", fetch_downloads)]
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

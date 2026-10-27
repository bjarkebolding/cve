#!/usr/bin/env python3
"""
Fetch auxiliary public sources for the AI x cybersecurity dashboard:

  data/kev.json           CISA Known Exploited Vulnerabilities (full list;
                          per entry origin, days-to-KEV, zero-day proxy; AI
                          entries flagged with stack layer; byYear)
  data/zerodays.json      Google Project Zero "0day In the Wild" tracker
                          (public Google Sheet CSV export), per year + recent
  data/malicious.json     Malicious open-source packages per ecosystem/year
                          (OSV MAL-* ids from the OSV GCS modified_id.csv index)
  data/epss.json          FIRST EPSS exploit-probability scores for the AI
                          CVE set + AI-flagged KEV entries
  data/ai_packages.json   OSV.dev advisories for the modern AI stack (PyPI,
                          npm, Go), deduped, with layer + fixed flag
  data/downloads.json     Adoption / attack-surface proxy: npm download history
                          (daily -> monthly) for AI npm packages + pypistats
                          snapshots for PyPI AI packages
  data/severity.json      Severity mix of the AI CVE set: record-based CVSS
                          from ai_meta.json, NVD fallback (data/cvss.json cache)

All sources are free, keyless and rate-limit friendly. Each is wrapped in its
own try/except: one failing source never blocks the others.
CVE_DATA_DIR overrides the data directory (default <repo>/data).
"""

import csv
import datetime as dt
import gzip
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
DATADIR = os.environ.get("CVE_DATA_DIR") or os.path.join(BASE, "data")


def dpath(name):
    return os.path.join(DATADIR, name)


# Human-readable names for common CWEs (NVD API often returns bare IDs).
# Fallback only: if NVD supplied a label with a name, that wins.
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-29": "Path Traversal: '\\..\\filename\\'",
    "CWE-73": "External Control of File Name or Path",
    "CWE-74": "Injection",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-119": "Improper Restriction of Operations within Memory Buffer Bounds",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-131": "Incorrect Calculation of Buffer Size",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-252": "Unchecked Return Value",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-369": "Divide By Zero",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-404": "Improper Resource Shutdown or Release",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-501": "Trust Boundary Violation",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-617": "Reachable Assertion",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
    "CWE-755": "Improper Handling of Exceptional Conditions",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-822": "Untrusted Pointer Dereference",
    "CWE-824": "Access of Uninitialized Pointer",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-915": "Improperly Controlled Modification of Object Attributes",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1321": "Prototype Pollution",
    "CWE-1333": "Inefficient Regular Expression Complexity (ReDoS)",
    "CWE-1336": "Server-Side Template Injection",
    "CWE-1426": "Improper Validation of Generative AI Output",
    "CWE-1427": "Improper Neutralization of Input Used for LLM Prompting",
}
UA = {"User-Agent": "cve-ai-dashboard/1.0 (research script)"}
# Optional free NVD API key (https://nvd.nist.gov/developers/request-an-api-key)
# raises the rate limit from 5 to 50 requests / 30 s.
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_DELAY = 0.7 if NVD_API_KEY else 6.5
# An AI CVE NVD has not scored yet is re-checked on later runs for this long.
CVSS_RECHECK_DAYS = 90
SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# --- adoption package lists (downloads.json) --------------------------------
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

# --- OSV package universe: (ecosystem, name, layer) -------------------------
# Every entry verified to have OSV coverage (2026-10-25). No coverage, dropped:
# Dify, ComfyUI, KServe, Triton, huggingface_hub, safetensors, onnxruntime,
# openai, xgboost, jax, tokenizers, AnythingLLM, LibreChat, RAGFlow.
OSV_PKGS = [
    # MCP servers & agent tools
    ("PyPI", "mcp", "mcp"),
    ("npm", "@modelcontextprotocol/sdk", "mcp"),
    ("PyPI", "fastmcp", "mcp"),
    ("PyPI", "mcp-server-git", "mcp"),
    ("npm", "@modelcontextprotocol/server-filesystem", "mcp"),
    ("npm", "@modelcontextprotocol/inspector", "mcp"),
    ("npm", "mcp-remote", "mcp"),
    ("PyPI", "agentscope", "mcp"),
    ("PyPI", "metagpt", "mcp"),
    # LLM gateways & proxies
    ("PyPI", "litellm", "gateway"),
    ("Go", "github.com/QuantumNous/new-api", "gateway"),
    ("Go", "github.com/songquanpeng/one-api", "gateway"),
    # Inference & model serving
    ("Go", "github.com/ollama/ollama", "inference"),
    ("PyPI", "vllm", "inference"),
    ("PyPI", "sglang", "inference"),
    ("Go", "github.com/mudler/LocalAI", "inference"),
    ("PyPI", "llama-cpp-python", "inference"),
    ("PyPI", "lmdeploy", "inference"),
    ("PyPI", "torchserve", "inference"),
    ("PyPI", "xinference", "inference"),
    ("PyPI", "text-generation", "inference"),
    # MLOps & ML platforms
    ("PyPI", "mlflow", "mlops"),
    ("PyPI", "ray", "mlops"),
    ("PyPI", "bentoml", "mlops"),
    ("PyPI", "clearml", "mlops"),
    ("PyPI", "label-studio", "mlops"),
    ("PyPI", "h2o", "mlops"),
    ("PyPI", "zenml", "mlops"),
    ("PyPI", "aim", "mlops"),
    ("PyPI", "mindsdb", "mlops"),
    ("Go", "github.com/kubeflow/pipelines", "mlops"),
    # LLM apps & orchestration
    ("PyPI", "langflow", "llmapp"),
    ("PyPI", "langflow-base", "llmapp"),
    ("PyPI", "open-webui", "llmapp"),
    ("npm", "open-webui", "llmapp"),
    ("npm", "flowise", "llmapp"),
    ("npm", "flowise-components", "llmapp"),
    ("PyPI", "gradio", "llmapp"),
    ("PyPI", "langchain", "llmapp"),
    ("PyPI", "langchain-core", "llmapp"),
    ("PyPI", "langchain-community", "llmapp"),
    ("PyPI", "langchain-experimental", "llmapp"),
    ("PyPI", "langgraph", "llmapp"),
    ("npm", "langchain", "llmapp"),
    ("npm", "@langchain/core", "llmapp"),
    ("PyPI", "llama-index", "llmapp"),
    ("PyPI", "llama-index-core", "llmapp"),
    ("PyPI", "haystack-ai", "llmapp"),
    ("npm", "@lobehub/chat", "llmapp"),
    ("PyPI", "chromadb", "llmapp"),
    ("PyPI", "pandasai", "llmapp"),
    ("PyPI", "vanna", "llmapp"),
    ("npm", "ai", "llmapp"),
    # Model files & loading
    ("PyPI", "picklescan", "model"),
    ("PyPI", "modelscope", "model"),
    # AI cloud services & assistants
    ("PyPI", "sagemaker", "cloud"),
    ("PyPI", "anthropic", "cloud"),
    ("npm", "@anthropic-ai/sdk", "cloud"),
    # ML frameworks & libraries
    ("PyPI", "tensorflow", "framework"),
    ("PyPI", "torch", "framework"),
    ("PyPI", "transformers", "framework"),
    ("PyPI", "keras", "framework"),
    ("PyPI", "onnx", "framework"),
    ("PyPI", "paddlepaddle", "framework"),
    ("PyPI", "scikit-learn", "framework"),
    ("PyPI", "diffusers", "framework"),
    ("PyPI", "sentence-transformers", "framework"),
    ("PyPI", "lightgbm", "framework"),
    ("PyPI", "ultralytics", "framework"),
    ("PyPI", "pytorch-lightning", "framework"),
    ("PyPI", "lightning", "framework"),
    ("PyPI", "deepspeed", "framework"),
    ("PyPI", "nemo-toolkit", "framework"),
    ("PyPI", "llamafactory", "framework"),
]


def get(url, timeout=30):
    headers = UA
    if NVD_API_KEY and url.startswith("https://services.nvd.nist.gov/"):
        headers = {**UA, "apiKey": NVD_API_KEY}
    req = urllib.request.Request(url, headers=headers)
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
    path = dpath(name)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)
    print(f"wrote {path} ({os.path.getsize(path)} bytes)", file=sys.stderr)


def read_json(name, default=None):
    try:
        with open(dpath(name)) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


# --- AI definition from build.py (imported lazily, defensively) ------------
def _build():
    try:
        if BASE not in sys.path:
            sys.path.insert(0, BASE)
        import build
        return build
    except Exception:
        return None


def is_ai_text(text):
    """Same matcher as build.py for the CVE list."""
    b = _build()
    if b is not None and hasattr(b, "is_ai_blob"):
        return bool(b.is_ai_blob(text or ""))
    return bool(re.search(r"machine learning|neural|llm|gpt|transformer",
                          (text or ""), re.I))


def layer_of_text(text):
    """build.classify_layer if available, else "other"."""
    b = _build()
    try:
        return b.classify_layer(text or "") or "other"
    except Exception:
        return "other"


def origin_of_text(text):
    """build.classify_origin if available, else "other"."""
    b = _build()
    try:
        return b.classify_origin(text or "") or "other"
    except Exception:
        return "other"


def is_ai_risk(rels):
    """build.is_ai_risk: any relation other than "found" (AI discovered the bug)."""
    return any(r != "found" for r in (rels or ()))


def relations_of_text(text, vendor=""):
    """build.ai_relations on free text (KEV/0day rows: no credits/CWE), else []."""
    b = _build()
    try:
        layer = b.ai_layer(text or "")
        return b.ai_relations(layer, text or "", text or "", "", set(), vendor=vendor)
    except Exception:
        return []


def lookup_records(cve_ids):
    """build.lookup_records over the parse cache, else {} (A not landed)."""
    b = _build()
    try:
        return b.lookup_records(list(cve_ids), DATADIR) or {}
    except Exception as err:
        print(f"build.lookup_records unavailable: {err}", file=sys.stderr)
        return {}


def norm_meta(ids):
    """ai_meta ids -> ({cve: {"d", "layer", "sev", ...}}, new_shape).

    Accepts the old {cve: "YYYY-MM-DD"} and the new {cve: {...}} shape.
    """
    out, new = {}, False
    for cid, v in (ids or {}).items():
        if isinstance(v, dict):
            new = True
            out[cid] = v
        else:
            out[cid] = {"d": v}
    return out, new


def load_meta():
    raw = read_json("ai_meta.json")
    if raw is None:
        return None, False
    return norm_meta(raw.get("ids"))


def days_between(a, b):
    """(b - a) in days for ISO days, or None."""
    try:
        return (dt.date.fromisoformat(b[:10]) - dt.date.fromisoformat(a[:10])).days
    except (TypeError, ValueError):
        return None


# --- 1. CISA KEV -------------------------------------------------------------
ZERO_DAY_MAX = 1  # KEV-added <= 1 day after CVE publication = "exploited at disclosure"
KEV_NOTES = ("added/origin: bucketed by KEV dateAdded year. zeroDay: bucketed by "
             "CVE publication year; an entry counts when its CVE publication day is "
             f"known and it was added to KEV <= {ZERO_DAY_MAX} day after publication "
             "(negative = added before publication).")


def oss_vendor(vendor):
    """True when build.OSS_VENDORS names this (KEV vendorProject) vendor."""
    try:
        return (vendor or "").strip().lower() in _build().OSS_VENDORS
    except Exception:
        return False


def kev_origin(vendor, vp, record_origin, origin_fn=origin_of_text):
    """One origin per KEV product, so the same product never lands in two
    origins: CISA's vendor/product text decides edge / platform / plugin; then a
    known open-source vendor; only then the CVE record's own origin (packageURL,
    GitHub filing), which varies with how each record was filed."""
    t = origin_fn(vp)
    if t in ("edge", "platform", "plugin"):
        return t
    if oss_vendor(vendor):
        return "supplychain"
    return record_origin or t


def kev_entries(vulns, meta, records=None, ai_match=is_ai_text,
                layer_fn=layer_of_text, origin_fn=origin_of_text, rel_fn=relations_of_text):
    """KEV catalog rows -> (entries newest first, aiCount).

    AI-related = CVE in ai_meta / with an AI-risk relation in the parse cache
    (the authoritative CVE-list tagging; "found" alone does not count, see
    build.is_ai_risk) OR build's matcher on CISA's
    vendor/product/name/description text. origin/published come from the
    parse cache (records), else KEV text / ai_meta. Origins ignore AI.
    """
    records = records or {}
    entries = []
    for v in vulns:
        cve = v.get("cveID", "")
        vp = f'{v.get("vendorProject", "")} {v.get("product", "")}'.strip()
        text = " ".join([vp, v.get("vulnerabilityName", ""),
                         v.get("shortDescription", "")])
        m = meta.get(cve)
        r = records.get(cve) or {}
        rels = list((m or {}).get("rels") or r.get("rels") or [])
        # KEV text is only consulted for CVEs the parse cache doesn't know
        flag = bool(m is not None or is_ai_risk(rels) or (not r and ai_match(text)))
        added = (v.get("dateAdded") or "")[:10]
        pub = (m or {}).get("d") or r.get("d")
        layer = None
        if flag:
            layer = (m or {}).get("layer") or r.get("layer") or layer_fn(text)
            if not is_ai_risk(rels):  # flagged by the KEV text matcher only
                rels = (rel_fn(text, v.get("vendorProject", "")) or ["product"]) + [x for x in rels if x == "found"]
        origin = kev_origin(v.get("vendorProject", ""), vp, r.get("origin"), origin_fn)
        if origin in ("mcp", "ai"):  # parse cache from before origins ignored AI
            origin = "other"
        days = days_between(pub, added) if pub else None
        entries.append({
            "cve": cve,
            "added": added,
            "product": vp,
            "desc": (v.get("shortDescription") or "")[:200],
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            "due": (v.get("dueDate") or "")[:10] or None,  # CISA BOD 22-01 remediation deadline
            "ai": flag,
            "rels": rels if flag else [],
            "found": "found" in rels,  # discovered by an AI tool (any CVE)
            "layer": layer,
            "vendor": (v.get("vendorProject") or "").strip(),
            "origin": origin,
            "published": pub,
            "daysToKev": days,
            "zeroDay": days is not None and days <= ZERO_DAY_MAX,
        })
    unify_product_origins(entries)
    entries.sort(key=lambda e: e["added"], reverse=True)
    return entries, sum(1 for e in entries if e["ai"])


def unify_product_origins(entries):
    """One origin per KEV (vendor, product): the majority of its entries, ties to
    a specific origin over "other" (record-level signals still vary by filing)."""
    groups = {}
    for e in entries:
        groups.setdefault(e["product"].strip().lower(), []).append(e)
    for es in groups.values():
        counts = {}
        for e in es:
            counts[e["origin"]] = counts.get(e["origin"], 0) + 1
        if len(counts) > 1:
            best = max(counts, key=lambda o: (counts[o], o != "other", o))
            for e in es:
                e["origin"] = best


def kev_by_year(entries):
    """{year: {"added", "ai", "ransomware", "zeroDay", "aiZeroDay", "origin": {id: n}}}
    (see KEV_NOTES)."""
    out = {}

    def row(y):
        return out.setdefault(y, {"added": 0, "ai": 0, "ransomware": 0, "zeroDay": 0,
                                  "aiZeroDay": 0, "origin": {}})

    for e in entries:
        y = e["added"][:4]
        if y:
            r = row(y)
            r["added"] += 1
            r["ai"] += 1 if e.get("ai") else 0
            r["ransomware"] += 1 if e.get("ransomware") else 0
            r["origin"][e["origin"]] = r["origin"].get(e["origin"], 0) + 1
        if e["zeroDay"] and e["published"]:
            r = row(e["published"][:4])
            r["zeroDay"] += 1
            r["aiZeroDay"] += 1 if e.get("ai") else 0
    return dict(sorted(out.items()))


def fetch_kev():
    raw = json.loads(get("https://www.cisa.gov/sites/default/files/feeds/"
                         "known_exploited_vulnerabilities.json"))
    meta, _ = load_meta()
    vulns = raw["vulnerabilities"]
    records = lookup_records(v.get("cveID", "") for v in vulns)
    entries, ai = kev_entries(vulns, meta or {}, records)
    write_json("kev.json", {
        "generatedAt": now_iso(),
        "source": "CISA Known Exploited Vulnerabilities catalog",
        "total": len(entries),
        "aiCount": ai,
        "ransomwareCount": sum(1 for e in entries if e["ransomware"]),
        "zeroDayCount": sum(1 for e in entries if e["zeroDay"]),
        "notes": KEV_NOTES,
        "byYear": kev_by_year(entries),
        "entries": entries,
    })


# --- 1b. Google Project Zero "0day In the Wild" tracker ----------------------
# Public Google Sheet, keyless CSV export of the "All" tab (gid verified
# 2026-10-25; tabs: Introduction, All, 2026 ... 2014).
PZ_SHEET = "1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY"
PZ_GID_ALL = "1190662839"
PZ_URL = f"https://docs.google.com/spreadsheets/d/{PZ_SHEET}/export?format=csv&gid={PZ_GID_ALL}"
PZ_VIEW = f"https://docs.google.com/spreadsheets/d/{PZ_SHEET}/"


def parse_zerodays(text):
    """CSV -> rows [{cve, vendor, product, type, date}] (date = Date Patched,
    "Date Discovered" is mostly "???"). Raises ValueError on a layout change."""
    rows = list(csv.DictReader(text.splitlines()))
    need = {"CVE", "Vendor", "Product", "Date Patched"}
    if not rows or not need <= set(rows[0]):
        raise ValueError(f"unexpected 0day sheet header: {list(rows[0]) if rows else []}")
    out, seen = [], set()
    for r in rows:
        cve = (r.get("CVE") or "").strip()
        day = (r.get("Date Patched") or "").strip()[:10]
        if not re.match(r"CVE-\d{4}-\d+$", cve) or cve in seen:
            continue
        seen.add(cve)
        out.append({"cve": cve, "vendor": (r.get("Vendor") or "").strip(),
                    "product": (r.get("Product") or "").strip(),
                    "type": (r.get("Type") or "").strip(),
                    "date": day if re.match(r"\d{4}-\d{2}-\d{2}$", day) else None})
    return out


def zerodays_payload(rows, records=None, kev_ids=(), origin_fn=origin_of_text,
                     rel_fn=relations_of_text, today=None):
    records = records or {}
    kev_ids = set(kev_ids)
    md = (today or now_iso())[5:10]  # "MM-DD": like-for-like year-to-date counts
    by_year, ai_year, ytd_year = {}, {}, {}
    for r in rows:
        rec = records.get(r["cve"]) or {}
        text = f'{r["vendor"]} {r["product"]}'
        r["origin"] = rec.get("origin") or origin_fn(text)
        if r["origin"] in ("mcp", "ai"):
            r["origin"] = "other"
        r["rels"] = list(rec.get("rels") or ([] if rec else rel_fn(text, r["vendor"])))
        r["ai"] = is_ai_risk(r["rels"])
        r["inKev"] = r["cve"] in kev_ids
        if r["date"]:
            by_year[r["date"][:4]] = by_year.get(r["date"][:4], 0) + 1
            if r["date"][5:10] <= md:
                ytd_year[r["date"][:4]] = ytd_year.get(r["date"][:4], 0) + 1
            if r["ai"]:
                ai_year[r["date"][:4]] = ai_year.get(r["date"][:4], 0) + 1
    recent = sorted((r for r in rows if r["date"]), key=lambda r: r["date"], reverse=True)
    return {
        "generatedAt": now_iso(),
        "source": "Google Project Zero, 0day \"In the Wild\" tracker",
        "url": PZ_VIEW,
        "method": "unique CVEs in the sheet's All tab, bucketed by Date Patched year",
        "total": len(rows),
        "byYear": dict(sorted(by_year.items())),
        "byYearToDate": dict(sorted(ytd_year.items())),  # patched by today's month-day, each year
        "aiByYear": dict(sorted(ai_year.items())),
        "aiTotal": sum(1 for r in rows if r["ai"]),
        "recent": recent[:20],
        "recentAi": [r for r in recent if r["ai"]][:20],
    }


def fetch_zerodays():
    rows = parse_zerodays(get(PZ_URL, timeout=60).decode("utf-8", "replace"))
    kev = read_json("kev.json", {}) or {}
    kev_ids = {e["cve"] for e in kev.get("entries") or []}
    write_json("zerodays.json", zerodays_payload(
        rows, lookup_records(r["cve"] for r in rows), kev_ids))


# --- 1c. Malicious open-source packages (OSV MAL-* ids) ----------------------
# Per-ecosystem index of the OSV GCS export: "<modified ISO>,<id>" per line
# (npm ~9 MB, PyPI ~1 MB, others < 0.5 MB; no all.zip download).
OSV_GCS = "https://osv-vulnerabilities.storage.googleapis.com"
MAL_ECOSYSTEMS = ["npm", "PyPI", "RubyGems", "NuGet", "crates.io", "Go",
                  "Maven", "VSCode", "Packagist"]


def count_mal(text):
    """modified_id.csv -> ({year: n}, set of ids); year = MAL-YYYY id year."""
    ids = set()
    for line in text.splitlines():
        _, _, vid = line.strip().rpartition(",")
        if re.match(r"MAL-\d{4}-\d+$", vid):
            ids.add(vid)
    years = {}
    for vid in ids:
        years[vid[4:8]] = years.get(vid[4:8], 0) + 1
    return dict(sorted(years.items())), ids


def fetch_malicious():
    by_year, totals, all_ids = {}, {}, set()
    for eco in MAL_ECOSYSTEMS:
        try:
            text = get(f"{OSV_GCS}/{urllib.parse.quote(eco)}/modified_id.csv",
                       timeout=120).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as err:
            print(f"OSV GCS {eco}: {err}", file=sys.stderr)
            continue
        years, ids = count_mal(text)
        if ids:
            by_year[eco], totals[eco] = years, len(ids)
            all_ids |= ids
    if not by_year:
        raise RuntimeError("no OSV ecosystem index fetched")
    write_json("malicious.json", {
        "generatedAt": now_iso(),
        "source": "OSV.dev malicious-package advisories (MAL-*, OpenSSF malicious-packages)",
        "method": ("unique MAL-* ids per ecosystem in the OSV GCS modified_id.csv "
                   "index, bucketed by the id's year (year the report was "
                   "catalogued, not necessarily first seen); includes withdrawn"),
        "byYear": by_year,
        "totals": totals,
        "total": len(all_ids),
    })


# --- 2. FIRST EPSS -------------------------------------------------------------
EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_CSV = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_BATCH = 100  # API page limit; ~1.5 kB URL


def parse_epss_api(d):
    """FIRST API JSON page -> ({cve: {"epss", "pct"}}, modelDate)."""
    scores, day = {}, None
    for r in d.get("data") or []:
        try:
            scores[r["cve"]] = {"epss": float(r["epss"]),
                                "pct": float(r["percentile"])}
        except (KeyError, TypeError, ValueError):
            continue
        day = max(day or "", r.get("date") or "") or None
    return scores, day


def parse_epss_csv(text, wanted):
    """Bulk CSV ("#model_version:..,score_date:..." + cve,epss,percentile);
    wanted None = every row."""
    scores, day = {}, None
    lines = text.splitlines()
    if lines and lines[0].startswith("#"):
        m = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", lines[0])
        day = m.group(1) if m else None
        lines = lines[1:]
    for r in csv.DictReader(lines):
        cve = r.get("cve")
        if wanted is None or cve in wanted:
            try:
                scores[cve] = {"epss": float(r["epss"]),
                               "pct": float(r["percentile"])}
            except (KeyError, TypeError, ValueError):
                pass
    return scores, day


def epss_wanted():
    """CVEs whose score is shown next to them: every AI-related CVE + every KEV entry."""
    meta, _ = load_meta()
    ids = set(meta or {})
    kev = read_json("kev.json", {}) or {}
    ids |= {e["cve"] for e in kev.get("entries") or []}
    return sorted(i for i in ids if i.startswith("CVE-"))


EPSS_TOP = 15
EPSS_RECENT_DAYS = 365


def epss_rank(scores, records, kev_ids, since, n=EPSS_TOP):
    """Patch-next lists from all EPSS scores: CVEs published on/after `since`
    that are NOT in KEV yet, highest EPSS first, for all and for AI-related
    CVEs; plus how many recent CVEs clear 10% / 50%.
    scores {cve: {"epss", "pct"}}, records = lookup_records() rows."""
    top = {"all": [], "ai": []}
    dist = {k: {"n": 0, "ge10": 0, "ge50": 0} for k in ("all", "ai")}
    for cve, sc in scores.items():
        r = records.get(cve)
        if not r or not r.get("d") or r["d"] < since:
            continue
        keys = ("all", "ai") if is_ai_risk(r.get("rels")) else ("all",)
        for k in keys:
            dist[k]["n"] += 1
            dist[k]["ge10"] += sc["epss"] >= 0.1
            dist[k]["ge50"] += sc["epss"] >= 0.5
            if cve not in kev_ids:
                top[k].append((sc["epss"], cve))
    out = {}
    for k, rows in top.items():
        rows.sort(key=lambda t: (-t[0], t[1]))
        out[k] = [{"cve": c, "epss": scores[c]["epss"], "pct": scores[c]["pct"],
                   "published": records[c]["d"], "product": records[c].get("product"),
                   "origin": records[c].get("origin"), "rels": records[c].get("rels") or []}
                  for _, c in rows[:n]]
    return out, dist


def fetch_epss():
    """Daily bulk CSV (~3 MB gz, every scored CVE): scores for the AI + KEV
    CVEs plus patch-next rankings over all recent CVEs. If the CSV fails,
    the API (batches of 100) scores just the AI + KEV CVEs (no rankings)."""
    ids = epss_wanted()
    wanted = set(ids)
    top, dist = None, None
    try:
        text = gzip.decompress(get(EPSS_CSV, timeout=120)).decode()
        allscores, day = parse_epss_csv(text, None)
        src = "FIRST EPSS (bulk CSV)"
        kev = read_json("kev.json", {}) or {}
        kev_ids = {e["cve"] for e in kev.get("entries") or []}
        since = (dt.date.today() - dt.timedelta(days=EPSS_RECENT_DAYS)).isoformat()
        records = lookup_records(allscores)
        if records:
            top, dist = epss_rank(allscores, records, kev_ids, since)
        scores = {c: v for c, v in allscores.items() if c in wanted}
    except (urllib.error.URLError, OSError, ValueError) as err:
        print(f"EPSS CSV: {err}; falling back to the API", file=sys.stderr)
        scores, day, src = {}, None, "FIRST EPSS"
        for i in range(0, len(ids), EPSS_BATCH):
            batch = ids[i:i + EPSS_BATCH]
            url = f"{EPSS_API}?cve={','.join(batch)}&limit={EPSS_BATCH}"
            s, d = parse_epss_api(json.loads(get(url, timeout=60)))
            scores.update(s)
            day = max(day or "", d or "") or None
            time.sleep(0.5)
    write_json("epss.json", {
        "generatedAt": now_iso(),
        "source": src,
        "modelDate": day,
        "requested": len(ids),
        "scores": dict(sorted(scores.items())),
        "recentDays": EPSS_RECENT_DAYS,
        "top": top,
        "dist": dist,
        "notes": ("top: CVEs published in the last recentDays days, not in CISA KEV, "
                  "highest EPSS first; dist: how many of those recent CVEs score "
                  ">= 10% / >= 50%"),
    })


# --- 2b. EPSS the day before KEV listing (advance-warning test) ----------------
# A KEV CVE's current EPSS already reflects the confirmed exploitation, so recall
# measured on today's scores is hindsight. This keeps each recent KEV CVE's score
# from the day before CISA listed it; past scores never change, so they are
# cached and only new KEV entries are fetched.
EPSS_PRIOR_DAYS = 2 * 365


def epss_prior_wanted(entries, cached, today=None):
    """{date: [cve]} still to fetch: KEV entries published in the last two
    years, score date = the day before dateAdded."""
    today = today or dt.date.today()
    since = (today - dt.timedelta(days=EPSS_PRIOR_DAYS)).isoformat()
    by = {}
    for e in entries:
        cve, added, pub = e.get("cve"), e.get("added"), e.get("published")
        if not cve or not added or not pub or pub < since or cve in cached:
            continue
        day = (dt.date.fromisoformat(added) - dt.timedelta(days=1)).isoformat()
        by.setdefault(day, []).append(cve)
    return by


def fetch_epss_prior():
    kev = read_json("kev.json", {}) or {}
    prior = read_json("epss_prior.json", {}) or {}
    scores = dict(prior.get("scores") or {})
    for day, cves in sorted(epss_prior_wanted(kev.get("entries") or [], scores).items()):
        for i in range(0, len(cves), EPSS_BATCH):
            batch = cves[i:i + EPSS_BATCH]
            url = f"{EPSS_API}?cve={','.join(batch)}&date={day}&limit={EPSS_BATCH}"
            got, _ = parse_epss_api(json.loads(get(url, timeout=60)))
            for c in batch:  # no score that day (CVE not yet published/scored) -> None
                scores[c] = {"date": day, "epss": got[c]["epss"] if c in got else None}
            time.sleep(0.3)
    write_json("epss_prior.json", {
        "generatedAt": now_iso(),
        "source": "FIRST EPSS API (historical, date = day before CISA KEV dateAdded)",
        "method": "epss null = no EPSS score existed that day (counts as no advance warning)",
        "scores": dict(sorted(scores.items())),
    })


# --- 3. OSV.dev AI package vulnerabilities -----------------------------------
def osv_query(name, ecosystem):
    """All OSV records for one package (follows next_page_token)."""
    vulns, token = [], None
    while True:
        q = {"package": {"name": name, "ecosystem": ecosystem}}
        if token:
            q["page_token"] = token
        d = json.loads(post("https://api.osv.dev/v1/query", q, timeout=60))
        vulns += d.get("vulns") or []
        token = d.get("next_page_token")
        if not token:
            return vulns


def dedupe_advisories(vulns):
    """Group OSV records describing the same vulnerability.

    OSV returns one record per database (e.g. PYSEC-* and GHSA-* for the same
    bug); records that share an id or alias are merged, transitively.
    Returns a list of groups (lists of records), in first-seen order.
    """
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for v in vulns:
        ids = [v.get("id", "")] + list(v.get("aliases") or [])
        for other in ids[1:]:
            parent[find(other)] = find(ids[0])
    groups = {}
    for v in vulns:
        groups.setdefault(find(v.get("id", "")), []).append(v)
    return list(groups.values())


def osv_fixed(group):
    """Any record's affected range has a "fixed" event."""
    return any("fixed" in ev
               for v in group for a in v.get("affected") or []
               for r in a.get("ranges") or [] for ev in r.get("events") or [])


def _advisory_row(group, package, layer=None):
    """One display row for a group of duplicate OSV records."""
    # earliest publication; prefer a GHSA record (it carries the summary)
    group = sorted(group, key=lambda v: v.get("published") or v.get("modified") or "")
    best = next((v for v in group if v.get("id", "").startswith("GHSA-") and v.get("summary")),
                next((v for v in group if v.get("summary")), group[0]))
    sev = ""
    for v in [best] + group:
        sev = next((s.get("score", "") for s in v.get("severity") or []
                    if s.get("type", "").startswith("CVSS")), "")
        if sev:
            break
    ids = [i for v in group for i in [v.get("id", "")] + list(v.get("aliases") or [])]
    pub = group[0].get("published") or group[0].get("modified") or ""
    return {
        "id": best.get("id", ""),
        "cve": next((a for a in ids if a.startswith("CVE-")), ""),
        "package": package,
        "layer": layer,
        "published": pub[:10],
        "summary": re.sub(r"\s+", " ", best.get("summary") or "")[:160],
        "severity": sev,
        "fixed": osv_fixed(group),
    }


def fetch_osv():
    by_month = {}
    per_package = {}
    tagged = []  # (record, "eco:pkg", layer)
    for eco, pkg, layer in OSV_PKGS:
        try:
            vulns = osv_query(pkg, eco)
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as err:
            print(f"OSV {eco}:{pkg}: {err}", file=sys.stderr)
            continue
        # npm "langchain" and PyPI "langchain" are different packages
        key = pkg if pkg not in per_package else f"{eco}:{pkg}"
        per_package[key] = {"ecosystem": eco, "layer": layer,
                            "count": len(dedupe_advisories(vulns)),
                            "latest": max((v.get("published") or "")[:10]
                                          for v in vulns) if vulns else None}
        tagged += [(v, f"{eco}:{pkg}", layer) for v in vulns]
        time.sleep(0.4)
    # dedupe across packages too: one advisory can list several of them
    tag_of = {id(v): (p, lay) for v, p, lay in tagged}
    recent = []
    for group in dedupe_advisories([v for v, _, _ in tagged]):
        pkg, layer = tag_of[id(group[0])]
        row = _advisory_row(group, pkg, layer)
        if not row["published"]:
            continue
        by_month[row["published"][:7]] = by_month.get(row["published"][:7], 0) + 1
        recent.append(row)
    recent.sort(key=lambda r: r["published"], reverse=True)
    write_json("ai_packages.json", {
        "generatedAt": now_iso(),
        "source": "OSV.dev (GitHub Security Advisories, PyPI, Go, etc.)",
        "total": len(recent),
        "months": dict(sorted(by_month.items())),
        "perPackage": per_package,
        "recent": recent[:40],
    })


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


# --- 5. Severity of the AI set: record CVSS, NVD fallback (incremental) -----
def _nvd_metric(metrics):
    """(severity, score, version) per rule 5: V31 -> V40 -> V30, never V2."""
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"),
                     ("cvssMetricV30", "3.0")):
        m = metrics.get(key)
        if not m:
            continue
        prim = next((x for x in m if x.get("type") == "Primary"), m[0])
        data = prim.get("cvssData") or {}
        sev = (data.get("baseSeverity") or "").upper() or None
        score = data.get("baseScore")
        if sev == "NONE":
            sev = None
        if sev is None and score:
            sev = ("CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0
                   else "MEDIUM" if score >= 4.0 else "LOW")
        return sev, score, ver
    return None, None, None


def _primary_cvss(cve):
    """(severity, score, cwe_id, cwe_label) from a NVD CVE object."""
    sev, score, _ = _nvd_metric(cve.get("metrics") or {})
    cwe_id, cwe_label = None, None
    for w in cve.get("weaknesses") or []:
        for wd in w.get("description") or []:
            txt = (wd.get("value") or "").strip()
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


def cvss_settled(sev, published_day, today=None):
    """Whether a fetched NVD record needs no re-check: it has a severity, or
    it is old enough that NVD analysis is not coming (records often arrive
    "Awaiting Analysis" with no metrics and get scored days later)."""
    if sev:
        return True
    today = today or dt.datetime.now(dt.timezone.utc).date()
    try:
        age = (today - dt.date.fromisoformat(published_day)).days
    except (TypeError, ValueError):
        return True
    return age > CVSS_RECHECK_DAYS


def _legacy(rec):
    """Cache entry written before rule 5 (V40-first, V2 allowed): no "v" key."""
    return "v" not in rec


def needs_nvd(cid, m, cache, new_shape, today=None):
    """Whether to (re)query NVD for this CVE.

    New ai_meta: only CVEs whose record has no severity (rule 5 fallback);
    legacy cache entries are refetched. Old ai_meta: every CVE, legacy ok.
    """
    if new_shape and m.get("sev"):
        return False
    rec = cache.get(cid) or {}
    if not rec.get("done"):
        return True
    if new_shape and _legacy(rec):
        return True
    return not cvss_settled(rec.get("sev"), m.get("d"), today)


def pick_sev(m, rec, new_shape):
    """(severity, source) for one CVE: record first, then NVD cache."""
    if m.get("sev"):
        return m["sev"], m.get("sevSrc") or "cna"
    rec = rec or {}
    if rec.get("sev") and not (new_shape and _legacy(rec)):
        return rec["sev"], "nvd"
    return None, "none"


def severity_payload(meta, cache, new_shape):
    """Aggregate -> severity.json body (+ CWE counts)."""
    by_month, totals, by_src, layer_totals = {}, {}, {}, {}
    cwe_counts, cwe_names = {}, {}
    rated = 0
    for cid, m in meta.items():
        rec = cache.get(cid) or {}
        cwe = m.get("cwe") or rec.get("cwe")
        if cwe:
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
            # prefer an NVD label that includes a name; fall back to the map
            lab = (rec.get("cweLabel") or "") if rec.get("cwe") == cwe else ""
            if lab and ": " in lab:
                cwe_names[cwe] = lab
            elif cwe in CWE_NAMES:
                cwe_names.setdefault(cwe, CWE_NAMES[cwe])
            elif lab:
                cwe_names.setdefault(cwe, lab)
        sev, src = pick_sev(m, rec, new_shape)
        if sev not in SEVS:
            sev, src = None, "none"
        by_src[src] = by_src.get(src, 0) + 1
        lt = layer_totals.setdefault(m.get("layer") or "other",
                                     {s: 0 for s in SEVS + ("UNRATED",)})
        lt[sev or "UNRATED"] += 1
        if not sev:
            continue
        rated += 1
        totals[sev] = totals.get(sev, 0) + 1
        row = by_month.setdefault((m.get("d") or "")[:7], {})
        row[sev] = row.get(sev, 0) + 1
    by_month.pop("", None)
    months = []
    if by_month:
        first, last = min(by_month), max(by_month)
        y, mo = int(first[:4]), int(first[5:7])
        while f"{y:04d}-{mo:02d}" <= last:
            ym = f"{y:04d}-{mo:02d}"
            row = by_month.get(ym, {})
            months.append({"m": ym, **{s: row.get(s, 0) for s in SEVS}})
            mo += 1
            if mo > 12:
                mo, y = 1, y + 1
    for k in ("cna", "adp", "nvd", "none"):
        by_src.setdefault(k, 0)
    return {
        "generatedAt": now_iso(),
        "source": ("CVE record CVSS (CNA, then CISA-ADP) over the AI-related "
                   "CVE set (cvelistV5); NVD API 2.0 fallback (v3.1 > v4.0 > v3.0)"),
        "aiTotal": len(meta),
        "rated": rated,
        "totals": totals,
        "bySource": by_src,
        "layerTotals": layer_totals,
        "cwe": dict(sorted(cwe_counts.items(), key=lambda kv: -kv[1])),
        "cweNames": cwe_names,
        "months": months,
    }


def _save_cache(cache):
    path = dpath("cvss.json")
    with open(path + ".tmp", "w") as f:
        json.dump(cache, f)
    os.replace(path + ".tmp", path)


def fetch_cvss(limit=0):
    """NVD fallback CVSS for AI CVEs without a record severity (1 cveId per
    request, cached in cvss.json), then write severity.json.
    """
    meta, new_shape = load_meta()
    if meta is None:
        print("ai_meta.json missing (run build.py first)", file=sys.stderr)
        return
    cache = read_json("cvss.json", {}) or {}
    todo = [c for c, m in meta.items() if needs_nvd(c, m, cache, new_shape)]
    todo.sort(key=lambda c: meta[c].get("d") or "", reverse=True)  # newest first
    print(f"NVD CVSS: {len(todo)} to fetch"
          + (f" (limit {limit})" if limit else ""), file=sys.stderr)
    if limit:
        todo = todo[:limit]
    # NOTE: NVD only honors the FIRST cveId of a multi-cveId query (verified
    # empirically), so we fetch one CVE per request.
    for i, cid in enumerate(todo):
        if i % 50 == 0 and i:
            _save_cache(cache)
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
            sev, score, ver = _nvd_metric(cve.get("metrics") or {})
            _, _, cwe_id, cwe_label = _primary_cvss(cve)
            cache[cid] = {"sev": sev, "score": score, "v": ver, "cwe": cwe_id,
                          "cweLabel": cwe_label,
                          "done": cvss_settled(sev, meta[cid].get("d"))}
        if not found:  # not in NVD yet -> retry next run
            cache[cid] = {"sev": None, "score": None, "v": None, "cwe": None,
                          "cweLabel": None, "done": False}
        if i + 1 < len(todo):
            time.sleep(NVD_DELAY)
    _save_cache(cache)
    write_json("severity.json", severity_payload(meta, cache, new_shape))


def main():
    os.makedirs(DATADIR, exist_ok=True)
    tasks = [("kev", fetch_kev),
             ("epss", fetch_epss),  # after KEV: scores AI-flagged KEV CVEs too
             ("epssprior", fetch_epss_prior),  # after KEV: EPSS the day before listing
             ("zerodays", fetch_zerodays),  # after KEV: inKev cross-ref
             ("malicious", fetch_malicious),
             ("osv", fetch_osv),
             ("downloads", fetch_downloads),
             ("cvss", lambda: fetch_cvss(
                 limit=int(os.environ.get("CVSS_LIMIT", 0))))]
    # SOURCES_ONLY=kev,epss runs a subset (local testing)
    only = {s.strip().lower() for s in os.environ.get("SOURCES_ONLY", "").split(",") if s.strip()}
    if only:
        tasks = [t for t in tasks if t[0] in only]
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

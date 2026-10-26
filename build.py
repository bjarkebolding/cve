#!/usr/bin/env python3
"""
Build data/data.json + data/ai_meta.json from the official CVE list
(CVEProject/cvelistV5). Record-based only: no NVD or other network lookups
besides the git sync.

Pipeline:
  1. Clone cvelistV5 (depth 1, partial/blobless, sparse on `cves/`) into
     ./vendor/cvelistV5 (override location with env CVE_CLONE_DIR).
     First run downloads ~4.5GB; later `git fetch` pulls only changed files.
  2. Parse every cves/<year>/<prefix>xxx/*.json into one row: cveMetadata
     (state, datePublished, dateReserved, assignerShortName), the AI layer
     (see "AI / ML detection" below; None = not AI), record severity
     (CNA CVSS 3.1 -> 4.0 -> 3.0 -> ADP 3.1), first CWE id, first affected
     product and the origin (ORIGINS: mcp, ai, supplychain, plugin, edge,
     platform, other; see origin_of). Rows are cached in <data>/cache.json (tagged PARSER_VERSION) so
     incremental runs only re-parse git-changed files.
  3. Emit <data>/data.json (schema-compatible with https://cve.0xosprey.com/data.json
     plus AI series, per-layer and per-origin months/years, per-CNA years, AI-vs-all severity and
     CWE mixes, matcher evaluation, hourly buckets and a recent-AI-CVE feed)
     and <data>/ai_meta.json (every AI CVE with day, layer, severity, CWE,
     CNA and product; read by sources.py).

<data> is ./data, or env CVE_DATA_DIR. sources.py reads per-CVE origin/layer via
lookup_records() and classifies free text with classify_origin(). tools/ai_labels.json (hand-labeled
sample, see tools/eval_ai.py) feeds the `evaluation` block when present.

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
from collections import Counter, defaultdict

REPO = "https://github.com/CVEProject/cvelistV5"
BASE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(BASE, "vendor")
CLONE = os.environ.get("CVE_CLONE_DIR") or os.path.join(VENDOR, "cvelistV5")
DATADIR = os.environ.get("CVE_DATA_DIR") or os.path.join(BASE, "data")
CACHE = os.path.join(DATADIR, "cache.json")
LAST_HEAD = os.path.join(DATADIR, "last_head.txt")
OUT = os.path.join(DATADIR, "data.json")
AI_META = os.path.join(DATADIR, "ai_meta.json")
LABELS = os.path.join(BASE, "tools", "ai_labels.json")

# Bump when parse_file()'s output changes meaning: cached rows from an older
# parser are discarded and every record is re-parsed.
PARSER_VERSION = 6
# Bump when the AI definition (layers / patterns) changes meaning.
DEFINITION_VERSION = 6
HOURS_KEEP = 40 * 24     # keep hourly buckets for the last N hours
COMPARE_MONTHS = 24      # severity/CWE comparison window (incl. current month)

# --- AI / ML detection ------------------------------------------------------
# A CVE is AI-related when the vulnerable software is AI/ML software, an AI
# service, or a component built for serving/building/using models or agents.
# Matched (lowercased) against the English description + affected_rows()
# (vendor/product/packageURL; downstream bundles and redistributors dropped).
# Each layer is a list of distinctive product names / phrases; the first
# layer that matches wins (AI_LAYERS order), then the weaker agent/MCP terms
# (-> "mcp"), then generic AI terminology (-> "other"). Generic package names
# (torch, jax, ray, ...) only count as packageURLs or after an AI vendor;
# NOT_AI_RE strips known look-alikes; Linux kernel records never match.
# No bare "ai", "agent", "model", "token", "gpt". Measure changes with
# tools/eval_ai.py and bump DEFINITION_VERSION + PARSER_VERSION.
AI_LAYERS = [
    {"id": "mcp", "label": "MCP servers & agent tools"},
    {"id": "gateway", "label": "LLM gateways & proxies"},
    {"id": "inference", "label": "Inference & model serving"},
    {"id": "mlops", "label": "MLOps & ML platforms"},
    {"id": "llmapp", "label": "LLM apps & orchestration"},
    {"id": "model", "label": "Model files & loading"},
    {"id": "cloud", "label": "AI cloud services & assistants"},
    {"id": "framework", "label": "ML frameworks & libraries"},
    {"id": "other", "label": "Other AI-related"},
]
LAYER_IDS = [x["id"] for x in AI_LAYERS]

# Package names too generic to match as words ("Jax Guestbook", BlackBerry
# "Torch", Apple "Accelerate Framework", "Ray" the person): only as a
# packageURL (pkg:pypi/torch, pkg:github/huggingface/peft) or right after an
# AI vendor ("huggingface transformers", "ray-project ray").
_GENERIC = {
    "framework": ["torch", "torchvision", "torchaudio", "jax", "jaxlib", "flax",
                  "accelerate", "peft", "timm", "transformers", "tokenizers",
                  "datasets", "evaluate", "optimum", "trl", "triton"],
    "mlops": ["ray", "aim"],
    "inference": ["text-generation-inference", "tgi"],
}
_AI_VENDORS = (r"hugging ?face|pytorch|meta-pytorch|jax-ml|google[ /-]jax|google-deepmind|"
               r"keras-team|ray-project|anyscale(?:, inc)?|openai|triton-lang|aimhubio")

LAYER_PATTERNS = {
    "mcp": [
        r"model context protocol", r"modelcontextprotocol", r"\bfastmcp\b", r"\bmcphub\b", r"\bmcp toolbox\b",
        r"\b(?:skywalking|royal|webo) mcp\b", r"\bmcp content manager\b",
        r"\bmcp[\s_-]?(?:servers?|tools?|clients?|hosts?|gateway|proxy|bridge|endpoints?|"
        r"transports?|sdk|integrations?|connectors?|plugins?|apps?|loopback|inspector|"
        r"registry|router|remote|framework|sessions?|resources?|prompts?|protocol)\b",
        r"\bmcp-[a-z]{2,}", r"[a-z]{2,}-mcp\b", r"/mcp\b",
        # coding agents / agent runtimes
        r"\bclaude[ -]code\b", r"\bcodex cli\b", r"openai[ /-]codex", r"\bgemini[ -]cli\b",
        r"\bopenclaw\b", r"\bnanoclaw\b", r"\bnemoclaw\b", r"\bopenhands\b", r"\bauto-?gpt\b",
        r"\bcrewai\b", r"\bmetagpt\b", r"\bcomposio\b", r"\bagentscope\b", r"\bsmolagents\b",
        r"microsoft[ /]autogen", r"\bautogen (?:studio|agents?)\b", r"\bpyautogen\b", r"\bag2ai\b",
        r"\broo[ -]code\b", r"\bkilo[ -]code\b", r"\bcline\b", r"\baider\b",
        r"\bwindsurf\b", r"\bcodeium\b", r"\banysphere\b", r"\bcursor (?:ide|editor|agent)\b",
        r"\bcursor cursor\b", r"\bgetcursor\b", r"\bletta(?:bot)?\b", r"\bpraisonai", r"\bomnigent\b",
        r"\bpipecat\b", r"\bopenviking\b",
    ],
    "gateway": [
        r"\blitellm\b", r"\bone-api\b", r"\bnew-api\b", r"quantumnous", r"songquanpeng",
        r"\bllm (?:gateway|proxy|router)\b", r"\bai gateway\b", r"\bportkey\b",
        r"\bopenrouter\b", r"\bkong ai\b", r"\bcopilot-api\b",
    ],
    "inference": [
        r"\bvllm\b", r"\bollama\b", r"triton[ _]inference[ _]server", r"\btritonserver\b",
        r"\blocalai\b", r"\blocal-ai\b", r"llama\.cpp", r"\bllama-cpp", r"\bllamafile\b",
        r"\bsglang\b", r"text[ -]generation[ -]inference", r"tensorrt", r"\bkserve\b",
        r"\bkoboldcpp\b", r"\bxinference\b", r"\blmdeploy\b", r"\btorchserve\b",
        r"\bexllama", r"\bmlc-llm\b", r"\bllama[ -]stack\b", r"\b(?:ai|ml) model server",
        r"\binference (?:server|endpoint|service|api)s?\b", r"\bray serve\b",
        r"\b(?:llm|ai|model) inference engine",
        r"\bnvidia nim\b", r"\bai[- ]serving\b", r"text[ -]embeddings[ -]inference", r"\blm studio\b",
    ],
    "mlops": [
        r"\bmlflow\b", r"\bkubeflow\b", r"\bclearml\b", r"\bh2oai\b", r"\bh2o-3\b",
        r"\bh2o\.ai\b", r"\bh2ogpt\b", r"label[ -]studio", r"\bbentoml\b", r"\bzenml\b",
        r"\banyscale\b", r"\bray[ -]project\b", r"\bray (?:cluster|dashboard|jobs?)\b",
        r"\bmetaflow\b", r"weights (?:&|and) biases", r"\bwandb\b", r"\bkedro\b",
        r"\bpolyaxon\b", r"\bmindsdb\b", r"\bseldon\b", r"\bdagster\b(?=.*\bml\b)",
        r"openshift ai\b", r"\bkubeai\b", r"\bdeterminedai\b", r"\bcvat\b",
        r"azure machine learning", r"\bsagemaker\b", r"\bdatarobot\b", r"\bdataiku\b",
        r"\bdomino data lab\b", r"\bmlrun\b", r"\bfeast feature store\b",
        r"\bmodel registry\b", r"\bml platform\b", r"\bml pipelines?\b", r"\blunary\b",
        r"\b(?:qnap|sap) ai core\b",
    ],
    "llmapp": [
        r"\blangflow\b", r"\bflowise", r"\bdify\b", r"open[ -]?webui", r"anything-?llm",
        r"\blibrechat\b", r"lobe-?chat", r"\blobehub\b", r"\bragflow\b", r"\bmaxkb\b",
        r"\blangchain", r"llama[-_ ]?index", r"\bcomfyui", r"comfy-?org",
        r"text-generation-webui", r"\bgradio\b", r"\bfastgpt\b", r"\bquivr\b",
        r"privategpt", r"\blangfuse\b", r"\blangsmith\b", r"\blanggraph\b",
        r"chuanhuchatgpt", r"chatgpt-next-web", r"\bnextchat\b", r"\bbig-agi\b",
        r"\bchatboxai\b", r"\bjan\.ai\b", r"\bsillytavern\b", r"\bkotaemon\b",
        r"\bdeepset-ai\b", r"\bdeepset haystack\b", r"\bhaystack-ai\b", r"semantic[ -]kernel",
        r"\bvanna\b", r"\bpandasai\b",
        r"\bchromadb\b", r"\bmilvus\b", r"\bqdrant\b", r"\bweaviate\b",
        r"\bstable[ -]diffusion", r"\bautomatic1111\b", r"\binvokeai\b",
        r"\bsd-webui\b", r"\bfooocus\b", r"\bn8n\b(?=.*\b(?:ai|llm)\b)",
        r"\bcoze\b", r"\bbisheng\b", r"\bdb-gpt\b", r"\bdeepwiki\b",
        r"\bopen-?interpreter\b", r"\bllm (?:apps?|applications?|platform|framework|chat)\b",
        r"\b(?<!\.)ai (?:chatbots?|chat|conversations?|assistants?|engine|content|writer|writing|copilot|"
        r"image|seo|platform|toolkit|providers?|router)\b",
        r"\b(?:ai|llm|gpt|chatgpt|openai)[- ]?(?:powered )?chat ?bots?\b",
        r"\brag (?:pipeline|application|engine|framework|system)s?\b",
        r"retrieval[- ]augmented generation",
    ],
    "model": [
        r"\bsafetensors\b", r"\bgguf\b", r"torch\.load", r"huggingface[_-]hub",
        r"hugging ?face hub", r"\bpicklescan\b", r"\bmodelscan\b", r"\bmodelaudit\b",
        r"\b(?:ml|ai|machine learning|pytorch|keras|onnx|pickled?|serialized|trained) models?\b",
        r"\bmodel (?:checkpoints?|weights)\b", r"\bkeras model", r"\.keras\b",
        r"\bmodel poisoning\b",
    ],
    "cloud": [
        r"azure openai", r"\bai foundry\b", r"azure ai\b",
        r"\b(?:microsoft|github|m365|office|bing|windows|edge|word|excel|outlook|teams|"
        r"security|dynamics(?: 365)?|power (?:platform|apps|automate)|365)[\s's]+copilot",
        r"\bcopilot[\s-](?:studio|chat|cli|agents?|for|plugin|extensions?|workspace)",
        r"\bcopilot copilot\b", r"\bbedrock\b(?=.*\b(?:amazon|aws|agent|llm|models?)\b)",
        r"\bamazon bedrock\b", r"\bagentcore\b", r"\bamazon q\b", r"\bq developer\b",
        r"vertex ai", r"google gemini", r"\bgemini (?:code assist|api|app|ai|enterprise|for|"
        r"nano|pro|models?|advanced)\b", r"\bchatgpt\b", r"openai(?<![a-z]openai)\b", r"\banthropic\b",
        r"\bclaude (?:ai|desktop|for|app|api)\b", r"\bwatsonx(?!\.data)", r"\bdeepseek\b",
        r"\bmistral ai\b", r"\bperplexity ai\b", r"\bnotebooklm\b", r"\bxai grok\b",
        r"\bbard\b(?=.*google)", r"\bai studio\b", r"\bbixby\b",
        r"\bwatson (?:assistant|studio|machine learning|discovery|openscale|natural language|speech|"
        r"knowledge studio|orchestrate)\b",
    ],
    "framework": [
        r"tensorflow", r"pytorch", r"paddlepaddle", r"\bpaddle(?:ocr|nlp|detection|hub|lite|"
        r"slim|serving|-?2onnx)\b", r"(?:hugging ?face|intel\S*) (?:\S+ ){0,2}transformers\b",
        r"transformers library", r"\bscikit-learn\b", r"\bsklearn\b", r"\bxgboost\b",
        r"\blightgbm\b", r"\bcatboost\b", r"\bonnx", r"\bkeras\b", r"openvino", r"\bmindspore\b",
        r"\bmxnet\b", r"\bcaffe2\b", r"\bnvcaffe\b", r"\bcaffe (?:deep learning|framework|models?)\b",
        r"\btheano\b", r"\bdiffusers\b", r"\bdeepspeed\b",
        r"\bmegatron", r"\bnvidia nemo\b", r"\bnemo (?:framework|speech|curator|agent|"
        r"guardrails|toolkit)", r"\bbionemo\b", r"\bnemo nemo\b", r"\bultralytics\b",
        r"\byolov\d", r"stable-baselines", r"\bbitsandbytes\b", r"sentence-transformers",
        r"\bnltk\b", r"\bfairseq\b", r"\bcntk\b", r"\bjoblib\b", r"\btflite\b",
        r"\btensorflow ?lite\b", r"\btfjs\b", r"\bjs-tiktoken\b", r"\btiktoken\b",
        r"\bvision[ -]language model", r"\bdeepface\b", r"\bopenai[- ]whisper\b",
        r"\bjax\b.*\bmodel\b", r"\btenstorrent\b", r"\blerobot\b",
        r"\bhugging ?face\b",
    ],
}
# weak agent terms: only when no product/layer name matched. Bare "MCP" is
# Model Context Protocol in practice (the few old acronym clashes are in
# NOT_AI_RE; kernel records are excluded in record_layer).
AGENT_PATTERNS = [
    r"\bmcp\b",
    r"\b(?<!\.)ai[- ]agents?\b", r"\bagentic\b", r"\bllm[- ]agents?\b", r"\bcoding agents?\b",
    r"\bai coding\b", r"\bmulti-agent\b", r"\bconversational agents?\b",
    r"\bagent (?:skills?|tools?)\b(?=.*\b(?:ai|llm)\b)",
    r"\btool[- ]calling\b",
]
# generic AI terminology -> "other"
OTHER_PATTERNS = [
    r"machine[ -]learning", r"deep[ -]learning", r"neural net", r"\bnlp\b",
    r"natural language processing", r"large language model", r"\bllms?\b",
    r"\bgpt-?[2-5](?:\.\d+)?(?:o|-turbo|-mini|-oss)?\b", r"\bgpt-(?:j|neo|oss)\b", r"\bgpt4all\b",
    # *gpt / gpt-* product names (docsgpt, gpt-researcher), not "GPT" partition tables
    r"\b[a-z]{2,}gpt\b", r"\bgpt-(?!partition|header|disk)[a-z]{4,}",
    r"generative ai", r"\bgenai\b", r"artificial intelligence",
    r"\b(?<!\.)ai[- ]models?\b", r"prompt injection", r"\b(?:llm|model|prompt) jailbreak",
    r"\bjailbreak prompts?\b", r"diffusion model",
    r"foundation model", r"\btransformer (?:models?|architecture)\b",
    r"embedding model", r"fine-?tun(?:e|ed|ing) (?:\S+ )?models?", r"\bml models?\b",
    # marketing words ("AI Powered Travel Booking") only as "X is an AI-powered ..."
    r"\bis an? (?:\S+ ){0,3}ai[- ](?:powered|driven|native|based|first)\b",
    r"\b(?<!\.)ai[- ](?:features?|services?|frameworks?|compute|api|sdk|inference|"
    r"workflows?|prompts?)\b",
    r"\bllama\b", r"\bneural engine\b",
    r"\bfac(?:e|ial) recognition (?:application|system|server|sdk|engine|software)",
    r"\bcomputer vision\b(?=.*\bmodel)",
]


def _generic_res():
    out = {}
    for layer, names in _GENERIC.items():
        alt = "|".join(re.escape(n) for n in names)
        end = r")(?![a-z0-9_.-])"
        out[layer] = [r"pkg:[a-z]+/(?:[^\s/]+/)?(?:" + alt + end,
                      r"\b(?:" + _AI_VENDORS + r")[\s/]+(?:" + alt + end,
                      r"\b(?:the|python|pypi) package (?:" + alt + end]
    return out


def _rx(pats):
    """One regex for lowercased text; leading \\b factored out (~5x faster)."""
    wb = [p[2:] for p in pats if p.startswith(r"\b")]
    rest = [p for p in pats if not p.startswith(r"\b")]
    return re.compile("|".join(([r"\b(?:%s)" % "|".join(wb)] if wb else []) + rest))


_GEN = _generic_res()
LAYER_RES = [(lid, _rx(LAYER_PATTERNS[lid] + _GEN.get(lid, [])))
             for lid in LAYER_IDS if lid in LAYER_PATTERNS]
AGENT_RE = _rx(AGENT_PATTERNS)
OTHER_RE = _rx(OTHER_PATTERNS)


# Names that contain an AI phrase / "MCP" but are not AI software.
NOT_AI_RE = re.compile(r"servicenow ai platform|watsonx\.data|artificial intelligence theme|"
                       r"clearpath mcp|client proxy \(mcp\)|"
                       r"ciena mcp|manage control plane? \(mcp\)|wl18xx mcp|\.mcp\b|mcp-firmware|"
                       r"\bmcp-?\d")  # last: Microchip mcp2221 / mcp23s08 chips


def ai_layer(text):
    """AI layer id of free text, or None if it is not AI-related."""
    if not text:
        return None
    text = NOT_AI_RE.sub(" ", text.lower())
    for lid, rx in LAYER_RES:
        if rx.search(text):
            return lid
    if AGENT_RE.search(text):
        return "mcp"
    if OTHER_RE.search(text):
        return "other"
    return None


def is_ai_blob(text):
    return ai_layer(text) is not None


def classify_layer(text):
    """Layer id for text already known to be AI-related ("other" fallback)."""
    return ai_layer(text) or "other"


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


def en_description(cna):
    """First English description of a CNA container ("en", "en-US", ...)."""
    for d in cna.get("descriptions") or []:
        if (d.get("lang") or "").lower().startswith("en") and d.get("value"):
            return d["value"]
    return ""


# Redistributors list every product that bundles a library (Red Hat "OpenShift
# AI" / "AI Inference Server" for a sudo or pyjwt bug): never match on them.
REDISTRIBUTOR_RE = re.compile(r"^\s*(?:red ?hat|suse|opensuse|debian|canonical|ubuntu|fedora)\b", re.I)


def _str(x):
    return x if isinstance(x, str) else ""


def product_adps(containers):
    """ADP containers that may name the vulnerable product. Supplier ADPs
    ("siemens-SADP", "redhat-SADP") list every downstream product that bundles
    the library (Siemens "AI Lightweight Inference Server" for an OpenSSL bug),
    so they are never used for product, vendor, origin or AI matching."""
    out = []
    for c in containers.get("adp") or []:
        if not isinstance(c, dict):
            continue
        short = _str((c.get("providerMetadata") or {}).get("shortName")).strip().lower()
        if short.endswith("-sadp"):
            continue
        out.append(c)
    return out


def affected_rows(containers):
    """(vendor, product, packageURL) rows used for AI matching: the CNA entries
    that share the first entry's vendor (later vendors are usually downstream
    bundles) plus the ADP entries (CISA's ADP adds the normalized CPE product,
    e.g. "gradio"); redistributor vendors are skipped."""
    rows = []
    cna = containers.get("cna") or {}
    first = None
    for a in (cna.get("affected") or []) if isinstance(cna, dict) else []:
        if not isinstance(a, dict):
            continue
        v = _str(a.get("vendor")).strip().lower()
        if first is None:
            first = v
        if v == first:
            rows.append((_str(a.get("vendor")), _str(a.get("product")), _str(a.get("packageURL"))))
    for c in product_adps(containers):
        for a in c.get("affected") or []:
            if isinstance(a, dict):
                rows.append((_str(a.get("vendor")), _str(a.get("product")), _str(a.get("packageURL"))))
    return [r for r in rows if not REDISTRIBUTOR_RE.match(r[0])]


def _affected_blob(containers):
    """affected_rows() as one matchable string."""
    return " ".join(" ".join(r) for r in affected_rows(containers))[:6000]


def load_record(path):
    """Parsed CVE JSON record, or None if unreadable."""
    try:
        with open(path, "rb") as f:
            rec = json.loads(f.read())
    except (OSError, ValueError):
        return None
    return rec if isinstance(rec, dict) else None


KERNEL_PREFIX = "in the linux kernel, the following vulnerability has been resolved"


def record_layer(containers):
    """AI layer of a record (description + affected rows), or None. Linux
    kernel records are never AI: their commit-message descriptions mention
    LLM-found bugs and driver names like "mcp-2221"."""
    cna = containers.get("cna") or {}
    desc = en_description(cna)[:800]
    if desc.lower().startswith(KERNEL_PREFIX):
        return None
    return ai_layer(desc + " " + _affected_blob(containers))


# --- severity / CWE / product -------------------------------------------------
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
# (container, metrics key, version) in priority order -- one CVSS family, v2 never
SEV_RULES = (("cna", "cvssV3_1", "3.1"), ("cna", "cvssV4_0", "4.0"),
             ("cna", "cvssV3_0", "3.0"), ("adp", "cvssV3_1", "3.1"))
CWE_RE = re.compile(r"^\s*(CWE-\d+)\b", re.I)


def sev_from_score(score):
    """CVSS v3 qualitative band (9.0/7.0/4.0/0.1); None for 0 / no score."""
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        return None
    for floor, sev in ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW")):
        if score >= floor:
            return sev
    return None


def record_severity(containers):
    """(sev, score, cvssVersion, source) from the record's own metrics, first
    of CNA 3.1 / CNA 4.0 / CNA 3.0 / ADP 3.1; all None if none present."""
    groups = {"cna": [containers.get("cna") or {}], "adp": list(containers.get("adp") or [])}
    for src, key, ver in SEV_RULES:
        for c in groups[src]:
            for m in (c.get("metrics") or []) if isinstance(c, dict) else []:
                d = m.get(key) if isinstance(m, dict) else None
                if not isinstance(d, dict):
                    continue
                score = d.get("baseScore")
                score = score if isinstance(score, (int, float)) and not isinstance(score, bool) else None
                sev = (d.get("baseSeverity") or "").upper() if isinstance(d.get("baseSeverity"), str) else ""
                if sev not in SEVERITIES:
                    sev = None if sev == "NONE" else sev_from_score(score)
                if sev is None and score is None and not d.get("baseSeverity"):
                    continue  # empty metric block
                return sev, score, ver, src
    return None, None, None, None


def record_cwe(cna):
    """First CWE id ("CWE-79") in the CNA problemTypes: cweId, else a
    "CWE-n ..." description prefix; None if none."""
    for pt in cna.get("problemTypes") or []:
        for d in (pt.get("descriptions") or []) if isinstance(pt, dict) else []:
            if not isinstance(d, dict):
                continue
            for v in (d.get("cweId"), d.get("description")):
                m = CWE_RE.match(v) if isinstance(v, str) else None
                if m:
                    return m.group(1).upper()
    return None


_NA = ("", "n/a", "na", "unknown", "unspecified", "-")


def record_product(containers):
    """First affected "vendor product" (CNA, then ADP), <= 80 chars, or None."""
    for c in [containers.get("cna") or {}] + product_adps(containers):
        for a in (c.get("affected") or []) if isinstance(c, dict) else []:
            if not isinstance(a, dict):
                continue
            v, p = _str(a.get("vendor")).strip(), _str(a.get("product")).strip()
            if p.lower() in _NA:
                continue
            if v.lower() in _NA or p.lower().startswith(v.lower()):
                return p[:80]
            return f"{v} {p}"[:80]
    return None


def record_vendor(containers):
    """First affected vendor (CNA, then ADP), <= 60 chars, or None."""
    for c in [containers.get("cna") or {}] + product_adps(containers):
        for a in (c.get("affected") or []) if isinstance(c, dict) else []:
            v = _str(a.get("vendor")).strip() if isinstance(a, dict) else ""
            if v and v.lower() not in _NA and not REDISTRIBUTOR_RE.match(v):
                return v[:60]
    return None


# --- AI relations: how a CVE relates to AI (multi-label, any number) ----------
# "AI-related" = at least one relation. product/agent/feature come from the
# AI layer matcher above; the others are separate signals that also reach
# CVEs in non-AI software (a GPU driver, a bug an AI tool found).
AI_RELATIONS = [
    {"id": "agent", "label": "MCP servers & AI agents"},
    {"id": "product", "label": "AI software & ML libraries"},
    {"id": "feature", "label": "AI assistants in mainstream software"},
    {"id": "weakness", "label": "AI-specific weakness"},
    {"id": "compute", "label": "AI compute: GPU & accelerator stack"},
    {"id": "found", "label": "Found by AI tools or AI labs"},
]
RELATION_IDS = [x["id"] for x in AI_RELATIONS]


def is_ai_risk(rels):
    """AI-related = an AI system is part of the attack surface (agent, product,
    feature, weakness, compute). "found" alone (an AI tool discovered a bug in
    curl) measures who finds bugs, not AI risk: it is tracked across all CVEs
    (landscape.all.relYears.found) but does not make a CVE AI-related."""
    return any(r != "found" for r in (rels or ()))

# Copilot, Gemini & co. built into mainstream products (cloud layer included)
FEATURE_RE = re.compile(
    r"\b(?:microsoft|m365|office|word|excel|outlook|teams|windows|edge|bing|github|"
    r"dynamics(?: 365)?|power (?:platform|apps|automate)|365)[\s's]+copilot\b|"
    r"\bcopilot\b(?=.*\b(?:microsoft|github|windows|office|m365)\b)|"
    r"\bgemini\b(?=.*\b(?:google|chrome|workspace|android|gmail)\b)|\bapple intelligence\b|"
    r"\beinstein (?:gpt|copilot|bots?|ai)\b|\bnow assist\b|\bjoule\b(?=.*\bsap\b)|\bamazon q\b|"
    r"\bduet ai\b|\batlassian intelligence\b|\brovo\b(?=.*atlassian)|\bzoom ai companion\b|"
    r"\bgitlab duo\b|\bjetbrains ai\b|\bjupyter[- ]ai\b|\bslack ai\b|\bnotion ai\b|"
    r"\bgrafana (?:llm|assistant)\b|\bai (?:assistant|chatbot|sidebar) (?:in|of|for) (?:firefox|chrome|edge|safari)\b")
# a cloud-layer match (ChatGPT, Gemini, Copilot ...) is an AI feature only when a
# mainstream vendor ships it; "chatgpt-on-wechat" is AI software
MAINSTREAM_RE = re.compile(
    r"^\s*(?:microsoft|github|google|amazon|aws|apple|ibm|samsung|salesforce|sap\b|oracle|"
    r"atlassian|adobe|zoom|slack|meta\b|servicenow|cisco|mozilla|gitlab|jetbrains|notion|grafana)")
# weakness classes that only exist because of a model in the loop
AI_CWES = {"CWE-1426", "CWE-1427"}  # generative-AI output / LLM prompt neutralization
WEAKNESS_RE = re.compile(
    r"prompt[- ]injection|\b(?:llm|model|ai|prompt) jailbreak|\bjailbreak (?:prompts?|the (?:llm|model))|"
    r"\b(?:llm|model|agent|assistant|chatbot)(?:'s)? system prompts?\b|"
    r"\bsystem prompts?(?: (?:leak|extraction|disclosure|override))|\bmodel poisoning\b|"
    r"\btraining[- ]data (?:poisoning|extraction|leak)|"
    r"\b(?:llm|model|ai)[- ]generated (?:output|content|code|responses?)\b|"
    r"\b(?:untrusted|malicious|crafted) (?:ml|ai|machine learning|pytorch|keras|onnx|hugging ?face|"
    r"pickled?) models?\b|\b(?:ml|ai|pytorch|keras|onnx|tensorflow) model (?:loading|deserialization)\b|"
    r"torch\.load|\bhallucinat|excessive agency|insecure output handling|"
    r"\b(?:llm|language model|ai model|model)'s output\b|\bllm output\b")
# the GPU/accelerator stack AI clusters run on (includes consumer GPU drivers:
# NVIDIA ships one driver branch for GeForce and data-center GPUs)
COMPUTE_RE = re.compile(
    r"\bnvidia (?:gpu|cuda|container toolkit|dgx|hgx|vgpu|virtual gpu|bluefield|nvlink|"
    r"base command|ai enterprise|data center gpu|fabric manager|dcgm|nccl|cudnn|mig\b)|"
    r"\bcuda(?: toolkit)?\b|\brocm\b|\bamd instinct\b|\bgaudi\b|\bhabana\b|\bcloud tpu\b")
# credits / description naming an AI discovery tool or AI lab. "Claude" alone
# is a first name, so it needs model/lab context.
FOUND_RE = re.compile(
    r"\bbig ?sleep\b|\bxbow\b|\baisle\b|\baardvark\b|\bcodemender\b|\bdepthfirst\b|\bzeropath\b|"
    r"\bvulnhuntr\b|\banthropic\b|\bopenai\b|\bgpt-?\d|\bopenai codex\b|"
    r"\bclaude(?: code| security| mythos| opus| sonnet| haiku| ai\b|[:-]|\s*$)|"
    r"\b(?:using|with|by|and|via) claude\b|"
    r"\bai[- ](?:agent|assisted|powered|driven)\b|\bllm[- ](?:assisted|based|powered|agent)\b|"
    r"autonomous (?:ai|agent|vulnerability|security)")
FOUND_DESC_RE = re.compile(
    r"\b(?:reported|found|discovered|identified|detected|spotted|uncovered) (?:by|with|using|via) "
    r"(?:\S+ ){0,4}?(?:claude|big ?sleep|gpt-?\d|codex|gemini|an? (?:ai|llm)\b|ai[- ]assisted|"
    r"llms?\b|xbow|aardvark|depthfirst|zeropath)", re.I)


def record_credits(cna):
    """All credit values of a CNA container as one string."""
    return " | ".join(_str(c.get("value")) for c in (cna.get("credits") or [])
                      if isinstance(c, dict))


def record_cwes(cna):
    """Every CWE id in the CNA problemTypes."""
    out = set()
    for pt in cna.get("problemTypes") or []:
        for d in (pt.get("descriptions") or []) if isinstance(pt, dict) else []:
            for v in (d.get("cweId"), d.get("description")) if isinstance(d, dict) else ():
                m = CWE_RE.match(v) if isinstance(v, str) else None
                if m:
                    out.add(m.group(1).upper())
    return out


def ai_relations(layer, desc, blob, credits, cwes, kernel=False, vendor=None):
    """Sorted AI_RELATIONS ids for one CVE (empty list = not AI-related).
    layer = record_layer(); blob = description + affected rows; kernel
    records only take "found" (their commit text names unrelated drivers)."""
    rels = set()
    d = (desc or "").lower()
    if FOUND_RE.search((credits or "").lower()) or FOUND_DESC_RE.search(desc or ""):
        rels.add("found")
    if not kernel:
        b = (blob or "").lower()
        if layer == "mcp":
            rels.add("agent")
        elif layer == "cloud" and MAINSTREAM_RE.match((vendor or "").lower()):
            rels.add("feature")
        elif layer:
            rels.add("product")
        if FEATURE_RE.search(b):
            rels.add("feature")
        if WEAKNESS_RE.search(d) or (cwes & AI_CWES):
            rels.add("weakness")
        if COMPUTE_RE.search(b):
            rels.add("compute")
    return [r for r in RELATION_IDS if r in rels]


def record_relations(containers, layer):
    """ai_relations() for a parsed record."""
    cna = containers.get("cna") or {}
    desc = en_description(cna)[:800]
    kernel = desc.lower().startswith(KERNEL_PREFIX)
    return ai_relations(layer, desc, desc + " " + _affected_blob(containers),
                        record_credits(cna), record_cwes(cna), kernel, record_vendor(containers))



# --- origins: where a CVE comes from (one per CVE) -----------------------------
ORIGINS = [
    {"id": "supplychain", "label": "Open-source projects & packages (supply chain)"},
    {"id": "plugin", "label": "Web CMS plugins & themes"},
    {"id": "edge", "label": "Network & security edge devices"},
    {"id": "platform", "label": "OS, browsers & core platforms"},
    {"id": "other", "label": "Enterprise & other software"},
]
ORIGIN_IDS = [x["id"] for x in ORIGINS]

# Evaluation order differs from the list order in one place: plugin is tested
# before supplychain (WordPress plugins carry packageURLs / wordpress.org
# collectionURLs). Origins say what kind of software it is and ignore AI:
# an AI tool lands in its natural class (a PyPI package -> supplychain); how a
# CVE relates to AI is the separate, multi-label AI_RELATIONS tagging.
PLUGIN_CNAS = {"wordfence", "patchstack", "wpscan"}
PLUGIN_RE = re.compile(
    r"\b(?:plugin|theme|add-?on|extension) for (?:wordpress|joomla!?|drupal)\b|"
    r"\bwordpress (?:plugins?|themes?)\b|\bwp (?:plugin|theme)\b|"
    r"\bjoomla!? (?:extensions?|components?|modules?|plugins?|templates?)\b|"
    r"\b(?:component|module|extension) for joomla|\bdrupal (?:modules?|themes?|contrib\w*)\b|"
    r"\bmodule for drupal\b|\b(?:plugin|theme)\b.{0,60}?\bfor wordpress\b|pkg:wordpress-|wordpress\.org/(?:plugins|themes)|"
    r"drupal\.org/project|themeforest\.net|codecanyon\.net")
# packageURL types / registry collectionURLs that mean "installed from a package registry"
SUPPLY_PURL_RE = re.compile(
    r"^pkg:(?:npm|pypi|maven|golang|cargo|composer|hex|gem|nuget|cpan|pub|conda|cocoapods|swift|"
    r"hackage|opam|conan|otp|github|gitlab|bitbucket|cran|julia|luarocks|oci|docker)/")
SUPPLY_COLLECTION_RE = re.compile(
    r"^https?://(?:www\.)?(?:registry\.npmjs\.org|npmjs\.com|pypi\.(?:org|python\.org)|"
    r"repo1?\.maven\.(?:apache\.)?org|central\.sonatype\.com|search\.maven\.org|pkg\.go\.dev|"
    r"proxy\.golang\.org|crates\.io|rubygems\.org|(?:api\.)?nuget\.org|packagist\.org|"
    r"(?:repo\.)?hex\.pm|pub\.dev|(?:meta)?cpan\.org|anaconda\.org|conda-forge|cocoapods\.org|"
    r"hackage\.haskell\.org|opam\.ocaml\.org|cran\.r-project\.org)")
# GitHub (GHSA advisories for open-source repos/packages) and ecosystem CNAs
SUPPLY_CNAS = {"github_m", "cpansec", "eef", "go", "psf", "openjs", "rubygems"}

# (vendor regex, product regex or None = any product, exclude regex or None),
# matched against each affected "vendor" / "product" (lowercased).
EDGE_VENDORS = [
    (r"fortinet", None, r"forticlient|fortitoken"),
    (r"ivanti|pulse ?secure", r"connect secure|policy secure|\bics\b|pulse|zta|zero trust|endpoint manager "
     r"mobile|epmm|mobileiron|sentry|cloud services appliance|\bcsa\b|traffic manager|vtm", None),
    (r"citrix|netscaler|cloud software group", r"netscaler|\badc\b|gateway|sd-?wan|application "
     r"delivery", None),
    (r"palo ?alto", r"pan-?os|globalprotect|prisma (?:access|sd-wan)|firewall", None),
    (r"cisco", r"\basa\b|adaptive security|firepower|\bftd\b|secure firewall|\bios\b|ios[ -]x[er]|"
     r"nx-?os|router|switch|meraki|sd-?wan|catalyst|nexus|aironet|wireless lan|\bwlc\b|\brv\d|"
     r"small business|email security|secure email|\besa\b|asyncos|identity services|\bise\b|"
     r"anyconnect|secure client|vpn|access point|integrated management controller", r"webex"),
    (r"sonicwall", None, None), (r"juniper", None, None), (r"check ?point", None, None),
    (r"zyxel", None, None), (r"array networks", None, None), (r"barracuda", None, None),
    (r"watchguard", None, None), (r"netgate|pfsense|opnsense", None, None),
    (r"draytek", None, None), (r"mikrotik", None, None), (r"tp-?link", None, None),
    (r"d-?link", None, None), (r"netgear", None, None), (r"tenda", None, None),
    (r"totolink", None, None), (r"linksys", None, None), (r"wavlink", None, None),
    (r"ruijie", None, None), (r"\bh3c\b", None, None), (r"four-faith", None, None),
    (r"teltonika", None, None), (r"cambium", None, None), (r"arista", None, None),
    (r"ruckus", None, None), (r"peplink", None, None), (r"cradlepoint", None, None),
    (r"edimax", None, None), (r"trendnet", None, None), (r"a10 networks", None, None),
    (r"netcore|\bnetis\b|\bcudy\b|comfast|ip-?com\b|\butt\b|\bxiaomi\b", r"router|\bwr\d|\bax\d|nbr|\bac\d", None),
    (r"\bf5\b", r"big-?ip|f5os|big-?iq|velos|rseries", None),
    (r"sophos", r"firewall|\butm\b|\bxg\b|sfos|\bsg\b|web appliance|email appliance|"
     r"connect|\bred\b", None),
    (r"ubiquiti|\bui\b", r"unifi|edge ?router|edgemax|edgeswitch|airos|usg|dream machine", None),
    (r"aruba|hewlett packard enterprise|\bhpe\b", r"arubaos|aruba ?os|\baos\b|aos-|clearpass|"
     r"instant|mobility (?:conductor|controller)|edgeconnect|\bvia\b|wireless operating|"
     r"access points?|aruba networking switch", None),
    (r"\basus\b", r"router|\brt-|asuswrt|\bgt-|\btuf-ax|zenwifi|\bax\d", None),
    (r"huawei", r"router|firewall|\busg\d|\bar\d|\bne\d|eudemon|hisecengine", None),
    (r"\bzte\b", r"router|\bmf\d|\bzxhn|\bf\d{3,4}\b|cpe", None),
    (r"progress|kemp", r"loadmaster", None), (r"proofpoint", r"email|protection server", None),
    (r"openvpn", r"access server", None), (r"versa", r"director|\bvos\b|flexvnf", None),
]
EDGE_PRODUCT_RE = re.compile(r"\brouters?\b|\bfirewall\b|ssl[- ]?vpn|\bvpn (?:server|gateway|"
                             r"appliance)|\bload balancer\b|\bwireless access point")
PLATFORM_VENDORS = [
    (r"microsoft", None, None), (r"\bapple\b", None, None), (r"mozilla", None, None),
    (r"google", r"android|chrome|pixel|fuchsia|wear ?os|chromium", None),
    (r"\bandroid\b|aosp", None, None), (r"^linux$", r"linux|kernel", None),
    (r"qualcomm", None, None), (r"mediatek", None, None),
    (r"huawei|honor", r"harmony ?os|emui|magic ?ui|huawei (?:mate|p\d|nova)|smartphone", None), (r"samsung", r"mobile|android|"
     r"galaxy|exynos|one ?ui|smartphone", None), (r"unisoc", None, None),
    (r"vmware|broadcom", r"esxi|vcenter|workstation|fusion|cloud foundation|vmware tools", None),
]
PLATFORM_CNAS = {"microsoft", "apple", "chrome", "google_android", "linux", "mozilla",
                 "qualcomm", "mediatek", "samsungmobile", "unisoc"}
# description fallbacks for records without a usable affected product (old NVD-era)
EDGE_DESC_RE = re.compile(
    r"\b(?:fortinet|fortios|fortigate|fortiproxy|fortiweb|pan-os|globalprotect|netscaler|"
    r"citrix (?:adc|gateway)|pulse (?:connect )?secure|ivanti connect secure|cisco (?:asa|adaptive "
    r"security|firepower|ios|nx-os|rv\d)|sonicwall|juniper|junos|check point|zyxel|barracuda|"
    r"watchguard|draytek|mikrotik|routeros|tp-link|d-link|netgear|tenda|totolink|linksys|"
    r"big-ip|array networks|sophos (?:firewall|utm|xg))\b|\b(?:wireless |vpn |broadband )?router\b")
PLATFORM_DESC_RE = re.compile(
    r"\b(?:microsoft|windows|internet explorer|apple|ipados|macos|mac os x|safari|watchos|tvos|"
    r"google chrome|chromium|mozilla|firefox|thunderbird|linux kernel|google android|"
    r"android (?:os|framework|kernel|system|media|\d)|(?:apple )?ios (?:before|\d|and ipados))\b")
# cameras / NAS / VPN client plugins from edge vendors are not edge devices
EDGE_EXCLUDE_RE = re.compile(r"camera|\bnas\d*\b|\bdn[rs]-\d|networkmanager|doorbell|\bnvr\b|\bdvr\b")


def _vendor_rules(rules):
    return [(re.compile(v), re.compile(p) if p else None, re.compile(x) if x else None)
            for v, p, x in rules]


EDGE_RULES = _vendor_rules(EDGE_VENDORS)
PLATFORM_RULES = _vendor_rules(PLATFORM_VENDORS)


def _vendor_match(rules, vendor, product):
    for v, p, x in rules:
        if v.search(vendor) and (p is None or p.search(product) or p.search(vendor)):
            if not (x and (x.search(product) or x.search(vendor))):
                return True
    return False


def _rows_all(containers):
    """(vendor, product, packageURL, collectionURL) of every CNA + ADP affected entry."""
    out = []
    for c in [containers.get("cna") or {}] + product_adps(containers):
        for a in (c.get("affected") or []) if isinstance(c, dict) else []:
            if isinstance(a, dict):
                out.append(tuple(_str(a.get(k)).strip() for k in
                                 ("vendor", "product", "packageURL", "collectionURL")))
    return out


def origin_of(assigner, desc, rows):
    """Origin id from the assigner short name, English description and affected
    rows [(vendor, product, packageURL, collectionURL)]; see ORIGINS."""
    asg = (assigner or "").lower()
    d = (desc or "")[:400].lower()
    named = [(v.lower().replace("_", " "), p.lower().replace("_", " "), u, c.lower())
             for v, p, u, c in rows
             if not (v.lower() in _NA and p.lower() in _NA) and not REDISTRIBUTOR_RE.match(v)]
    first_v = named[0][0] if named else ""
    own = [r for r in named if r[0] == first_v] or named   # skip downstream bundles
    # vendor "n/a" with the vendor in the product ("Cisco IOS"): match on the product
    own = [(p if v in _NA else v, p, u, c) for v, p, u, c in own]
    blob = " ".join(f"{v} {p} {u.lower()} {c}" for v, p, u, c in own)
    if asg in PLUGIN_CNAS or PLUGIN_RE.search(d) or PLUGIN_RE.search(blob):
        return "plugin"
    if (asg in SUPPLY_CNAS or any(SUPPLY_PURL_RE.match(u.lower()) for _, _, u, _ in own)
            or any(SUPPLY_COLLECTION_RE.match(c) for _, _, _, c in own)):
        return "supplychain"
    if own:
        if (not EDGE_EXCLUDE_RE.search(blob + " " + d[:200])
                and any(_vendor_match(EDGE_RULES, v, p) or EDGE_PRODUCT_RE.search(p)
                        for v, p, _, _ in own)):
            return "edge"
        if asg in PLATFORM_CNAS or any(_vendor_match(PLATFORM_RULES, v, p) for v, p, _, _ in own):
            return "platform"
        return "other"
    if EDGE_DESC_RE.search(d) and not EDGE_EXCLUDE_RE.search(d[:200]):
        return "edge"
    if asg in PLATFORM_CNAS or PLATFORM_DESC_RE.search(d):
        return "platform"
    return "other"


def record_origin(containers, assigner):
    """origin_of() for a parsed record."""
    cna = containers.get("cna") or {}
    return origin_of(assigner, en_description(cna), _rows_all(containers))


def classify_origin(text):
    """Origin id for free text such as KEV "vendorProject product name" strings
    (no assigner / packageURL available)."""
    t = (text or "").lower()
    if PLUGIN_RE.search(t):
        return "plugin"
    if re.search(r"pkg:[a-z]+/", t):
        return "supplychain"
    if EDGE_DESC_RE.search(t) or EDGE_PRODUCT_RE.search(t) or _vendor_match(EDGE_RULES, t, t):
        return "edge"
    if PLATFORM_DESC_RE.search(t) or _vendor_match(PLATFORM_RULES, t, t):
        return "platform"
    return "other"


def parse_file(path):
    """(cve_id, row) for one CVE record, or None. row = [state, pubISO, resISO,
    layer|None, sev, score, cvssV, sevSrc, cwe, cna, product, origin, vendor,
    relations|None]
    (indexes are private: other modules use lookup_records())."""
    rec = load_record(path)
    meta = rec and rec.get("cveMetadata")
    if not isinstance(meta, dict):
        return None
    containers = rec.get("containers") or {}
    if not isinstance(containers, dict):
        containers = {}
    layer = record_layer(containers)
    sev, score, ver, src = record_severity(containers)
    return (
        meta.get("cveID") or meta.get("cveId") or "",
        [(meta.get("state") or "").upper(),
         meta.get("datePublished") or "",
         meta.get("dateReserved") or "",
         layer, sev, score, ver, src,
         record_cwe(containers.get("cna") or {}),
         meta.get("assignerShortName") or None,
         record_product(containers),
         record_origin(containers, meta.get("assignerShortName")),
         record_vendor(containers),
         record_relations(containers, layer) or None],
    )


def lookup_records(cve_ids, data_dir=None):
    """{cve: {"d": publishedDay|None, "origin", "layer", "product", "cna",
    "vendor", "rels"}} for
    the ids found in the parse cache (<data_dir or DATADIR>/cache.json)."""
    path = os.path.join(data_dir or DATADIR, "cache.json")
    try:
        with open(path) as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return {}
    if raw.get("version") != PARSER_VERSION:
        return {}
    recs = raw.get("records") or {}
    out = {}
    for cid in cve_ids:
        r = recs.get(cid)
        if r:
            out[cid] = {"d": (r[1] or "")[:10] or None if r[0] == "PUBLISHED" else None,
                        "origin": r[11], "layer": r[3], "product": r[10], "cna": r[9],
                        "vendor": r[12], "rels": r[13] or []}
    return out


def record_path(cid):
    """cves/<year>/<N>xxx/<id>.json -- the year is the ID's, not publication's."""
    try:
        _, year, seq = cid.split("-")
        return os.path.join(CLONE, "cves", year, f"{int(seq) // 1000}xxx", cid + ".json")
    except ValueError:
        return None


def parse_many(paths):
    """parse_file over paths; a process pool for big batches (full parse)."""
    if len(paths) < 2000:
        yield from map(parse_file, paths)
        return
    import multiprocessing
    with multiprocessing.Pool(min(8, os.cpu_count() or 1)) as pool:
        yield from pool.imap_unordered(parse_file, paths, chunksize=500)


# --- aggregation helpers (pure) -------------------------------------------------
def top_counts(counter, n):
    """{key: count} of the n most common, ties broken by key."""
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n])


def cna_years(ai_rows, top=8, since="2018"):
    """{year: {assigner: n, ..., "other": n}} over (dayISO, assigner) pairs."""
    by_year = defaultdict(Counter)
    for day, cna in ai_rows:
        if day[:4] >= since:
            by_year[day[:4]][cna or "unknown"] += 1
    out = {}
    for y in sorted(by_year):
        c = by_year[y]
        head = top_counts(c, top)
        rest = sum(c.values()) - sum(head.values())
        if rest:
            head["other"] = rest
        out[y] = head
    return out


def concentration(ai_rows, since="2018", min_share=0.10, min_n=25):
    """Single products that dominate a year's AI CVEs (bulk disclosures, e.g.
    TensorFlow 2021-22): {year: {"total": n, "top": [{product, n, share,
    cna, cnaN}]}} over (dayISO, product, assigner) rows, years with a hit."""
    by_year = defaultdict(lambda: defaultdict(Counter))
    spelling = defaultdict(Counter)  # grouping key -> original spellings
    for day, product, cna in ai_rows:
        if day[:4] >= since and product:
            key = product.strip().lower()
            by_year[day[:4]][key][cna or "unknown"] += 1
            spelling[key][product.strip()] += 1
    out = {}
    for y in sorted(by_year):
        prods = by_year[y]
        total = sum(sum(c.values()) for c in prods.values())
        top = []
        for prod, cnas in sorted(prods.items(), key=lambda kv: -sum(kv[1].values()))[:3]:
            n = sum(cnas.values())
            if n / total < min_share or n < min_n:
                break
            cna, cna_n = cnas.most_common(1)[0]
            top.append({"product": spelling[prod].most_common(1)[0][0], "n": n, "share": round(n / total, 3),
                        "cna": cna, "cnaN": cna_n})
        if top:
            out[y] = {"total": total, "top": top}
    return out


def origin_years(origin_month, since="2018"):
    """{origin: {year: n}} (years >= since, every origin and year present)."""
    years = sorted({m[:4] for c in origin_month.values() for m in c if m[:4] >= since})
    out = {}
    for o in ORIGIN_IDS:
        c = Counter()
        for m, n in origin_month.get(o, {}).items():
            c[m[:4]] += n
        out[o] = {y: c.get(y, 0) for y in years}
    return out


def _windowed_top(cur, prev, n, names=None):
    """[{"id", "n", "prev"[, "name"]}] for the n largest keys of cur."""
    out = []
    for k, v in sorted(cur.items(), key=lambda kv: (-kv[1], kv[0]))[:n]:
        row = {"id": k, "n": v, "prev": prev.get(k, 0)}
        if names:
            row["name"] = names[k].most_common(1)[0][0]
        out.append(row)
    return out


# CNAs whose filing volume jumped for reasons of reporting practice (GitHub
# advisories, VulnCheck's bulk assignments): growth is shown with and without them.
BULK_CNAS = ("GitHub_M", "VulnCheck")


def ytd_filers(rows, today, bulk=BULK_CNAS):
    """Year-to-date vs the same days last year, overall and per origin, with the
    bulk filers' share: {window, prevWindow, bulkCnas, all, origins}; each count
    is {cur, prev, bulkCur, bulkPrev}. rows: (day, sev, cwe, cna, vendor, origin,
    rels) per published CVE. One window for every ratio a title prints."""
    cy, py = str(today.year), str(today.year - 1)
    md = today.strftime("%m-%d")
    zero = lambda: {"cur": 0, "prev": 0, "bulkCur": 0, "bulkPrev": 0}
    tot, by = zero(), defaultdict(zero)
    for day, _sev, _cwe, cna, _vend, origin, _rels in rows:
        if day[5:] > md:
            continue
        k = "cur" if day[:4] == cy else "prev" if day[:4] == py else None
        if not k:
            continue
        b = "bulkCur" if k == "cur" else "bulkPrev"
        for c in (tot, by[origin or "other"]):
            c[k] += 1
            if cna in bulk:
                c[b] += 1
    return {"window": [f"{cy}-01-01", today.isoformat()], "prevWindow": [f"{py}-01-01", f"{py}-{md}"],
            "bulkCnas": list(bulk), "all": tot, "origins": dict(by)}


def landscape(rows, months, today, since="2018", top=12):
    """The same set of aggregates for any slice of CVEs (all, AI-related).
    rows: (pubDay, sev, cwe, cna, vendor, origin, rels) per PUBLISHED CVE.
    Windows: the last 365 days (`cur`, ending today) vs the 365 before (`prev`)."""
    cur_from = (today - dt.timedelta(days=364)).isoformat()
    prev_from = (today - dt.timedelta(days=729)).isoformat()
    month_n, years = Counter(), Counter()
    sev_years = defaultdict(Counter)
    origin_y = defaultdict(Counter)
    rel_y = defaultdict(Counter)
    cwe = (Counter(), Counter())
    vendor = (Counter(), Counter())
    cna = (Counter(), Counter())
    sev_w = []
    names = defaultdict(Counter)
    total = 0
    for day, sev, cw, asg, vend, origin, rels in rows:
        total += 1
        month_n[day[:7]] += 1
        y = day[:4]
        if y >= since:
            years[y] += 1
            sev_years[y][sev if sev in SEVERITIES else "UNRATED"] += 1
            origin_y[origin or "other"][y] += 1
            for r in rels or ():
                rel_y[r][y] += 1
        w = 0 if day >= cur_from else 1 if day >= prev_from else None
        if w is None:
            continue
        if w == 0:
            sev_w.append(sev)
        if cw:
            cwe[w][cw] += 1
        if vend:
            key = vend.strip().lower()
            vendor[w][key] += 1
            names[key][vend.strip()] += 1
        cna[w][asg or "unknown"] += 1
    ys = sorted(years)
    return {
        "total": total,
        "months": [month_n.get(m, 0) for m in months],
        "years": {y: years[y] for y in ys},
        "sevYears": {y: {k: sev_years[y].get(k, 0) for k in SEVERITIES + ("UNRATED",)} for y in ys},
        "originYears": {o: {y: origin_y[o].get(y, 0) for y in ys} for o in ORIGIN_IDS},
        "relYears": {r: {y: rel_y[r].get(y, 0) for y in ys} for r in RELATION_IDS},
        "window": {"cur": [cur_from, today.isoformat()],
                   "prev": [prev_from, (today - dt.timedelta(days=365)).isoformat()],
                   "n": sum(cna[0].values()), "prevN": sum(cna[1].values())},
        "sevWindow": sev_mix(sev_w),
        "cweTop": _windowed_top(cwe[0], cwe[1], top),
        "vendorTop": _windowed_top(vendor[0], vendor[1], top, names),
        "cnaTop": _windowed_top(cna[0], cna[1], top),
    }


def window_months(months, n=COMPARE_MONTHS):
    """[first, last] of the last n months (the current, partial month included)."""
    return [months[-n:][0], months[-1]] if months else None


def sev_mix(sevs):
    """{"CRITICAL": n, ..., "UNRATED": n} for an iterable of sev values."""
    c = Counter(s if s in SEVERITIES else "UNRATED" for s in sevs)
    return {k: c.get(k, 0) for k in SEVERITIES + ("UNRATED",)}


def stratified_eval(labels, strata, pool, predict):
    """Precision/recall estimated from a stratified hand-labeled sample.
    labels {id: bool}, strata {id: name}, pool {name: population size at
    labeling time}, predict(id) -> bool|None (None = not in the corpus).
    Each stratum's confusion counts are scaled by pool/sampled; returns
    (precision|None, recall|None, n_used, {stratum: {pool, n, tp, fp, fn, tn}})."""
    per = defaultdict(lambda: [0, 0, 0, 0])  # tp fp fn tn
    for cid, truth in labels.items():
        p = predict(cid)
        st = strata.get(cid)
        if p is None or st not in pool:
            continue
        per[st][(0 if truth else 1) if p else (2 if truth else 3)] += 1
    tp = fp = fn = 0.0
    n = 0
    for st, (a, b, c, d) in per.items():
        k = a + b + c + d
        n += k
        w = pool[st] / k
        tp, fp, fn = tp + a * w, fp + b * w, fn + c * w
    prec = round(tp / (tp + fp), 4) if tp + fp else None
    rec = round(tp / (tp + fn), 4) if tp + fn else None
    detail = {st: dict(zip(("tp", "fp", "fn", "tn"), v), pool=pool[st], n=sum(v))
              for st, v in sorted(per.items())}
    return prec, rec, n, detail


def evaluation(records):
    """data.json `evaluation` block from tools/ai_labels.json, or None."""
    try:
        with open(LABELS) as f:
            lab = json.load(f)
    except (OSError, ValueError):
        return None
    labels, strata, pool = lab.get("labels") or {}, lab.get("strata") or {}, lab.get("pool") or {}
    if not labels:
        return None

    def predict(cid):
        r = records.get(cid)
        return None if r is None else bool(r[3])

    prec, rec, n, detail = stratified_eval(labels, strata, pool, predict)
    return {"labeledAt": lab.get("labeledAt"), "sample": n, "precision": prec,
            "recall": rec, "method": lab.get("method") or "", "strata": detail}


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
            raw = json.load(f)
        if raw.get("version") != PARSER_VERSION:
            print("cache from an older parser -> full re-parse", file=sys.stderr)
            args.full = True
        else:
            cache = raw["records"]
            print(f"cache: {len(cache)} records", file=sys.stderr)

    incremental = isinstance(changed, set)
    records = {}       # cve id -> parse_file() row
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
                    if name[:-5] in cache and not args.full:
                        records[name[:-5]] = cache[name[:-5]]
                    else:
                        to_parse.append(os.path.join(root, name))

    print(f"parsing {len(to_parse)} file(s)...", file=sys.stderr)
    done = 0
    for r in parse_many(to_parse):
        done += 1
        if done % 50000 == 0:
            print(f"  {done}/{len(to_parse)}", file=sys.stderr)
        if r and r[0]:
            records[r[0]] = r[1]

    # --- aggregate ------------------------------------------------------------
    today = dt.datetime.now(dt.timezone.utc).date()
    hours_keep_from = today - dt.timedelta(days=HOURS_KEEP // 24)

    pub_days = defaultdict(int)
    ai_days = defaultdict(int)
    layer_month = defaultdict(Counter)   # layer -> month -> n
    origin_month = defaultdict(Counter)  # origin -> month -> n
    hours = defaultdict(int)
    ai_hours = defaultdict(int)
    ai_meta = {}
    ai_cna = []        # (day, assigner) per AI CVE
    ai_products = []   # (day, product, assigner) per AI CVE
    published_total = ai_total = rejected_total = 0
    recent_ai = []     # (published_iso, id)

    land_all, land_ai = [], []

    for cid, row in records.items():
        state, pub, _res, layer = row[0], row[1], row[2], row[3]
        rels = row[13]
        if state == "PUBLISHED" and pub:
            day = pub[:10]
            pub_days[day] += 1
            published_total += 1
            origin_month[row[11] or "other"][day[:7]] += 1
            lrow = (day, row[4], row[8], row[9], row[12], row[11], rels)
            land_all.append(lrow)
            if day >= hours_keep_from.isoformat():
                hours[pub[:13]] += 1  # "YYYY-MM-DDTHH"
            if layer:
                layer_month[layer][day[:7]] += 1
            if is_ai_risk(rels):
                land_ai.append(lrow)
                ai_days[day] += 1
                ai_total += 1
                ai_cna.append((day, row[9]))
                ai_products.append((day, row[10], row[9]))
                ai_meta[cid] = {"d": day, "layer": layer, "rels": rels, "sev": row[4],
                                "score": row[5], "cvssV": row[6], "sevSrc": row[7],
                                "cwe": row[8], "cna": row[9], "product": row[10],
                                "vendor": row[12], "origin": row[11]}
                if day >= hours_keep_from.isoformat():
                    ai_hours[pub[:13]] += 1
                if day >= (today - dt.timedelta(days=30)).isoformat():
                    recent_ai.append((pub, cid))
        elif state == "REJECTED":
            rejected_total += 1

    # recent AI CVE feed: re-read the last 30d of AI records for descriptions
    recent_ai.sort(reverse=True)
    feed = []
    for pub, cid in recent_ai[:30]:
        desc = ""
        path = record_path(cid)
        rec = load_record(path) if path else None
        if rec:
            desc = re.sub(r"\s+", " ", en_description(
                (rec.get("containers") or {}).get("cna") or {}))[:240]
        m = ai_meta[cid]
        feed.append({
            "id": cid,
            "published": pub[:16].replace("T", " "),
            "description": desc,
            "cna": m["cna"] or "",
            "cnaName": m["cna"] or "",
            "layer": m["layer"],
            "rels": m["rels"],
            "origin": m["origin"],
            "product": m["product"],
            "cvss": ({"sev": m["sev"], "score": m["score"], "v": m["cvssV"], "src": m["sevSrc"]}
                     if m["sev"] or m["score"] is not None else None),
        })

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
                    "method": ("soFar / median over the last 12 complete years of the share of "
                               "each month published by the same day-of-month"),
                }

    # --- AI vs all: record severity + CWE over the comparison window --------------
    window = window_months(months)
    sev_ai, sev_all, cwe_ai, cwe_all = [], [], Counter(), Counter()
    if window:
        for row in records.values():
            if row[0] != "PUBLISHED" or not row[1] or not (window[0] <= row[1][:7] <= window[1]):
                continue
            sev_all.append(row[4])
            if row[8]:
                cwe_all[row[8]] += 1
            if row[13]:
                sev_ai.append(row[4])
                if row[8]:
                    cwe_ai[row[8]] += 1
    severity_compare = {"window": window, "ai": sev_mix(sev_ai), "all": sev_mix(sev_all),
                        "source": "record CVSS: CNA 3.1 > CNA 4.0 > CNA 3.0 > ADP 3.1"}
    cwe_compare = {"window": window, "ai": top_counts(cwe_ai, 25), "all": top_counts(cwe_all, 25),
                   "aiTotal": sum(cwe_ai.values()), "allTotal": sum(cwe_all.values()),
                   "note": "totals = CVEs in the window with a CNA CWE id"}

    payload = {
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": "CVEProject/cvelistV5 (PUBLISHED records, by datePublished day)",
        "definitionVersion": DEFINITION_VERSION,
        "layers": AI_LAYERS,
        "total": published_total,
        "aiTotal": ai_total,
        "rejectedTotal": rejected_total,
        "months": months,
        "counts": counts,
        "aiMonths": [ai_month_counts.get(m, 0) for m in months],
        "layerMonths": {lid: [layer_month[lid].get(m, 0) for m in months] for lid in LAYER_IDS},
        "relations": AI_RELATIONS,
        "landscape": {"all": landscape(land_all, months, today),
                      "ai": landscape(land_ai, months, today)},
        "origins": ORIGINS,
        "originMonths": {o: [origin_month[o].get(m, 0) for m in months] for o in ORIGIN_IDS},
        "originYears": origin_years(origin_month),
        "ytd": ytd_filers(land_all, today),
        "cnaYears": cna_years(ai_cna),
        "concentration": concentration(ai_products),
        "severityCompare": severity_compare,
        "cweCompare": cwe_compare,
        "evaluation": evaluation(records),
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
        json.dump({"version": PARSER_VERSION, "records": records}, f)
    with open(AI_META, "w") as f:
        json.dump({"generatedAt": payload["generatedAt"], "definitionVersion": DEFINITION_VERSION,
                   "layers": AI_LAYERS, "relations": AI_RELATIONS, "ids": dict(sorted(ai_meta.items()))}, f)

    print(f"wrote {OUT}", file=sys.stderr)
    print(f"  {published_total} published ({ai_total} AI-related), "
          f"{rejected_total} rejected, {len(months)} months since {months[0]}",
          file=sys.stderr)
    ev = payload["evaluation"]
    if ev:
        print(f"  evaluation: precision {ev['precision']} recall {ev['recall']} (n={ev['sample']})",
              file=sys.stderr)

    if args.delete_clone:
        shutil.rmtree(CLONE, ignore_errors=True)
        print("deleted clone", file=sys.stderr)


if __name__ == "__main__":
    main()

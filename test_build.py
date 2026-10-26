#!/usr/bin/env python3
"""Unit tests for the pure helpers in build.py (no network, no full clone).

Run:  python3 test_build.py
"""
import json
import os
import subprocess
import sys
import tempfile

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import build  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f" FAIL {name}")


def test_is_ai_blob():
    print("is_ai_blob / classify_layer")
    L = build.classify_layer
    # one positive per layer (text as it appears in description / affected rows)
    layer_cases = [
        ("mcp", "mcp-server-kubernetes is an MCP Server that can connect to a cluster"),
        ("mcp", "The MCP Python SDK, an implementation of the Model Context Protocol"),
        ("mcp", "modelcontextprotocol inspector"),
        ("mcp", "Claude Code is an agentic coding tool"),
        ("mcp", "OpenClaw OpenClaw pkg:npm/openclaw"),
        ("mcp", "AGiXT is a dynamic AI Agent Automation Platform"),
        ("gateway", "LiteLLM is a proxy server (AI Gateway) to call LLM APIs"),
        ("gateway", "QuantumNous new-api"),
        ("inference", "vLLM is an inference and serving engine for large language models"),
        ("inference", "NVIDIA Triton Inference Server for Linux contains a vulnerability"),
        ("inference", "ollama ollama/ollama"),
        ("inference", "llama.cpp server crash"),
        ("mlops", "MLflow is an open source AI engineering platform"),
        ("mlops", "Ray is an AI compute engine. ray-project ray"),
        ("mlops", "Versions of the package ray before 2.43.0 log the redis password"),
        ("mlops", "h2oai h2oai/h2o-3"),
        ("mlops", "Microsoft Azure Machine Learning"),
        ("llmapp", "Langflow versions prior to 1.3.0 are susceptible to code injection"),
        ("llmapp", "IBM Langflow OSS"),
        ("llmapp", "Flowise is a drag & drop user interface"),
        ("llmapp", "Open WebUI is a self-hosted AI platform"),
        ("llmapp", "storyicon comfyui_segment_anything"),
        ("llmapp", "The AI Engine plugin for WordPress is vulnerable"),
        ("model", "Picklescan before 0.0.33 fails to detect the gadget"),
        ("model", "loading a crafted GGUF file"),
        ("cloud", "Command injection in M365 Copilot allows disclosure"),
        ("cloud", "Server-side request forgery in Azure AI Foundry"),
        ("cloud", "Microsoft Visual Studio Code CoPilot Chat Extension"),
        ("cloud", "IBM Watson Assistant for IBM Cloud Pak for Data"),
        ("framework", "TensorFlow is an open source platform for machine learning"),
        ("framework", "pkg:pypi/torch"),
        ("framework", "huggingface transformers"),
        ("framework", "affected product: transformers library"),
        ("framework", "Intel(R) Extension for Transformers"),
        ("framework", "onnxruntime import"),
        ("framework", "NVIDIA NeMo Framework contains a vulnerability"),
        ("model", "A machine learning model deserializes input"),
        ("other", "Vulnerability in the large language model runtime"),
        ("other", "The LLM endpoint allows prompt injection"),
        ("other", "loading a transformer model from disk"),
        ("other", "Blinko is an AI-powered card note-taking project"),
        ("other", "uses GPT-4o to summarize tickets"),
        ("mcp", "SiYuan contains a path traversal in the MCP file tool"),
    ]
    for want, text in layer_cases:
        check(f"{want}: {text[:50]}", build.is_ai_blob(text) and L(text) == want)
    # priority: an MCP server inside an LLM app is "mcp"; agent words don't beat product names
    check("priority mcp > llmapp", L("Langflow MCP server stdio transport") == "mcp")
    check("product beats weak agent term",
          L("Langflow is a tool for building AI agents") == "llmapp")
    check("classify_layer fallback", L("plain text") == "other")
    check("layers ordered", [x["id"] for x in build.AI_LAYERS] ==
          ["mcp", "gateway", "inference", "mlops", "llmapp", "model", "cloud", "framework", "other"])

    # known false positives of the old matcher and boundary cases
    negatives = [
        "Jax Guestbook 3.5.0 allows remote attackers to bypass authentication",
        "Research In Motion BlackBerry Torch 9800 with firmware 6.0.0.246",
        "The Accelerate Framework component in Apple iOS before 9.1",
        "The Accelerate theme for WordPress is vulnerable",
        "Moby is a project to enable and accelerate software containerization",
        "AjaxSearchPro plugin before 4.20",
        "JAX-WS client and service in Sun Java",
        "JAX-RS endpoint misconfiguration",
        "SQL injection in the login form allows bypass",
        "sets the optimum number of retries",
        "configures its XML transformer without XXE protection",
        "vm2's source code transformer",
        "Increments Qiita::Markdown allows XSS in transformers.",
        "OpenCV (Open Source Computer Vision Library) has a buffer overflow",
        "SourceCodester Drug Recommendation System 1.0",
        "Microchip MPLAB IDE via a .MCP project file",
        "hid: mcp-2221: prevent uaf in delayed work",
        "CIENA Navigator NCS  CIENA MCP",
        "Kaseya KServer file upload",
        "Gemini Labs Site Reviews site-reviews",
        "Minecraft Bedrock Dedicated Server heap overflow",
        "The Tourfic – AI Powered Travel Booking plugin for WordPress",
        "Jenkins Digital.ai App Management Publisher Plugin",
        "SQL injection in chatbox.php in pSys 0.7.0",
        "does not have device jailbreak detection",
        "ServiceNow has addressed a vulnerability in the ServiceNow AI platform",
        "a maliciously crafted MODEL file parsed through Autodesk AutoCAD",
        "glTF model loading in the 3D engine module",
        "the jbd2_journal_stop() function calling jbd2_might_wait_for_commit()",
        "getcursorposition() in TightVNC",
        "logstash grok filter",
        "TypeBot is a chatbot builder tool",
        "Unisys Libra systems with MCP-firmware 40.0",
        "Unisys ClearPath MCP TCP/IP Networking Services",
        "MitraStar GPT-2541GNAC (HGU) devices allow root access",
        "SQL injection in index.php in Classifieds Caffe",
        "printers have /usr/bin/lua installed setuid (jailbreak attack)",
        "",
    ]
    for text in negatives:
        check(f"not AI: {text[:50]!r}", not build.is_ai_blob(text))


def _write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _rec(cid, cna=None, adp=None, **meta):
    m = {"cveId": cid, "state": "PUBLISHED", "datePublished": "2026-05-01T10:00:00.000Z",
         "dateReserved": "2026-04-01T00:00:00.000Z", "assignerShortName": "GitHub_M"}
    m.update(meta)
    c = {"cna": cna or {}}
    if adp is not None:
        c["adp"] = adp
    return {"dataVersion": "5.1", "containers": c, "cveMetadata": m}


def test_parse_file():
    print("parse_file")
    R = build.parse_file
    with tempfile.TemporaryDirectory() as d:
        def run(name, rec):
            p = os.path.join(d, name + ".json")
            _write(p, json.dumps(rec))
            return R(p)

        cid, row = run("CVE-2024-1234", _rec(
            "CVE-2024-1234",
            cna={"descriptions": [{"lang": "en", "value": "XSS in a machine learning tool"}],
                 "affected": [{"vendor": "acme", "product": "mltool"}],
                 "metrics": [{"cvssV3_1": {"baseScore": 6.1, "baseSeverity": "MEDIUM"}}],
                 "problemTypes": [{"descriptions": [{"cweId": "CWE-79", "description": "CWE-79 XSS"}]}]},
            datePublished="2024-05-01T00:00:00.000Z", dateReserved="2024-04-01T00:00:00.000Z"))
        check("id + state", cid == "CVE-2024-1234" and row[0] == "PUBLISHED")
        check("published / reserved dates", row[1][:10] == "2024-05-01" and row[2][:10] == "2024-04-01")
        check("layer from desc", row[3] == "other")
        check("severity fields", row[4:8] == ["MEDIUM", 6.1, "3.1", "cna"])
        check("cwe + cna + product", row[8] == "CWE-79" and row[9] == "GitHub_M"
              and row[10] == "acme mltool")

        # metadata far into the file (>32KB of references before it)
        cid, row = run("CVE-1999-9999", {
            "containers": {"cna": {"references": [{"url": "https://example.com/%d" % i}
                                                  for i in range(1200)]}},
            "cveMetadata": {"cveID": "CVE-1999-9999", "state": "REJECTED",
                            "dateReserved": "1999-01-01T00:00:00.000Z"}})
        check("metadata after large container + cveID spelling", cid == "CVE-1999-9999")
        check("rejected state, not AI, no sev", row[0] == "REJECTED" and row[3] is None
              and row[4] is None and row[10] is None)

        def layer_of(desc_entry, name):
            return run(name, _rec(name, cna={"descriptions": [desc_entry]}))[1][3]
        check("value before lang",
              layer_of({"value": "RCE in a machine learning server", "lang": "en"}, "CVE-2026-1"))
        check("lang en-US", layer_of({"lang": "en-US", "value": "PyTorch loader RCE"}, "CVE-2026-2"))
        check("escaped quote before keyword",
              layer_of({"lang": "en", "value": 'The "load" API of the LLM gateway'}, "CVE-2026-3"))
        check("non-English only -> not AI",
              layer_of({"lang": "de", "value": "machine learning"}, "CVE-2026-4") is None)
        check("Linux kernel commit text -> not AI", layer_of(
            {"lang": "en", "value": "In the Linux kernel, the following vulnerability has been "
             "resolved:  net: fix leak. This issue was caught by LLM."}, "CVE-2026-6") is None)

        _, row = run("CVE-2026-5", _rec("CVE-2026-5", cna={
            "affected": [{"vendor": "vllm-project", "product": "vllm"}]}))
        check("AI layer from affected product", row[3] == "inference" and row[10] == "vllm-project vllm")

        # downstream bundles listed after the real product do not make it AI
        _, row = run("CVE-2026-7", _rec("CVE-2026-7", cna={
            "descriptions": [{"lang": "en", "value": "pyjwt accepts a crafted token"}],
            "affected": [{"vendor": "jpadilla", "product": "pyjwt"},
                         {"vendor": "Red Hat", "product": "Red Hat AI Inference Server 3.3"},
                         {"vendor": "Other", "product": "Red Hat OpenShift AI"}]}))
        check("downstream AI bundle ignored", row[3] is None)
        _, row = run("CVE-2026-8", _rec("CVE-2026-8", cna={
            "descriptions": [{"lang": "en", "value": "A flaw in sudo"}],
            "affected": [{"vendor": "Red Hat", "product": "Red Hat Enterprise Linux AI (RHEL AI) 3"}]}))
        check("redistributor-only AI product ignored", row[3] is None)
        _, row = run("CVE-2026-9", _rec("CVE-2026-9", cna={
            "descriptions": [{"lang": "en", "value": "Missing authz"}],
            "affected": [{"vendor": "n/a", "product": "n/a"}]},
            adp=[{"affected": [{"vendor": "gradio_project", "product": "gradio"}]}]))
        check("ADP affected product matched", row[3] == "llmapp" and row[10] == "gradio_project gradio")
        # supplier ADPs list every downstream product bundling the library
        _, row = run("CVE-2026-10", _rec("CVE-2026-10", cna={
            "descriptions": [{"lang": "en", "value": "Stack buffer overflow in CMS parsing"}],
            "affected": [{"vendor": "OpenSSL", "product": "OpenSSL"}]},
            adp=[{"providerMetadata": {"shortName": "siemens-SADP"},
                  "affected": [{"vendor": "Siemens", "product": "AI Lightweight Inference Server"}]}]))
        check("supplier ADP (-SADP) ignored", row[3] is None and row[10] == "OpenSSL")

        p3 = os.path.join(d, "x.json")
        _write(p3, '{"unrelated": true}')
        check("no metadata -> None", R(p3) is None)
        check("missing file -> None", R(os.path.join(d, "nope.json")) is None)

    rp = build.record_path("CVE-2025-11849")
    check("record_path", rp.endswith(os.path.join("cves", "2025", "11xxx", "CVE-2025-11849.json")))
    check("record_path small seq", build.record_path("CVE-2026-5").endswith(
        os.path.join("2026", "0xxx", "CVE-2026-5.json")))
    check("record_path bad id", build.record_path("bogus") is None)


def test_severity():
    print("record_severity")
    S = build.record_severity

    def m(**kw):
        return [{k: v} for k, v in kw.items()]
    v31 = {"baseScore": 8.8, "baseSeverity": "HIGH"}
    v40 = {"baseScore": 9.3, "baseSeverity": "CRITICAL"}
    v30 = {"baseScore": 5.3, "baseSeverity": "MEDIUM"}
    adp = [{"providerMetadata": {"shortName": "CISA-ADP"},
            "metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}]
    check("rule 1: CNA 3.1 first (even if listed after 4.0)",
          S({"cna": {"metrics": m(cvssV4_0=v40) + m(cvssV3_1=v31)}}) == ("HIGH", 8.8, "3.1", "cna"))
    check("rule 2: CNA 4.0 over 3.0",
          S({"cna": {"metrics": m(cvssV3_0=v30, cvssV4_0=v40)}}) == ("CRITICAL", 9.3, "4.0", "cna"))
    check("rule 3: CNA 3.0", S({"cna": {"metrics": m(cvssV3_0=v30)}}) == ("MEDIUM", 5.3, "3.0", "cna"))
    check("rule 4: ADP 3.1 when CNA has none", S({"cna": {}, "adp": adp}) == ("HIGH", 7.5, "3.1", "adp"))
    check("CNA beats ADP", S({"cna": {"metrics": m(cvssV3_0=v30)}, "adp": adp})[3] == "cna")
    check("v2 ignored", S({"cna": {"metrics": m(cvssV2_0={"baseScore": 10.0})}}) == (None,) * 4)
    check("score only -> v3 band", S({"cna": {"metrics": m(cvssV3_1={"baseScore": 9.0})}})[0] == "CRITICAL")
    check("NONE -> null", S({"cna": {"metrics": m(cvssV3_1={"baseScore": 0.0, "baseSeverity": "NONE"})}})
          == (None, 0.0, "3.1", "cna"))
    check("lowercase severity", S({"cna": {"metrics": m(cvssV3_1={"baseSeverity": "low"})}})[0] == "LOW")
    check("no metrics", S({"cna": {}}) == (None, None, None, None))
    check("bands", [build.sev_from_score(x) for x in (9.8, 7.0, 6.9, 4.0, 0.1, 0, None)] ==
          ["CRITICAL", "HIGH", "MEDIUM", "MEDIUM", "LOW", None, None])


def test_cwe_product():
    print("record_cwe / record_product")
    C = build.record_cwe
    check("cweId", C({"problemTypes": [{"descriptions": [{"cweId": "CWE-22", "description": "x"}]}]})
          == "CWE-22")
    check("first of several", C({"problemTypes": [
        {"descriptions": [{"description": "n/a"}]},
        {"descriptions": [{"cweId": "CWE-918"}, {"cweId": "CWE-20"}]}]}) == "CWE-918")
    check("description prefix", C({"problemTypes": [{"descriptions": [
        {"description": "CWE-79 Improper Neutralization"}]}]}) == "CWE-79")
    check("non-CWE text -> None", C({"problemTypes": [{"descriptions": [
        {"description": "Remote code execution"}]}]}) is None)
    check("NVD-CWE-noinfo -> None", C({"problemTypes": [{"descriptions": [
        {"cweId": "NVD-CWE-noinfo"}]}]}) is None)
    check("none", C({}) is None)
    P = build.record_product
    check("vendor + product", P({"cna": {"affected": [{"vendor": "langflow-ai", "product": "langflow"}]}})
          == "langflow-ai langflow")
    check("skip n/a entries", P({"cna": {"affected": [{"vendor": "n/a", "product": "n/a"},
                                                     {"vendor": "NVIDIA", "product": "Megatron-LM"}]}})
          == "NVIDIA Megatron-LM")
    check("no duplicated vendor", P({"cna": {"affected": [
        {"vendor": "NVIDIA", "product": "NVIDIA Triton Inference Server"}]}}) == "NVIDIA Triton Inference Server")
    check("unknown vendor", P({"cna": {"affected": [{"vendor": "n/a", "product": "ray"}]}}) == "ray")
    check("ADP fallback", P({"cna": {}, "adp": [{"affected": [{"vendor": "x", "product": "y"}]}]}) == "x y")
    check("<= 80 chars", len(P({"cna": {"affected": [{"vendor": "v", "product": "p" * 200}]}})) == 80)
    check("none", P({"cna": {}}) is None)


def test_agg_pure():
    print("aggregation helpers")
    rows = ([("2024-01-02", "GitHub_M")] * 5 + [("2024-03-01", "VulDB")] * 3
            + [("2024-05-01", f"cna{i}") for i in range(8)] + [("2017-01-01", "mitre")])
    cy = build.cna_years(rows, top=3)
    check("cnaYears top + other", cy == {"2024": {"GitHub_M": 5, "VulDB": 3, "cna0": 1, "other": 7}})
    check("cnaYears since 2018", "2017" not in build.cna_years(rows))
    check("sev_mix", build.sev_mix(["HIGH", None, "LOW", "HIGH"]) ==
          {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 1, "UNRATED": 1})
    months = [f"2025-{m:02d}" for m in range(1, 13)] + [f"2026-{m:02d}" for m in range(1, 11)]
    check("window 24 months", build.window_months(months, 24) == ["2025-01", "2026-10"])
    check("window last n", build.window_months(months, 3) == ["2026-08", "2026-10"])
    check("window empty", build.window_months([]) is None)
    check("top_counts ties by key", build.top_counts({"b": 2, "a": 2, "c": 1}, 2) == {"a": 2, "b": 2})

    prow = ([("2021-03-01", "TensorFlow", "GitHub_M")] * 90 + [("2021-04-01", "vllm", "GitHub_M")] * 10
            + [("2024-01-01", f"p{i}", "x") for i in range(40)] + [("2017-01-01", "tensorflow", "x")] * 50)
    conc = build.concentration(prow)
    check("concentration flags dominant product", conc.get("2021", {}).get("top") ==
          [{"product": "TensorFlow", "n": 90, "share": 0.9, "cna": "GitHub_M", "cnaN": 90}])
    check("concentration skips spread-out / small / pre-2018 years",
          "2024" not in conc and "2017" not in conc)

    labels = {"f1": True, "f2": False, "s1": True, "s2": False, "r1": False, "r2": False}
    strata = {"f1": "flagged", "f2": "flagged", "s1": "suspect", "s2": "suspect",
              "r1": "random", "r2": "random"}
    pool = {"flagged": 100, "suspect": 50, "random": 1000}
    pred = {"f1": True, "f2": True, "s1": False, "s2": False, "r1": False, "r2": None}.get
    p, r, n, det = build.stratified_eval(labels, strata, pool, pred)
    # flagged: 1 TP 1 FP (x50) -> 50 TP 50 FP; suspect: 1 FN of 2 (x25) -> 25 FN
    check("stratified precision", p == 0.5)
    check("stratified recall", r == round(50 / 75, 4))
    check("records not in corpus skipped", n == 5 and det["random"]["n"] == 1)
    check("no labels", build.stratified_eval({}, {}, {}, pred)[:2] == (None, None))


def test_data_dir_env():
    print("CVE_DATA_DIR")
    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, CVE_DATA_DIR=d)
        out = subprocess.run(
            [sys.executable, "-c", "import build; print(build.DATADIR, build.CACHE, build.OUT, "
             "build.AI_META, build.LAST_HEAD)"],
            cwd=BASE, env=env, capture_output=True, text=True).stdout.split()
        check("all build state under CVE_DATA_DIR",
              len(out) == 5 and all(p.startswith(d) for p in out))
    check("default data dir", build.DATADIR == os.path.join(BASE, "data")
          or os.environ.get("CVE_DATA_DIR"))
    check("no NVD helpers left", not hasattr(build, "nvd_enrich") and not hasattr(build, "ORGS"))


def test_origins():
    print("origins")
    O = build.origin_of
    check("origin ids", [x["id"] for x in build.ORIGINS] ==
          ["supplychain", "plugin", "edge", "platform", "other"])
    check("AI PyPI package -> supplychain (origins ignore AI)",
          O("GitHub_M", "", [("vllm", "vllm", "pkg:pypi/vllm", "")]) == "supplychain")
    check("WordPress plugin with packageURL -> plugin", O("GitHub_M", "",
          [("acme", "acme-forms", "pkg:wordpress-plugin/acme-forms", "")]) == "plugin")
    check("wordpress.org collection -> plugin", O("Patchstack", "XSS in Foo",
          [("foo", "Foo", "", "https://wordpress.org/plugins")]) == "plugin")
    check("old-style plugin description -> plugin", O("mitre",
          "The Foo plugin before 1.2 for WordPress has XSS.", [("n/a", "n/a", "", "")]) == "plugin")
    check("Joomla extension -> plugin", O("Joomla", "Joomla Extension - x",
          [("balbooa", "Balbooa Forms extension for Joomla", "", "")]) == "plugin")
    check("npm purl -> supplychain", O("VulnCheck", "", [("hono", "hono", "pkg:npm/hono", "")])
          == "supplychain")
    check("maven collection -> supplychain", O("apache", "",
          [("Apache", "Commons", "", "https://repo.maven.apache.org/maven2")]) == "supplychain")
    check("GitHub_M repo -> supplychain", O("GitHub_M", "", [("systemd", "systemd", "", "")])
          == "supplychain")
    check("FortiOS -> edge", O("fortinet", "", [("Fortinet", "FortiOS", "", "")]) == "edge")
    check("FortiClient not edge", O("fortinet", "", [("Fortinet", "FortiClientWindows", "", "")])
          == "other")
    check("Cisco ASA -> edge", O("cisco", "",
          [("Cisco", "Cisco Adaptive Security Appliance (ASA) Software", "", "")]) == "edge")
    check("Cisco Webex not edge", O("cisco", "", [("Cisco", "Cisco Webex Meetings", "", "")])
          == "other")
    check("Ivanti Connect Secure -> edge", O("ivanti", "", [("Ivanti", "Connect Secure", "", "")])
          == "edge")
    check("Ivanti Endpoint Manager not edge", O("ivanti", "", [("Ivanti", "Endpoint Manager", "", "")])
          == "other")
    check("NGINX not edge", O("f5", "", [("F5", "NGINX Plus", "", "")]) == "other")
    check("D-Link NAS not edge", O("VulDB", "", [("D-Link", "DNS-320", "", "")]) == "other")
    check("UniFi camera not edge", O("hackerone", "", [("Ubiquiti Inc", "UniFi Protect Cameras", "", "")])
          == "other")
    check("old router description -> edge", O("mitre",
          "TOTOLINK A3300R was discovered to contain a command injection", [("n/a", "n/a", "", "")]) == "edge")
    check("Windows -> platform", O("microsoft", "", [("Microsoft", "Windows 10 Version 1809", "", "")])
          == "platform")
    check("Linux kernel -> platform", O("Linux", "In the Linux kernel, ...", [("Linux", "Linux", "", "")])
          == "platform")
    check("HarmonyOS -> platform", O("huawei", "", [("Huawei", "HarmonyOS", "", "")]) == "platform")
    check("Android app (desc only) not platform", O("mitre",
          "SunGrow iSolarCloud Android application contains hardcoded credentials",
          [("n/a", "n/a", "", "")]) == "other")
    check("downstream Red Hat rows ignored", O("redhat", "A flaw in libfoo",
          [("Red Hat", "Red Hat Enterprise Linux 9", "", "")]) == "other")
    check("Oracle -> other", O("oracle", "", [("Oracle Corporation", "PeopleSoft", "", "")]) == "other")

    C = build.classify_origin
    check("text: Langflow -> other (no AI origin)", C("Langflow Langflow code injection") == "other")
    check("text: Fortinet FortiOS -> edge", C("Fortinet FortiOS") == "edge")
    check("text: Microsoft Windows -> platform", C("Microsoft Windows SMB") == "platform")
    check("text: Cisco Webex -> other", C("Cisco Webex Meetings") == "other")
    check("text: Oracle E-Business -> other", C("Oracle E-Business Suite") == "other")

    oy = build.origin_years({"plugin": {"2017-01": 3, "2024-02": 2, "2024-05": 1}, "edge": {"2025-01": 4}})
    check("originYears since 2018, all origins/years",
          oy["plugin"] == {"2024": 3, "2025": 0} and oy["edge"] == {"2024": 0, "2025": 4}
          and oy["other"] == {"2024": 0, "2025": 0})

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "CVE-2026-11.json")
        _write(p, json.dumps(_rec("CVE-2026-11", cna={
            "descriptions": [{"lang": "en", "value": "Stack overflow in Tenda AC18"}],
            "affected": [{"vendor": "Tenda", "product": "AC18"}]}, assignerShortName="VulDB")))
        cid, row = build.parse_file(p)
        check("parse_file origin + product for non-AI rows", row[11] == "edge" and row[10] == "Tenda AC18")
        with open(os.path.join(d, "cache.json"), "w") as f:
            json.dump({"version": build.PARSER_VERSION, "records": {cid: row}}, f)
        got = build.lookup_records(["CVE-2026-11", "CVE-1-1"], data_dir=d)
        check("lookup_records", got == {"CVE-2026-11": {"d": "2026-05-01", "origin": "edge",
                                                        "layer": None, "product": "Tenda AC18",
                                                        "cna": "VulDB", "vendor": "Tenda",
                                                        "rels": []}})
        with open(os.path.join(d, "cache.json"), "w") as f:
            json.dump({"version": -1, "records": {cid: row}}, f)
        check("lookup_records ignores stale cache", build.lookup_records([cid], data_dir=d) == {})
    check("lookup_records missing cache", build.lookup_records(["x"], data_dir="/nonexistent") == {})


def test_relations():
    print("AI relations")
    R = build.ai_relations
    check("relation ids", build.RELATION_IDS ==
          ["agent", "product", "feature", "weakness", "compute", "found"])
    check("mcp layer -> agent", R("mcp", "an MCP server", "", "", set()) == ["agent"])
    check("llmapp layer -> product", R("llmapp", "Langflow", "langflow", "", set()) == ["product"])
    check("cloud layer, Microsoft -> feature",
          R("cloud", "M365 Copilot", "m365 copilot", "", set(), vendor="Microsoft") == ["feature"])
    check("cloud layer, hobby repo -> product",
          R("cloud", "chatgpt-on-wechat", "", "", set(), vendor="zhayujie") == ["product"])
    check("Copilot named in a Microsoft product -> feature",
          R(None, "x", "Microsoft 365 Copilot Chat info disclosure", "", set()) == ["feature"])
    check("prompt injection -> weakness",
          R(None, "Indirect prompt injection in the summary feature", "", "", set()) == ["weakness"])
    check("CWE-1427 -> weakness", R(None, "x", "", "", {"CWE-1427"}) == ["weakness"])
    for text in ("demonstrated by JailbreakMe", "requires user interaction with a system prompt asking for permission",
                 "Integer overflow during glTF model loading", "allowing for potential data poisoning"):
        check(f"not a weakness: {text[:30]}", R(None, text, text, "", set()) == [])
    check("NVIDIA GPU driver -> compute",
          R(None, "NVIDIA GPU Display Driver for Linux", "nvidia gpu display driver", "", set()) == ["compute"])
    check("CUDA toolkit -> compute", R(None, "x", "nvidia cuda toolkit", "", set()) == ["compute"])
    for credits in ("Google Big Sleep", "Alex Gaynor using Claude from Anthropic", "iglocska | Claude Opus 5",
                    "Zhenpeng Lin of depthfirst", "XBOW", "Claude", "Stanislav Fort (Aisle Research)"):
        check(f"found: {credits}", R(None, "x", "", credits, set()) == ["found"])
    check("Claude the person is not found-by-AI", R(None, "x", "", "Claude Ndanda (TrixX)", set()) == [])
    check("description 'reported by Claude Mythos' -> found",
          R(None, "This issue was reported by Claude Mythos.", "", "", set()) == ["found"])
    check("is_ai_risk: found alone is not AI risk", not build.is_ai_risk(["found"]) and not build.is_ai_risk([])
          and build.is_ai_risk(["found", "agent"]) and build.is_ai_risk(["weakness"]))
    check("kernel records only take found",
          R(None, "nvidia gpu, prompt injection", "nvidia gpu", "Big Sleep", set(), kernel=True) == ["found"])
    check("multi-label", R("mcp", "prompt injection in an MCP server", "", "XBOW", set()) ==
          ["agent", "weakness", "found"])


def test_landscape():
    print("landscape")
    import datetime as dt
    today = dt.date(2026, 10, 26)
    rows = [("2026-10-01", "HIGH", "CWE-79", "GitHub_M", "Acme", "other", ["agent"]),
            ("2026-01-05", None, "CWE-79", "GitHub_M", "acme", "plugin", None),
            ("2025-06-01", "LOW", "CWE-22", "mitre", "Foo", "edge", ["found", "product"]),
            ("2017-03-01", "LOW", None, "mitre", None, "other", None)]
    L = build.landscape(rows, ["2017-03", "2025-06", "2026-01", "2026-10"], today)
    check("total + months", L["total"] == 4 and L["months"] == [1, 1, 1, 1])
    check("years since 2018", L["years"] == {"2025": 1, "2026": 2})
    check("sevYears with UNRATED", L["sevYears"]["2026"]["HIGH"] == 1 and L["sevYears"]["2026"]["UNRATED"] == 1)
    check("originYears", L["originYears"]["plugin"] == {"2025": 0, "2026": 1})
    check("relYears", L["relYears"]["found"] == {"2025": 1, "2026": 0} and L["relYears"]["agent"]["2026"] == 1)
    check("window last 365d vs prior", L["window"]["cur"] == ["2025-10-27", "2026-10-26"]
          and L["window"]["n"] == 2 and L["window"]["prevN"] == 1)
    check("cweTop: current-window keys with prev counts", L["cweTop"] == [{"id": "CWE-79", "n": 2, "prev": 0}])
    check("vendorTop case-folded, display name", L["vendorTop"][0]["n"] == 2 and L["vendorTop"][0]["name"] in ("Acme", "acme"))


def main():
    test_relations()
    test_landscape()
    test_is_ai_blob()
    test_parse_file()
    test_severity()
    test_cwe_product()
    test_agg_pure()
    test_origins()
    test_data_dir_env()
    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

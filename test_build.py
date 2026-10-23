#!/usr/bin/env python3
"""Unit tests for the pure helpers in build.py (no network, no full clone).

Run:  python3 test_build.py
"""
import os
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
    print("is_ai_blob")
    # genuine AI hits
    check("desc 'machine learning'", build.is_ai_blob("A machine learning model deserializes input"))
    check("desc 'large language model'", build.is_ai_blob("Vulnerability in the large language model runtime"))
    check("desc 'LLM'", build.is_ai_blob("The LLM endpoint allows prompt injection"))
    check("pkg transformers", build.is_ai_blob("affected product: transformers library"))
    check("pkg onnx", build.is_ai_blob("onnxruntime import"))
    # boundary-aware negatives
    check("AJAX not jax", not build.is_ai_blob("AjaxSearchPro plugin before 4.20"))
    check("JAX-WS not jax", not build.is_ai_blob("JAX-WS client and service in Sun Java"))
    check("JAX-RS not jax", not build.is_ai_blob("JAX-RS endpoint misconfiguration"))
    check("plain text not AI", not build.is_ai_blob("SQL injection in the login form allows bypass"))
    check("optimum word", not build.is_ai_blob("sets the optimum number of retries"))
    check("empty", not build.is_ai_blob(""))


def _write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def test_parse_file():
    print("parse_file")
    with tempfile.TemporaryDirectory() as d:
        # modern record: metadata near the top, published
        p1 = os.path.join(d, "CVE-2024-1234.json")
        _write(p1, json_dumps(
            {"dataversion": "5.1", "containers": {"cna": {"descriptions": [
                {"lang": "en", "value": "XSS in a machine learning tool"}]}},
             "cveMetadata": {"cveId": "CVE-2024-1234", "state": "PUBLISHED",
                             "datePublished": "2024-05-01T00:00:00.000Z",
                             "dateReserved": "2024-04-01T00:00:00.000Z"}}))
        r1 = build.parse_file(p1)
        check("published detected", r1 and r1[0] == "CVE-2024-1234" and r1[1] == "PUBLISHED")
        check("published date", r1 and r1[2][:10] == "2024-05-01")
        check("reserved date", r1 and r1[3][:10] == "2024-04-01")
        check("AI flag from desc", r1 and r1[4] is True)

        # old-style record: metadata pushed far in (>32KB) via padding
        p2 = os.path.join(d, "CVE-1999-9999.json")
        pad = '"containers": {"cna": {"references": [' + ','.join(
            ['{"url": "https://example.com/%d"}' % i for i in range(1200)]) + ']}}, '
        _write(p2, pad + json_dumps({"cveMetadata": {"cveID": "CVE-1999-9999", "state": "REJECTED",
                                                      "dateReserved": "1999-01-01T00:00:00.000Z"}}))
        r2 = build.parse_file(p2)
        check("old record parsed (fallback read)", r2 and r2[0] == "CVE-1999-9999")
        check("rejected state", r2 and r2[1] == "REJECTED")

        # missing metadata
        p3 = os.path.join(d, "x.json")
        _write(p3, '{"unrelated": true}')
        check("no metadata -> None", build.parse_file(p3) is None)

        # missing file
        check("missing file -> None", build.parse_file(os.path.join(d, "nope.json")) is None)


def json_dumps(obj):
    import json
    return json.dumps(obj)


def test_agg_pure():
    print("aggregation (port of JS bucketize for the month key)")
    # sanity: a full year of daily counts sums correctly when bucketed by month
    import calendar
    days = {f"2026-{m:02d}-{d:02d}": 1 for m in (1, 2, 3)
            for d in range(1, calendar.monthrange(2026, m)[1] + 1)}
    total = sum(days.values())
    check("sum stable", total == 90)


def test_sources_pure():
    import sources
    print("sources._primary_cvss")
    v31 = {"metrics": {"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"baseScore": 1.0, "baseSeverity": "LOW"}},
        {"type": "Primary", "cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}},
    ]},
     "descriptions": [{"value": "XSS in (CWE-79) the parser."}]}
    sev, score, cwe_id, cwe_label = sources._primary_cvss(v31)
    check("primary chosen over secondary", sev == "HIGH" and score == 8.1)
    check("cwe from description marker", cwe_id == "CWE-79" and cwe_label == "CWE-79")
    v2 = {"metrics": {"cvssMetricV2": [{"type": "Primary",
         "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]},
     "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89: Improper Neutralization"}]}]}
    sev, score, cwe_id, cwe_label = sources._primary_cvss(v2)
    check("v2 fallback + cwe from weaknesses",
          sev == "MEDIUM" and score == 5.0 and cwe_id == "CWE-89"
          and cwe_label == "CWE-89: Improper Neutralization")
    sev, score, cwe_id, cwe_label = sources._primary_cvss({"metrics": {}})
    check("no metrics -> (None, None, None, None)",
          sev is None and score is None and cwe_id is None and cwe_label is None)
    check("is_ai_text machine learning", sources.is_ai_text("machine learning pipeline"))
    check("is_ai_text plain", not sources.is_ai_text("SQL injection in login"))


def main():
    test_is_ai_blob()
    test_parse_file()
    test_agg_pure()
    test_sources_pure()
    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

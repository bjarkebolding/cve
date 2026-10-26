#!/usr/bin/env python3
"""Unit tests for the pure helpers in sources.py (no network).

Run:  python3 test_sources.py
"""
import datetime as dt
import json
import os
import sys
import tempfile

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import sources  # noqa: E402

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


def test_primary_cvss():
    print("sources._primary_cvss / _nvd_metric")
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
    check("v2 never used (rule 5) + cwe from weaknesses",
          sev is None and score is None and cwe_id == "CWE-89"
          and cwe_label == "CWE-89: Improper Neutralization")
    sev, score, cwe_id, cwe_label = sources._primary_cvss({"metrics": {}})
    check("no metrics -> (None, None, None, None)",
          sev is None and score is None and cwe_id is None and cwe_label is None)
    both = {"cvssMetricV40": [{"type": "Primary", "cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}],
            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}
    check("v3.1 preferred over v4.0", sources._nvd_metric(both) == ("HIGH", 7.5, "3.1"))
    only4 = {"cvssMetricV40": both["cvssMetricV40"],
             "cvssMetricV30": [{"type": "Primary", "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]}
    check("v4.0 preferred over v3.0", sources._nvd_metric(only4) == ("CRITICAL", 9.3, "4.0"))
    banded = {"cvssMetricV30": [{"cvssData": {"baseScore": 7.0}}]}
    check("score-only -> v3 band", sources._nvd_metric(banded) == ("HIGH", 7.0, "3.0"))
    none = {"cvssMetricV31": [{"cvssData": {"baseScore": 0.0, "baseSeverity": "NONE"}}]}
    check("NONE -> null", sources._nvd_metric(none)[0] is None)
    check("is_ai_text machine learning", sources.is_ai_text("machine learning pipeline"))
    check("is_ai_text plain", not sources.is_ai_text("SQL injection in login"))
    check("layer_of_text returns an id", isinstance(sources.layer_of_text("vLLM server"), str))


def test_osv():
    print("sources.dedupe_advisories / _advisory_row / osv_fixed")
    pysec = {"id": "PYSEC-2026-1", "aliases": ["CVE-2026-9", "GHSA-aaaa"],
             "published": "2026-10-15T00:00:00Z"}
    ghsa = {"id": "GHSA-aaaa", "aliases": ["CVE-2026-9"], "summary": "vLLM: DoS",
            "published": "2026-10-05T00:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
            "affected": [{"ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "0.6.2"}]}]}]}
    via_cve = {"id": "GHSA-bbbb", "aliases": ["CVE-2026-9"], "published": "2026-10-20T00:00:00Z"}
    other = {"id": "GHSA-cccc", "aliases": ["CVE-2026-10"], "published": "2026-10-01T00:00:00Z",
             "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    groups = sources.dedupe_advisories([pysec, ghsa, via_cve, other])
    check("PYSEC+GHSA (+shared CVE alias) merged", sorted(len(g) for g in groups) == [1, 3])
    row = sources._advisory_row(next(g for g in groups if len(g) == 3), "PyPI:vllm", "inference")
    check("row prefers GHSA with summary", row["id"] == "GHSA-aaaa" and row["summary"] == "vLLM: DoS")
    check("row takes earliest published", row["published"] == "2026-10-05")
    check("row CVE + severity", row["cve"] == "CVE-2026-9" and row["severity"].startswith("CVSS:3.1"))
    check("row layer", row["layer"] == "inference")
    check("fixed event in any duplicate -> fixed", row["fixed"] is True)
    check("introduced only -> not fixed", sources.osv_fixed([other]) is False)
    check("no affected -> not fixed", sources.osv_fixed([via_cve]) is False)
    check("package list has layers",
          all(len(p) == 3 and p[2] in {"mcp", "gateway", "inference", "mlops", "llmapp",
                                        "model", "cloud", "framework", "other"}
              for p in sources.OSV_PKGS))
    check("package list unique", len({p[:2] for p in sources.OSV_PKGS}) == len(sources.OSV_PKGS))


def test_cvss_settled():
    print("sources.cvss_settled")
    today = dt.date(2026, 10, 25)
    check("scored -> settled", sources.cvss_settled("HIGH", "2026-10-24", today))
    check("unscored + recent -> recheck", not sources.cvss_settled(None, "2026-10-01", today))
    check("unscored + old -> settled", sources.cvss_settled(None, "2025-01-01", today))
    check("no day -> settled", sources.cvss_settled(None, None, today))


def test_meta_shapes():
    print("sources.norm_meta")
    old, new_shape = sources.norm_meta({"CVE-2025-1": "2025-03-01"})
    check("old shape -> {d}", old == {"CVE-2025-1": {"d": "2025-03-01"}} and not new_shape)
    rec = {"d": "2025-03-01", "layer": "llmapp", "sev": "HIGH", "score": 8.8,
           "cvssV": "3.1", "sevSrc": "cna", "cwe": "CWE-94", "cna": "GitHub_M",
           "product": "langflow-ai langflow"}
    new, new_shape = sources.norm_meta({"CVE-2025-1": rec})
    check("new shape kept", new["CVE-2025-1"] is rec and new_shape)
    check("empty", sources.norm_meta(None) == ({}, False))
    check("days_between", sources.days_between("2025-03-01", "2025-05-05") == 65)
    check("days_between bad -> None", sources.days_between("", "2025-05-05") is None)


def test_kev():
    print("sources.kev_entries")
    vulns = [
        {"cveID": "CVE-2025-3248", "vendorProject": "Langflow", "product": "Langflow",
         "vulnerabilityName": "Langflow Missing Authentication", "dateAdded": "2025-05-05",
         "shortDescription": "code injection", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2025-9999", "vendorProject": "Acme", "product": "SmartLLM",
         "vulnerabilityName": "x", "dateAdded": "2025-06-01", "shortDescription": "",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2024-1", "vendorProject": "Microsoft", "product": "Windows",
         "vulnerabilityName": "x", "dateAdded": "2024-01-01", "shortDescription": ""},
    ]
    for ids in ({"CVE-2025-3248": "2025-04-07"},
                {"CVE-2025-3248": {"d": "2025-04-07", "layer": "llmapp"}}):
        meta, _ = sources.norm_meta(ids)
        entries, n = sources.kev_entries(
            vulns, meta, ai_match=lambda t: "LLM" in t, layer_fn=lambda t: "other")
        by = {e["cve"]: e for e in entries}
        shape = "new" if isinstance(ids["CVE-2025-3248"], dict) else "old"
        check(f"[{shape}] aiCount = meta + text match", n == 2)
        lf = by["CVE-2025-3248"]
        check(f"[{shape}] published + daysToKev",
              lf["published"] == "2025-04-07" and lf["daysToKev"] == 28)
        check(f"[{shape}] layer from meta or fallback",
              lf["layer"] == ("llmapp" if shape == "new" else "other"))
        tx = by["CVE-2025-9999"]
        check(f"[{shape}] text-flagged: layer via classifier, no publish day",
              tx["ai"] and tx["layer"] == "other" and tx["published"] is None
              and tx["daysToKev"] is None and tx["ransomware"])
        check(f"[{shape}] non-AI has null layer", not by["CVE-2024-1"]["ai"]
              and by["CVE-2024-1"]["layer"] is None)
        check(f"[{shape}] newest first", entries[0]["cve"] == "CVE-2025-9999")


def test_epss():
    print("sources.parse_epss_api / parse_epss_csv")
    d = {"status": "OK", "data": [
        {"cve": "CVE-2025-3248", "epss": "0.999930000", "percentile": "0.999870000", "date": "2026-10-25"},
        {"cve": "CVE-2024-37032", "epss": "0.896330000", "percentile": "0.997850000", "date": "2026-10-25"},
        {"cve": "CVE-bad", "epss": "x", "percentile": "0.1", "date": "2026-10-25"}]}
    scores, day = sources.parse_epss_api(d)
    check("api: floats", scores["CVE-2025-3248"] == {"epss": 0.99993, "pct": 0.99987})
    check("api: bad row skipped", "CVE-bad" not in scores and len(scores) == 2)
    check("api: modelDate", day == "2026-10-25")
    check("api: empty", sources.parse_epss_api({"data": []}) == ({}, None))
    text = ("#model_version:v2026.06.15,score_date:2026-10-25T12:03:13Z\n"
            "cve,epss,percentile\nCVE-1999-0001,0.04753,0.91816\n"
            "CVE-2025-3248,0.99993,0.99987\n")
    scores, day = sources.parse_epss_csv(text, {"CVE-2025-3248"})
    check("csv: wanted only + modelDate",
          scores == {"CVE-2025-3248": {"epss": 0.99993, "pct": 0.99987}} and day == "2026-10-25")


def test_severity():
    print("sources.pick_sev / needs_nvd / severity_payload")
    today = dt.date(2026, 10, 25)
    rec_cna = {"d": "2026-09-01", "layer": "llmapp", "sev": "HIGH", "sevSrc": "cna", "cwe": "CWE-94"}
    rec_adp = {"d": "2026-09-02", "layer": "mcp", "sev": "CRITICAL", "sevSrc": "adp", "cwe": None}
    rec_none = {"d": "2026-10-20", "layer": "mcp", "sev": None, "cwe": None}
    rec_old = {"d": "2020-01-01", "layer": "framework", "sev": None, "cwe": None}
    nvd_new = {"sev": "MEDIUM", "score": 5.0, "v": "3.1", "cwe": "CWE-22",
               "cweLabel": "CWE-22", "done": True}
    legacy = {"sev": "HIGH", "score": 7.5, "cwe": "CWE-79", "cweLabel": "CWE-79", "done": True}
    check("record sev wins over NVD", sources.pick_sev(rec_cna, nvd_new, True) == ("HIGH", "cna"))
    check("adp source kept", sources.pick_sev(rec_adp, None, True) == ("CRITICAL", "adp"))
    check("null record -> NVD", sources.pick_sev(rec_none, nvd_new, True) == ("MEDIUM", "nvd"))
    check("new shape: legacy cache sev not used", sources.pick_sev(rec_none, legacy, True) == (None, "none"))
    check("old shape: legacy cache sev used", sources.pick_sev({"d": "x"}, legacy, False) == ("HIGH", "nvd"))
    check("no data -> none", sources.pick_sev(rec_none, None, True) == (None, "none"))
    cache = {"B": nvd_new, "C": legacy}
    check("rated record -> no NVD query", not sources.needs_nvd("A", rec_cna, cache, True, today))
    check("unrated + settled new cache -> no query", not sources.needs_nvd("B", rec_old, cache, True, today))
    check("unrated + legacy cache -> refetch", sources.needs_nvd("C", rec_old, cache, True, today))
    check("old shape + legacy -> no refetch", not sources.needs_nvd("C", {"d": "2020-01-01"}, cache, False, today))
    check("uncached -> query", sources.needs_nvd("D", rec_none, cache, True, today))
    recent_unscored = {"D": {"sev": None, "v": None, "done": True}}
    check("recent unscored -> recheck", sources.needs_nvd("D", rec_none, recent_unscored, True, today))

    meta = {"A": rec_cna, "B": dict(rec_none), "C": rec_old, "E": rec_adp}
    p = sources.severity_payload(meta, cache, True)
    check("bySource", p["bySource"] == {"cna": 1, "adp": 1, "nvd": 1, "none": 1})
    check("rated/totals", p["rated"] == 3 and p["totals"] == {"HIGH": 1, "MEDIUM": 1, "CRITICAL": 1})
    check("layerTotals",
          p["layerTotals"]["mcp"] == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "UNRATED": 0}
          and p["layerTotals"]["framework"]["UNRATED"] == 1
          and p["layerTotals"]["llmapp"]["HIGH"] == 1)
    check("cwe: record first, NVD fallback (legacy cwe ok)",
          p["cwe"] == {"CWE-94": 1, "CWE-22": 1, "CWE-79": 1})
    check("cweNames from map", p["cweNames"]["CWE-94"] == "Code Injection")
    check("months span + aiTotal", p["aiTotal"] == 4 and p["months"][0]["m"] == "2026-09"
          and p["months"][-1]["m"] == "2026-10" and p["months"][0]["HIGH"] == 1
          and p["months"][0]["CRITICAL"] == 1 and p["months"][1]["MEDIUM"] == 1)
    old_meta, ns = sources.norm_meta({"C": "2020-01-01"})
    p = sources.severity_payload(old_meta, cache, ns)
    check("old shape payload", p["rated"] == 1 and p["bySource"]["nvd"] == 1
          and p["layerTotals"] == {"other": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "UNRATED": 0}})


def test_datadir():
    print("sources CVE_DATA_DIR / read_json / write_json / epss_wanted")
    old = sources.DATADIR
    with tempfile.TemporaryDirectory() as tmp:
        sources.DATADIR = tmp
        try:
            sources.write_json("ai_meta.json", {"ids": {"CVE-2025-1": {"d": "2025-01-01"}}})
            sources.write_json("kev.json", {"entries": [
                {"cve": "CVE-2025-2", "ai": True}, {"cve": "CVE-2025-3", "ai": False}]})
            check("write -> read under DATADIR",
                  json.load(open(os.path.join(tmp, "ai_meta.json")))["ids"]["CVE-2025-1"]["d"] == "2025-01-01")
            check("epss_wanted = ai_meta + AI KEV", sources.epss_wanted() == ["CVE-2025-1", "CVE-2025-2"])
            check("read_json missing -> default", sources.read_json("nope.json", 7) == 7)
        finally:
            sources.DATADIR = old


def test_kev_origin():
    print("sources.kev_entries origin/zeroDay + kev_by_year")
    vulns = [
        {"cveID": "CVE-2026-1", "vendorProject": "Fortinet", "product": "FortiOS",
         "dateAdded": "2026-03-02"},
        {"cveID": "CVE-2026-2", "vendorProject": "Microsoft", "product": "Windows",
         "dateAdded": "2026-04-01"},
        {"cveID": "CVE-2025-3", "vendorProject": "Langflow", "product": "Langflow",
         "dateAdded": "2026-01-10"},
        {"cveID": "CVE-2026-4", "vendorProject": "Acme", "product": "Router",
         "dateAdded": "2026-02-01"},
        {"cveID": "CVE-2026-5", "vendorProject": "Acme", "product": "Thing",
         "dateAdded": "2026-02-01"},
    ]
    records = {
        "CVE-2026-1": {"d": "2026-03-01", "origin": "edge"},
        "CVE-2026-2": {"d": "2026-03-01", "origin": "platform"},
        "CVE-2025-3": {"d": "2025-12-31", "origin": "ai", "layer": "llmapp"},
        "CVE-2026-5": {"d": "2026-02-03", "origin": "other"},
    }
    entries, n = sources.kev_entries(
        vulns, {}, records, ai_match=lambda t: False,
        layer_fn=lambda t: "other",
        origin_fn=lambda t: "edge" if "Router" in t else "other")
    by = {e["cve"]: e for e in entries}
    check("origin from lookup", by["CVE-2026-1"]["origin"] == "edge"
          and by["CVE-2026-2"]["origin"] == "platform")
    check("zeroDay: 1 day -> true", by["CVE-2026-1"]["zeroDay"] and by["CVE-2026-1"]["daysToKev"] == 1)
    check("zeroDay: 31 days -> false", not by["CVE-2026-2"]["zeroDay"])
    check("added before publication -> zeroDay", by["CVE-2026-5"]["daysToKev"] == -2
          and by["CVE-2026-5"]["zeroDay"])
    check("lookup AI origin flags ai + layer", n == 1 and by["CVE-2025-3"]["ai"]
          and by["CVE-2025-3"]["origin"] == "ai" and by["CVE-2025-3"]["layer"] == "llmapp")
    check("unknown CVE: classify_origin on text, no published",
          by["CVE-2026-4"]["origin"] == "edge" and by["CVE-2026-4"]["published"] is None
          and by["CVE-2026-4"]["zeroDay"] is False)
    mcp, _ = sources.kev_entries(vulns[:1], {"CVE-2026-1": {"d": "2026-03-01", "layer": "mcp"}},
                                 records, ai_match=lambda t: False)
    check("ai_meta mcp layer -> origin mcp", mcp[0]["origin"] == "mcp")
    nolookup, _ = sources.kev_entries(vulns[1:2], {}, None, ai_match=lambda t: False,
                                      origin_fn=lambda t: "ai")
    check("text origin 'ai' without AI flag -> other", nolookup[0]["origin"] == "other")
    y = sources.kev_by_year(entries)
    check("byYear added by dateAdded year", list(y) == ["2026"] and y["2026"]["added"] == 5)
    check("byYear zeroDay by publication year", y["2026"]["zeroDay"] == 2)
    late = sources.kev_by_year([{"added": "2026-01-01", "origin": "edge", "zeroDay": True,
                                 "published": "2025-12-31"}])
    check("zeroDay year = publication year", late["2025"] == {"added": 0, "zeroDay": 1, "origin": {}}
          and late["2026"]["zeroDay"] == 0)
    check("byYear origin", y["2026"]["origin"] == {"edge": 2, "platform": 1, "ai": 1, "other": 1})


def test_zerodays():
    print("sources.parse_zerodays / zerodays_payload")
    text = ("CVE,Vendor,Product,Type,Description,Date Discovered,Date Patched,Advisory\n"
            "CVE-2026-96951,Microsoft,Windows,Feature Bypass,x,???,2026-10-13,u\n"
            "CVE-2025-1,Apple,iOS,Memory Corruption,y,???,2025-02-01,u\n"
            "CVE-2025-1,Apple,iOS,dup,y,???,2025-02-01,u\n"
            "-,,,,,,,\n"
            ",,,,,,,\n"
            "CVE-2014-2,Adobe,Flash,UAF,z,???,???,u\n")
    rows = sources.parse_zerodays(text)
    check("rows: valid CVEs, deduped", [r["cve"] for r in rows] == ["CVE-2026-96951", "CVE-2025-1", "CVE-2014-2"])
    check("bad date -> None", rows[2]["date"] is None)
    try:
        sources.parse_zerodays("a,b\n1,2\n")
        check("layout change raises", False)
    except ValueError:
        check("layout change raises", True)
    p = sources.zerodays_payload(rows, {"CVE-2025-1": {"origin": "platform"}},
                                 {"CVE-2026-96951"}, origin_fn=lambda t: "other")
    check("byYear by Date Patched", p["byYear"] == {"2025": 1, "2026": 1} and p["total"] == 3)
    check("recent newest first, dated only", [r["cve"] for r in p["recent"]] == ["CVE-2026-96951", "CVE-2025-1"])
    check("origin + inKev", p["recent"][1]["origin"] == "platform" and p["recent"][0]["inKev"]
          and not p["recent"][1]["inKev"])


def test_malicious():
    print("sources.count_mal")
    text = ("2026-10-25T18:30:04.8Z,MAL-2026-18294\n"
            "2026-10-25T17:45:04.3Z,MAL-2025-1\n"
            "2026-10-25T17:45:04.3Z,MAL-2025-1\n"
            "2026-10-24T00:00:00Z,GHSA-xxxx-yyyy-zzzz\n"
            "2026-10-24T00:00:00Z,MAL-2024-7\n\n")
    years, ids = sources.count_mal(text)
    check("MAL ids only, unique, by id year", years == {"2024": 1, "2025": 1, "2026": 1} and len(ids) == 3)
    check("empty", sources.count_mal("") == ({}, set()))


def main():
    test_primary_cvss()
    test_osv()
    test_cvss_settled()
    test_meta_shapes()
    test_kev()
    test_kev_origin()
    test_zerodays()
    test_malicious()
    test_epss()
    test_severity()
    test_datadir()
    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

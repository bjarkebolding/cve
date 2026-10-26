#!/usr/bin/env python3
"""Score the current AI matcher (build.record_layer) against the hand-labeled
sample in tools/ai_labels.json. Reads the records from the local cvelistV5
clone (env CVE_CLONE_DIR, as build.py). No network.

Run:  python3 tools/eval_ai.py [-v]     (-v lists every disagreement)

Strata (see ai_labels.json "strataRule"): "flagged" = matched by the matcher at
labeling time, "suspect" = unmatched but hit SUSPECT_RE, "random" = the rest.
Precision/recall are estimated by scaling each stratum's confusion counts by
its population size ("pool"), so the rare-class recall is not inflated by the
oversampled strata. Small strata -> wide error bars, esp. "random".
"""
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
import build  # noqa: E402

# the keyword net that defined the "suspect" stratum when the sample was drawn
SUSPECT_RE = re.compile(
    r"\b(?:ai|a\.i\.|ml|llms?|gpt\w*|inference|neural|prompts?|copilot|chat ?bots?|agentic|"
    r"agents? (?:framework|platform|tool)|openai|claude|gemini|anthropic|mistral|hugging\w*|"
    r"embeddings?|vector (?:db|database|store|search)|tensors?|cuda|onnx|models? (?:training|"
    r"serving|inference|hub|zoo|registry|weights)|training data|dataset|deep|intelligen\w*|"
    r"smart assistant|voice assistant|speech|vision|recogni\w+|semantic|nlp|rag|chat\w*|"
    r"assistant)\b", re.I)


def predict(cid):
    """True/False from the record's matcher result; None if not in the clone."""
    path = build.record_path(cid)
    rec = build.load_record(path) if path else None
    if not rec:
        return None
    c = rec.get("containers") or {}
    return build.record_layer(c) is not None


def main():
    verbose = "-v" in sys.argv
    with open(os.path.join(BASE, "tools", "ai_labels.json")) as f:
        lab = json.load(f)
    labels, strata, pool = lab["labels"], lab["strata"], lab["pool"]
    preds = {cid: predict(cid) for cid in labels}
    missing = [c for c, p in preds.items() if p is None]

    print(f"labels: {len(labels)} (labeled {lab.get('labeledAt')}), missing records: {len(missing)}")
    print(f"{'stratum':<9} {'pool':>7} {'n':>4} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}")
    tot = [0, 0, 0, 0]
    for st in pool:
        cm = [0, 0, 0, 0]
        for cid, truth in labels.items():
            p = preds[cid]
            if strata.get(cid) != st or p is None:
                continue
            cm[(0 if truth else 1) if p else (2 if truth else 3)] += 1
        tot = [a + b for a, b in zip(tot, cm)]
        print(f"{st:<9} {pool[st]:>7} {sum(cm):>4} {cm[0]:>4} {cm[1]:>4} {cm[2]:>4} {cm[3]:>4}")
    tp, fp, fn, _ = tot
    raw_p = tp / (tp + fp) if tp + fp else float("nan")
    raw_r = tp / (tp + fn) if tp + fn else float("nan")
    print(f"raw (unweighted sample): precision {raw_p:.3f}  recall {raw_r:.3f}")
    prec, rec, n, _ = build.stratified_eval(labels, strata, pool, lambda c: preds.get(c))
    print(f"population-weighted:     precision {prec}  recall {rec}  (n={n})")

    if verbose:
        for cid, truth in sorted(labels.items()):
            if preds[cid] is not None and preds[cid] != truth:
                kind = "FP" if preds[cid] else "FN"
                print(f"  {kind} {strata.get(cid):<8} {cid}")


if __name__ == "__main__":
    main()

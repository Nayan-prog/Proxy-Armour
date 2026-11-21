"""Detection accuracy on the synthetic corpus.

    python -m eval.run_detection

Configs: (a) regex, (b) regex+entropy, (c) regex+entropy+AST (Proxy Armour),
(d) detect-secrets (Yelp) with its default plugins and filters, as an external baseline.

Matching (eval/common.py): a prediction matches a gold span when they overlap by
>= 50% of the longer span; overlapping predictions from different detectors are
merged first (one secret found twice is one prediction). Overall metrics are
label-agnostic (what matters for DLP is that the value is caught); per-type recall
is attributed to the gold type, false positives to the predicted label.
FPR = share of hard-negative samples (no gold spans) with at least one alarm.

detect-secrets is line-based and its `secret_value` is often a fragment (a regex
capture such as "ghp" for GitHub tokens, only the BEGIN header for PEM keys), so it
is scored at LINE level: a gold span is caught if detect-secrets reported any line
that span is on, and a report is a false positive only if its line holds no gold
span - more lenient than the span rule used for our configs. It is run like `detect-secrets scan` (SecretsCollection.scan_file on
a temp file with a realistic extension), NOT via `scan_line`, whose ad-hoc mode
reports every word regardless of entropy limits. It does not look for PII, so a
secrets-only row is reported too.
Redundant predictions nested inside a longer one are merged before scoring, for
every config alike (the proxy redacts the union anyway).
Detector thresholds are the committed defaults - nothing is tuned on this corpus.
"""
from collections import defaultdict
from pathlib import Path

from armour_config import settings
from app.detectors.ast_detector import AstDetector
from app.detectors.engine import scan_text
from app.detectors.entropy_detector import EntropyDetector
from app.detectors.regex_detector import RegexDetector
from eval.common import Counts, md_table, pct, write_csv, write_fragment
from eval.generate import load

PII = {"EMAIL", "PHONE_IN", "AADHAAR", "PAN", "CREDIT_CARD"}
E = settings.detectors.entropy
ENTROPY = EntropyDetector(min_length=E.min_length, base64_threshold=E.base64_threshold,
                          hex_threshold=E.hex_threshold, min_digits=E.min_digits)
CONFIGS = {
    "(a) regex": [RegexDetector()],
    "(b) regex+entropy": [RegexDetector(), ENTROPY],
    "(c) regex+entropy+AST": [RegexDetector(), ENTROPY, AstDetector()],
}
DS = "(d) detect-secrets"
ORDER = list(CONFIGS) + [DS]


def armour_predict(detectors):
    def predict(text, category=None):
        return [{"start": f["start"], "end": f["end"], "type": f["type"]} for f in scan_text(text, detectors)]
    return predict


EXTENSION = {"json_config": ".json", "env_text": ".env", "prose_pii": ".txt", "prose_keys": ".txt",
             "hard_negative": ".txt"}           # py_* -> .py


def detect_secrets_predict(text: str, category: str) -> list[dict]:
    """Run detect-secrets the way `detect-secrets scan` does: SecretsCollection.scan_file
    on a file with a realistic extension (default plugins AND filters apply).
    NOT `scan_line`: that is the ad-hoc mode, which reports every word regardless of
    entropy limits ("the", "is", ...)."""
    import tempfile

    from detect_secrets import SecretsCollection
    from detect_secrets.settings import default_settings

    lines = text.splitlines(keepends=True)
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line))
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"sample{EXTENSION.get(category, '.py')}"
        path.write_text(text, encoding="utf-8")
        with default_settings():
            collection = SecretsCollection()
            collection.scan_file(str(path))
            found = [secret for _, secret in collection]
    preds = []
    for secret in found:
        line_index = secret.line_number - 1
        line = lines[line_index] if 0 <= line_index < len(lines) else ""
        offset = starts[line_index] if 0 <= line_index < len(lines) else 0
        # line-level: detect-secrets' secret_value is often a fragment (a regex
        # capture such as "ghp" for GitHub tokens, the BEGIN header for PEM keys),
        # so the whole reported line is the prediction (scored with line_level=True)
        start, end = offset, offset + len(line.rstrip("\r\n"))
        preds.append({"start": start, "end": end, "type": f"DS:{secret.type}"})
    return preds


def evaluate(samples, predict, line_level=False):
    all_types, secrets_only = Counts(), Counts()
    by_category: dict[str, Counts] = defaultdict(Counts)
    for s in samples:
        preds = predict(s["text"], s["category"])
        all_types.add_sample(s["spans"], preds, line_level)
        secrets_only.add_sample([g for g in s["spans"] if g["type"] not in PII],
                                [p for p in preds if p["type"] not in PII], line_level)
        by_category[s["category"]].add_sample(s["spans"], preds, line_level)
    return all_types, secrets_only, by_category


def main():
    predictors = {name: armour_predict(d) for name, d in CONFIGS.items()}
    predictors[DS] = detect_secrets_predict

    overall_rows, type_rows, fp_rows, cat_rows = [], [], [], []
    results = {}
    for split in ("test", "dev"):
        samples = load(split)
        for name in ORDER:
            all_c, sec_c, cats = evaluate(samples, predictors[name], line_level=(name == DS))
            results[(split, name)] = (all_c, sec_c, cats)
            for scope, c in (("all types", all_c), ("secrets only", sec_c)):
                overall_rows.append({"split": split, "config": name, "scope": scope, **c.metrics()})
            if split != "test":
                continue
            gold_types = sorted(set(all_c.tp_by_type) | set(all_c.fn_by_type))
            for t in gold_types:
                tp, fn = all_c.tp_by_type.get(t, 0), all_c.fn_by_type.get(t, 0)
                type_rows.append({"config": name, "type": t, "support": tp + fn, "tp": tp, "fn": fn,
                                  "recall": tp / (tp + fn)})
            for label, n in sorted(all_c.fp_by_label.items(), key=lambda x: -x[1]):
                fp_rows.append({"config": name, "predicted_label": label, "false_positives": n})
            for cat, c in sorted(cats.items()):
                m = c.metrics()
                cat_rows.append({"config": name, "category": cat, "tp": m["tp"], "fn": m["fn"], "fp": m["fp"],
                                 "recall": m["recall"]})

    write_csv("detection_overall.csv", overall_rows)
    write_csv("detection_per_type.csv", type_rows)
    write_csv("detection_false_positives.csv", fp_rows, fieldnames=["config", "predicted_label", "false_positives"])
    write_csv("detection_by_category.csv", cat_rows)

    # ---------------------------------------------------------------- markdown
    test_n = len(load("test"))
    gold_n = sum(len(s["spans"]) for s in load("test"))
    neg_n = sum(1 for s in load("test") if not s["spans"])

    def overall_table(split, scope):
        rows = []
        for r in overall_rows:
            if r["split"] == split and r["scope"] == scope:
                rows.append([r["config"], r["tp"], r["fp"], r["fn"], pct(r["precision"]), pct(r["recall"]),
                             pct(r["f1"]), pct(r["fpr"]), pct(r["fnr"])])
        return md_table(["Configuration", "TP", "FP", "FN", "Precision", "Recall", "F1", "FPR", "FNR"], rows)

    types = sorted({r["type"] for r in type_rows},
                   key=lambda t: (-next(r["support"] for r in type_rows if r["type"] == t), t))
    per_type = []
    for t in types:
        support = next(r["support"] for r in type_rows if r["type"] == t)
        recalls = [pct(next(r["recall"] for r in type_rows if r["type"] == t and r["config"] == c), 0) for c in ORDER]
        per_type.append([f"`{t}`{' †' if support < 5 else ''}", support, *recalls])

    cats = sorted({r["category"] for r in cat_rows})
    per_cat = []
    for cat in cats:
        row = [f"`{cat}`"]
        for c in ORDER:
            r = next(x for x in cat_rows if x["category"] == cat and x["config"] == c)
            row.append(f"{pct(r['recall'], 0)} ({r['fp']} FP)" if r["tp"] + r["fn"] else f"— ({r['fp']} FP)")
        per_cat.append(row)

    fp_table = []
    for c in ORDER:
        labels = [f"`{r['predicted_label']}` {r['false_positives']}" for r in fp_rows if r["config"] == c]
        fp_table.append([c, sum(r["false_positives"] for r in fp_rows if r["config"] == c), ", ".join(labels) or "—"])

    md = f"""
### Detection accuracy (test split: {test_n} samples, {gold_n} labelled spans, {neg_n} hard negatives)

**Table D1 - all types** (configs a-c: span-level, overlap ≥ 50% of the longer span; (d): line-level, see Method)

{overall_table("test", "all types")}

**Table D2 - secrets only** (PII types excluded from gold and predictions; detect-secrets does not target PII)

{overall_table("test", "secrets only")}

**Table D3 - recall by ground-truth type** († support < 5: indicative only)

{md_table(["Type", "n", *ORDER], per_type)}

**Table D4 - recall (and false positives) by sample category**

{md_table(["Category", *ORDER], per_cat)}

**Table D5 - false positives by predicted label**

{md_table(["Configuration", "FP", "Labels"], fp_table, align="lrl")}

<details><summary>Dev split (sanity check only - nothing was tuned on either split)</summary>

{overall_table("dev", "all types")}

</details>
"""
    write_fragment("detection.md", md)
    print(md)


if __name__ == "__main__":
    main()

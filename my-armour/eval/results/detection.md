### Detection accuracy (test split: 183 samples, 207 labelled spans, 25 hard negatives)

**Table D1 - all types** (configs a-c: span-level, overlap ≥ 50% of the longer span; (d): line-level, see Method)

| Configuration | TP | FP | FN | Precision | Recall | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| (a) regex | 112 | 0 | 95 | 100.0% | 54.1% | 70.2% | 0.0% | 45.9% |
| (b) regex+entropy | 137 | 0 | 70 | 100.0% | 66.2% | 79.7% | 0.0% | 33.8% |
| (c) regex+entropy+AST | 183 | 0 | 24 | 100.0% | 88.4% | 93.8% | 0.0% | 11.6% |
| (d) detect-secrets | 89 | 2 | 118 | 97.8% | 43.0% | 59.7% | 8.0% | 57.0% |

**Table D2 - secrets only** (PII types excluded from gold and predictions; detect-secrets does not target PII)

| Configuration | TP | FP | FN | Precision | Recall | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| (a) regex | 49 | 0 | 95 | 100.0% | 34.0% | 50.8% | 0.0% | 66.0% |
| (b) regex+entropy | 74 | 0 | 70 | 100.0% | 51.4% | 67.9% | 0.0% | 48.6% |
| (c) regex+entropy+AST | 120 | 0 | 24 | 100.0% | 83.3% | 90.9% | 0.0% | 16.7% |
| (d) detect-secrets | 89 | 2 | 55 | 97.8% | 61.8% | 75.7% | 3.6% | 38.2% |

**Table D3 - recall by ground-truth type** († support < 5: indicative only)

| Type | n | (a) regex | (b) regex+entropy | (c) regex+entropy+AST | (d) detect-secrets |
| --- | ---: | ---: | ---: | ---: | ---: |
| `HARDCODED_SECRET` | 94 | 0% | 26% | 74% | 54% |
| `EMAIL` | 18 | 100% | 100% | 100% | 0% |
| `AADHAAR` | 13 | 100% | 100% | 100% | 0% |
| `CREDIT_CARD` | 12 | 100% | 100% | 100% | 0% |
| `PAN` | 12 | 100% | 100% | 100% | 0% |
| `PHONE_IN` | 8 | 100% | 100% | 100% | 0% |
| `SLACK_TOKEN` | 8 | 100% | 100% | 100% | 100% |
| `AWS_KEY` | 7 | 100% | 100% | 100% | 100% |
| `GITHUB_TOKEN` | 7 | 100% | 100% | 100% | 100% |
| `ANTHROPIC_KEY` | 6 | 100% | 100% | 100% | 17% |
| `STRIPE_KEY` | 6 | 83% | 100% | 100% | 67% |
| `DB_CONNECTION_STRING` | 5 | 100% | 100% | 100% | 80% |
| `PRIVATE_KEY` † | 4 | 100% | 100% | 100% | 100% |
| `GOOGLE_API_KEY` † | 3 | 100% | 100% | 100% | 0% |
| `JWT` † | 3 | 100% | 100% | 100% | 100% |
| `OPENAI_KEY` † | 1 | 100% | 100% | 100% | 0% |

**Table D4 - recall (and false positives) by sample category**

| Category | (a) regex | (b) regex+entropy | (c) regex+entropy+AST | (d) detect-secrets |
| --- | ---: | ---: | ---: | ---: |
| `env_text` | 38% (0 FP) | 68% (0 FP) | 68% (0 FP) | 53% (0 FP) |
| `hard_negative` | — (0 FP) | — (0 FP) | — (0 FP) | — (2 FP) |
| `json_config` | 58% (0 FP) | 65% (0 FP) | 100% (0 FP) | 50% (0 FP) |
| `prose_keys` | 90% (0 FP) | 100% (0 FP) | 100% (0 FP) | 70% (0 FP) |
| `prose_pii` | 100% (0 FP) | 100% (0 FP) | 100% (0 FP) | 0% (0 FP) |
| `py_assign` | 8% (0 FP) | 29% (0 FP) | 100% (0 FP) | 54% (0 FP) |
| `py_comment` | 11% (0 FP) | 11% (0 FP) | 11% (0 FP) | 11% (0 FP) |
| `py_dict` | 13% (0 FP) | 33% (0 FP) | 100% (0 FP) | 93% (0 FP) |
| `py_fstring` | 33% (0 FP) | 44% (0 FP) | 44% (0 FP) | 44% (0 FP) |
| `py_kwargs` | 20% (0 FP) | 33% (0 FP) | 100% (0 FP) | 80% (0 FP) |

**Table D5 - false positives by predicted label**

| Configuration | FP | Labels |
| --- | ---: | --- |
| (a) regex | 0 | — |
| (b) regex+entropy | 0 | — |
| (c) regex+entropy+AST | 0 | — |
| (d) detect-secrets | 2 | `DS:Secret Keyword` 2 |

<details><summary>Dev split (sanity check only - nothing was tuned on either split)</summary>

| Configuration | TP | FP | FN | Precision | Recall | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| (a) regex | 283 | 2 | 204 | 99.3% | 58.1% | 73.3% | 0.0% | 41.9% |
| (b) regex+entropy | 339 | 0 | 148 | 100.0% | 69.6% | 82.1% | 0.0% | 30.4% |
| (c) regex+entropy+AST | 440 | 0 | 47 | 100.0% | 90.3% | 94.9% | 0.0% | 9.7% |
| (d) detect-secrets | 206 | 23 | 281 | 90.0% | 42.3% | 57.5% | 23.7% | 57.7% |

</details>

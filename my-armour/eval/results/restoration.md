### Restoration (test split, through the mock LLM, real proxy hooks in-process)

**Table R1 - honest LLM** (restoration = distinct issued placeholders restored; survival =
issued placeholders present in the LLM reply before restoration; fidelity = client answer
byte-identical to the mock's answer to the *unprotected* prompt; leak alarms on honest
traffic are false alarms; syntax = restored Python code that parses / tokenized Python samples)

| Mode | Requests | Blocked | Tokenized | Allowed | Placeholders | Restored | Survival | Fidelity | Leak alarms | Syntax OK |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| JSON | 183 | 26 | 115 | 42 | 133 | 100.0% | 100.0% | 100.0% | 0 | 59/59 |
| SSE stream | 183 | 26 | 115 | 42 | 133 | 100.0% | 100.0% | 100.0% | 0 | 59/59 |

**Table R2 - integrity under a mangling LLM** (integrity = client answer equals the oracle:
only exact issued placeholders restored, damaged ones left visibly unrestored; counters =
missing/unknown/leak reported exactly as expected; wrong restorations = an original value
placed where no issued placeholder was)

| Mangling | What the LLM did | Mode | Flows | Integrity | Counters correct | Wrong restorations |
| --- | --- | :---: | ---: | ---: | ---: | ---: |
| `drop` | one placeholder removed | JSON | 115 | 100.0% | 100.0% | 0 |
| `drop` | one placeholder removed | SSE | 115 | 100.0% | 100.0% | 0 |
| `alter_case` | one placeholder lower-cased | JSON | 115 | 100.0% | 100.0% | 0 |
| `alter_case` | one placeholder lower-cased | SSE | 115 | 100.0% | 100.0% | 0 |
| `truncate` | last hex digit cut | JSON | 115 | 100.0% | 100.0% | 0 |
| `truncate` | last hex digit cut | SSE | 115 | 100.0% | 100.0% | 0 |
| `split` | space inserted inside | JSON | 115 | 100.0% | 100.0% | 0 |
| `split` | space inserted inside | SSE | 115 | 100.0% | 100.0% | 0 |
| `duplicate` | one placeholder repeated | JSON | 115 | 100.0% | 100.0% | 0 |
| `duplicate` | one placeholder repeated | SSE | 115 | 100.0% | 100.0% | 0 |
| `forge` | never-issued PA_ string added | JSON | 115 | 100.0% | 100.0% | 0 |
| `forge` | never-issued PA_ string added | SSE | 115 | 100.0% | 100.0% | 0 |
| `leak` | an original value returned | JSON | 115 | 100.0% | 100.0% | 0 |
| `leak` | an original value returned | SSE | 115 | 100.0% | 100.0% | 0 |

Leak check: in 1 of 115 leak flows the returned value had never been tokenized (a detector miss - it was already sent in plaintext); the leak check covers tokenized originals only, so no alarm is expected there and none was raised. Every leak of a tokenized value was flagged.

### Latency (500 measured requests per cell after 20 warm-up; non-streaming OpenAI chat; payload = Python code with 3 secrets)

**Table L1 - latency added by Proxy Armour (ms)**. Direct = client → mock LLM; Armour = client →
mitmproxy + Proxy Armour → mock LLM. Added = Armour − direct (mean / median / p95 of each
distribution). "vs plain mitmproxy" = Armour − mitmproxy without the addon (median), i.e. the
cost of scanning/tokenizing/restoring on top of TLS interception. Fail-closed = share of requests
the proxy blocked with 503 because the scanner did not answer within `scanner_timeout` (5 s) - the
designed overload behaviour (never forward unscanned). Other errors = any other non-200 on the
three paths (e.g. 502 when an upstream connection drops under overload); the mock LLM uses a 75 s
keep-alive like typical provider load balancers. Latency columns cover successful requests
("n/a" when fewer than 30 succeeded). Added values are differences between the two distributions'
statistics, not per-request deltas - so with many clients, where the direct path's own tail is wide,
added p95 can be smaller than added median.

| Payload | Clients | Direct median | Armour median | Added mean | Added median | Added p95 | vs plain mitmproxy | Armour req/s | Fail-closed | Other errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 KiB | 1 | 4.5 | 42.3 | **39.3** | **37.8** | **69.2** | 30.0 | 21 | 0.0% | 0 |
| 1 KiB | 10 | 32.8 | 284.4 | **267.7** | **251.6** | **455.7** | 237.7 | 31 | 0.0% | 0 |
| 1 KiB | 50 | 350.6 | 1570.2 | **1106.3** | **1219.5** | **1802.8** | 1050.3 | 28 | 0.0% | 0 |
| 10 KiB | 1 | 3.6 | 73.1 | **79.6** | **69.5** | **131.9** | 65.8 | 12 | 0.0% | 0 |
| 10 KiB | 10 | 24.1 | 575.3 | **602.8** | **551.2** | **875.1** | 530.9 | 15 | 0.0% | 0 |
| 10 KiB | 50 | 336.1 | 4635.2 | **4252.9** | **4299.2** | **6160.0** | 4119.0 | 10 | 0.0% | 0 |
| 50 KiB | 1 | 4.7 | 299.8 | **315.0** | **295.1** | **459.7** | 290.6 | 3 | 0.0% | 0 |
| 50 KiB | 10 | 26.0 | 2615.1 | **2698.3** | **2589.1** | **3513.8** | 2569.4 | 3 | 0.0% | 0 |
| 50 KiB | 50 | 363.0 | n/a (0 ok) | n/a (0 ok) | n/a (0 ok) | n/a (0 ok) | n/a (0 ok) | 0 | 100.0% | 0 |

**Table L2 - per-stage timing inside the proxy, median ms (1 client)**. detect and verify include the
HTTP round trip to the scanner service; the in-process row is the detectors alone on the same text.

| Payload | parse | detect | of which in-process detection compute | tokenize | verify | restore |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 KiB | 0.09 | 14.01 | 11.66 | 0.23 | 13.79 | 1.13 |
| 10 KiB | 0.09 | 29.59 | 36.81 | 0.27 | 29.35 | 4.65 |
| 50 KiB | 0.19 | 125.97 | 118.28 | 0.66 | 126.42 | 26.28 |

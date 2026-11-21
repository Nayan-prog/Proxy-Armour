"""Run every benchmark and write eval/results/RESULTS.md.

    python -m eval.run_all             # full run (~20 min; latency dominates)
    python -m eval.run_all --quick     # small latency run for a smoke test
"""
import subprocess
import sys

from eval import generate, report, run_detection, run_restoration


def main():
    quick = "--quick" in sys.argv
    generate.write()
    run_detection.main()
    run_restoration.main()
    latency = [sys.executable, "-m", "eval.run_latency"]
    if quick:
        latency += ["--requests", "30", "--sizes", "1,10", "--concurrency", "1,10"]
    subprocess.run(latency, check=True)        # separate process: clean event loop, own services
    report.main()


if __name__ == "__main__":
    main()

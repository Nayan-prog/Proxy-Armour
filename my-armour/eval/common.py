"""Shared evaluation helpers: span matching, metrics, environment capture, table output."""
import csv
import math
import os
import platform
import statistics
import subprocess
import sys
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"

# tables contain ≥, †, — : print UTF-8 even on a cp1252 Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
MIN_OVERLAP = 0.5   # a prediction matches a gold span if they overlap >= 50% of the LONGER span


def overlap_ok(a: tuple[int, int], b: tuple[int, int]) -> bool:
    inter = min(a[1], b[1]) - max(a[0], b[0])
    return inter > 0 and inter >= MIN_OVERLAP * max(a[1] - a[0], b[1] - b[0])


def nested(inner: tuple[int, int], outer: tuple[int, int]) -> bool:
    """inner lies mostly (>= 50% of its own length) inside outer."""
    inter = min(inner[1], outer[1]) - max(inner[0], outer[0])
    return inter > 0 and inter >= MIN_OVERLAP * (inner[1] - inner[0])


def merge_predictions(preds: list[dict]) -> list[dict]:
    """Collapse redundant predictions before scoring, identically for every config.

    Several detectors may report the same value (regex + entropy on a GitHub token),
    and the entropy detector also flags the parts of a JWT or the lines of a PEM key
    that regex reported as a whole. A prediction lying mostly inside a longer one is
    merged into it - the proxy redacts the union anyway (engine.merge_overlaps) - so
    one secret is one prediction, not one TP plus several FPs.
    """
    out: list[dict] = []
    for p in sorted(preds, key=lambda p: -(p["end"] - p["start"])):          # longest first
        if not any(nested((p["start"], p["end"]), (q["start"], q["end"])) for q in out):
            out.append(p)
    return sorted(out, key=lambda p: p["start"])


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    neg_samples: int = 0          # samples with no gold spans
    neg_samples_flagged: int = 0  # ... where the detector raised anything
    tp_by_type: dict = field(default_factory=dict)
    fn_by_type: dict = field(default_factory=dict)
    fp_by_label: dict = field(default_factory=dict)

    def add_sample(self, gold: list[dict], preds: list[dict], line_level: bool = False) -> None:
        """line_level: predictions are whole lines; a gold span is caught if any
        prediction's line intersects it (used for the line-based detect-secrets)."""
        preds = merge_predictions(preds)
        match_fn = (lambda a, b: a[0] < b[1] and b[0] < a[1]) if line_level else overlap_ok
        used = set()
        for g in gold:
            match = next((i for i, p in enumerate(preds) if i not in used
                          and match_fn((g["start"], g["end"]), (p["start"], p["end"]))), None)
            if match is None:
                self.fn += 1
                self.fn_by_type[g["type"]] = self.fn_by_type.get(g["type"], 0) + 1
            else:
                used.add(match)
                self.tp += 1
                self.tp_by_type[g["type"]] = self.tp_by_type.get(g["type"], 0) + 1
        for i, p in enumerate(preds):
            if i not in used:
                self.fp += 1
                self.fp_by_label[p["type"]] = self.fp_by_label.get(p["type"], 0) + 1
        if not gold:
            self.neg_samples += 1
            self.neg_samples_flagged += bool(preds)

    def metrics(self) -> dict:
        p = self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0
        r = self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        fpr = self.neg_samples_flagged / self.neg_samples if self.neg_samples else 0.0
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "precision": p, "recall": r, "f1": f1,
                "fpr": fpr, "fnr": 1 - r if self.tp + self.fn else 0.0}


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile (q in 0..100): the ceil(q/100 * n)-th smallest value.
    (No round(): Python rounds half to even, which picked the next rank up.)"""
    s = sorted(values)
    k = max(0, min(len(s) - 1, math.ceil(q / 100 * len(s)) - 1))
    return s[k]


def summary(values: list[float]) -> dict:
    return {"mean": statistics.fmean(values), "median": statistics.median(values),
            "p95": percentile(values, 95), "n": len(values)}


# ------------------------------------------------------------------ output

def write_csv(name: str, rows: list[dict], fieldnames: list[str] | None = None) -> Path:
    """rows may be empty (e.g. no false positives at all): then only the header is written."""
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / name
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames or (list(rows[0]) if rows else []))
        writer.writeheader()
        for row in rows:
            writer.writerow({k: (f"{v:.4f}" if isinstance(v, float) else v) for k, v in row.items()})
    return path


def md_table(headers: list[str], rows: list[list], align: str | None = None) -> str:
    align = align or "l" + "r" * (len(headers) - 1)
    sep = ["---:" if a == "r" else ":---:" if a == "c" else "---" for a in align]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(sep) + " |"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def write_fragment(name: str, markdown: str) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / name
    path.write_text(markdown.strip() + "\n", encoding="utf-8")
    return path


def pct(x: float, digits: int = 1) -> str:
    return f"{x * 100:.{digits}f}%"


# ------------------------------------------------------------------ environment

def _cpu_name() -> str:
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            return winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        except OSError:
            pass
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _ram_gb() -> float:
    if sys.platform == "win32":
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(MemoryStatus)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
        return status.ullTotalPhys / 2**30
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30


def environment() -> dict:
    def version(pkg):
        try:
            return metadata.version(pkg)
        except metadata.PackageNotFoundError:
            return "not installed"
    try:
        # "-dirty": measured with uncommitted changes on top of that commit
        commit = subprocess.run(["git", "describe", "--always", "--dirty"], capture_output=True, text=True,
                                cwd=RESULTS.parent.parent).stdout.strip()
    except OSError:
        commit = "unknown"
    return {
        "CPU": _cpu_name(),
        "Logical cores": os.cpu_count(),
        "RAM": f"{_ram_gb():.1f} GiB",
        "OS": f"{platform.system()} {platform.release()} ({platform.version()})",
        "Python": platform.python_version(),
        "mitmproxy": version("mitmproxy"), "FastAPI": version("fastapi"), "uvicorn": version("uvicorn"),
        "httpx": version("httpx"), "detect-secrets": version("detect-secrets"),
        "Git commit": commit,
    }

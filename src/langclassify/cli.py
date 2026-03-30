from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from typing import Iterable

from .detectors import classify_path
from .models import Classification
from .tools import ToolRunner


def _iter_paths_from_list_file(list_file: str) -> Iterable[str]:
    with open(list_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.strip()
            if not p or p.startswith("#"):
                continue
            yield p


def _iter_paths_from_dir(root: str) -> Iterable[str]:
    for dirpath, _, filenames in os.walk(root):
        for n in filenames:
            yield os.path.join(dirpath, n)


def _to_csv_row(c: Classification) -> dict[str, str]:
    ev = "; ".join([f"{e.kind}:{e.value} (via {e.via})" for e in c.evidence[:12]])
    if len(c.evidence) > 12:
        ev += f"; ... (+{len(c.evidence)-12} more)"
    return {
        "path": c.path,
        "file_kind": c.file_kind,
        "language": c.language,
        "confidence": f"{c.confidence:.3f}",
        "evidence": ev,
        "errors": "; ".join(c.errors),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="langclassify",
        description="Classify files/binaries by implementation language using shebang, ELF/PE metadata, symbols, and fingerprints.",
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--list", dest="list_file", help="Path to newline-delimited file list.")
    src.add_argument("--dir", dest="dir_root", help="Directory to scan recursively.")

    ap.add_argument("--root", default=".", help="Base directory to resolve relative paths from list (default: .)")
    ap.add_argument("--workers", type=int, default=8, help="Worker threads (default: 8)")

    ap.add_argument("--json-out", required=True, help="Write per-file results to this JSON file.")
    ap.add_argument("--csv-out", required=True, help="Write per-file results to this CSV file.")
    ap.add_argument("--summary-out", default=None, help="Write summary counts JSON to this file (optional).")

    ap.add_argument("--use-ldd", action="store_true", help="Also run ldd on ELF files (NOT recommended for untrusted binaries).")
    ap.add_argument("--use-strings", action="store_true", help="Allow calling 'strings' tool (byte-scan is used regardless).")

    ns = ap.parse_args(argv)

    tools = ToolRunner()

    if ns.list_file:
        paths = []
        for p in _iter_paths_from_list_file(ns.list_file):
            if os.path.isabs(p):
                paths.append(p)
            else:
                paths.append(os.path.normpath(os.path.join(ns.root, p)))
    else:
        paths = list(_iter_paths_from_dir(ns.dir_root))

    results: list[Classification] = []
    counts = Counter()

    with ThreadPoolExecutor(max_workers=max(1, ns.workers)) as ex:
        futs = {
            ex.submit(classify_path, p, tools, ns.use_ldd, ns.use_strings): p
            for p in paths
        }
        for fut in as_completed(futs):
            c = fut.result()
            results.append(c)
            counts[c.language] += 1

    # Write JSON
    with open(ns.json_out, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in sorted(results, key=lambda x: x.path)], f, indent=2)

    # Write CSV
    with open(ns.csv_out, "w", encoding="utf-8", newline="") as f:
        fieldnames = ["path", "file_kind", "language", "confidence", "evidence", "errors"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in sorted(results, key=lambda x: x.path):
            w.writerow(_to_csv_row(r))

    # Print counts to stdout
    print("Counts by language:")
    for lang, n in counts.most_common():
        print(f"  {lang:10s} {n}")

    if ns.summary_out:
        with open(ns.summary_out, "w", encoding="utf-8") as f:
            json.dump({"counts": dict(counts)}, f, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


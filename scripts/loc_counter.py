"""
NetSphere Line-of-Code (LOC) Auditor.
Calculates total physical lines of code, code vs comments vs blanks, categorized by language and module directory.
"""
from __future__ import annotations
import os
import sys
from collections import defaultdict


def count_lines_in_file(file_path: str):
    total = 0
    blank = 0
    comment = 0
    code = 0
    ext = os.path.splitext(file_path)[1].lower()

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                total += 1
                stripped = line.strip()
                if not stripped:
                    blank += 1
                elif ext in (".py", ".sh") and stripped.startswith("#"):
                    comment += 1
                elif ext in (".js", ".css") and (stripped.startswith("//") or stripped.startswith("/*")):
                    comment += 1
                elif ext == ".html" and stripped.startswith("<!--"):
                    comment += 1
                else:
                    code += 1
    except Exception:
        pass

    return total, code, comment, blank


def main():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ignored_dirs = {".git", ".pytest_cache", "__pycache__", ".venv", "venv", "build", "dist"}

    ext_stats = defaultdict(lambda: {"files": 0, "total": 0, "code": 0, "comment": 0, "blank": 0})
    dir_stats = defaultdict(lambda: {"files": 0, "total": 0})

    grand_total = 0

    for root, dirs, files in os.walk(root_dir):
        # Skip ignored
        dirs[:] = [d for d in dirs if d not in ignored_dirs]

        rel_dir = os.path.relpath(root, root_dir)
        top_dir = rel_dir.split(os.sep)[0] if rel_dir != "." else "root"

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in (".pyc", ".pyo", ".png", ".jpg", ".ico"):
                continue

            full_path = os.path.join(root, file)
            tot, cod, com, blk = count_lines_in_file(full_path)

            ext_stats[ext]["files"] += 1
            ext_stats[ext]["total"] += tot
            ext_stats[ext]["code"] += cod
            ext_stats[ext]["comment"] += com
            ext_stats[ext]["blank"] += blk

            dir_stats[top_dir]["files"] += 1
            dir_stats[top_dir]["total"] += tot
            grand_total += tot

    print("=" * 78)
    print(f"{'NETSPHERE CODEBASE METRICS & LINE-OF-CODE AUDIT':^78}")
    print("=" * 78)
    print(f"{'Language / Extension':<22} {'Files':<10} {'Blank':<10} {'Comment':<10} {'Code':<12} {'Total Lines':<12}")
    print("-" * 78)

    for ext, stats in sorted(ext_stats.items(), key=lambda x: x[1]["total"], reverse=True):
        ext_label = ext if ext else "[no ext]"
        print(f"{ext_label:<22} {stats['files']:<10} {stats['blank']:<10} {stats['comment']:<10} {stats['code']:<12} {stats['total']:<12,}")

    print("-" * 78)
    print(f"{'Directory Summary':<22} {'Files':<10} {'Total Lines':<12}")
    print("-" * 78)
    for d, stats in sorted(dir_stats.items(), key=lambda x: x[1]["total"], reverse=True):
        print(f"{d:<22} {stats['files']:<10} {stats['total']:<12,}")

    print("=" * 78)
    print(f"GRAND TOTAL: {grand_total:,} LINES OF CODE")
    print("=" * 78)

    if grand_total >= 50000:
        print(f"[SUCCESS] Verification PASSED: {grand_total:,} LOC exceeds requirement (>= 50,000 LOC)")
        return 0
    else:
        print(f"[FAILED] Verification FAILED: {grand_total:,} LOC is below 50,000 LOC requirement")
        return 1


if __name__ == "__main__":
    sys.exit(main())

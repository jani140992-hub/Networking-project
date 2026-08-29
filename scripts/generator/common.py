"""
Common utility functions for NetSphere codebase generator.
"""
import os
import sys

def get_project_root():
    # scripts/generator/common.py -> project root is two levels up
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

def write_code_file(rel_path, content):
    root = get_project_root()
    full_path = os.path.join(root, rel_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(content)
    line_count = len(content.splitlines())
    print(f"  [+] Wrote {rel_path} ({line_count:,} lines)")
    return line_count

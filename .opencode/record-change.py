#!/usr/bin/env python3
"""
Auto-update graph AND log change in one command.
Usage: python3 record-change.py "<file>" "<description>" "<how>"
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path("/home/kali/pq")
GRAPH_FILE = PROJECT_ROOT / ".opencode" / "graph.json"

def scan_rust_files():
    core_path = PROJECT_ROOT / "securevault-core" / "src"
    files = []
    if core_path.exists():
        for f in core_path.rglob("*.rs"):
            files.append(str(f.relative_to(PROJECT_ROOT)))
    return files

def scan_android_files():
    android_path = PROJECT_ROOT / "android" / "app" / "src"
    files = []
    if android_path.exists():
        for f in android_path.rglob("*.kt"):
            files.append(str(f.relative_to(PROJECT_ROOT)))
    return files

def scan_windows_files():
    windows_path = PROJECT_ROOT / "windows" / "src"
    files = []
    if windows_path.exists():
        for ext in ["*.ts", "*.tsx"]:
            for f in windows_path.rglob(ext):
                files.append(str(f.relative_to(PROJECT_ROOT)))
    return files

def update_and_log(file_path: str, description: str, how: str):
    if not GRAPH_FILE.exists():
        print("Error: graph.json not found")
        sys.exit(1)

    with open(GRAPH_FILE, "r") as f:
        graph = json.load(f)

    timestamp = datetime.now().isoformat()
    graph["last_updated"] = timestamp

    if "changes" not in graph:
        graph["changes"] = []

    change = {
        "timestamp": timestamp,
        "file": file_path,
        "description": description,
        "how": how
    }
    graph["changes"].insert(0, change)

    if "securevault-core" in graph.get("modules", {}):
        graph["modules"]["securevault-core"]["files"] = scan_rust_files()
    if "android" in graph.get("modules", {}):
        graph["modules"]["android"]["files"] = scan_android_files()
    if "windows" in graph.get("modules", {}):
        graph["modules"]["windows"]["files"] = scan_windows_files()

    with open(GRAPH_FILE, "w") as f:
        json.dump(graph, f, indent=2)

    print(f"✓ Graph updated and change logged:")
    print(f"  File: {file_path}")
    print(f"  What: {description}")
    print(f"  How: {how}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 record-change.py <file> <what> <how>")
        print("Example: python3 record-change.py securevault-core/src/crypto/poly.rs \"Added NTT\" \"Implemented number-theoretic transform\"")
        sys.exit(1)
    
    update_and_log(sys.argv[1], sys.argv[2], sys.argv[3])
#!/usr/bin/env python3
"""
Auto-updates the knowledge graph when codebase changes.
Run after any file edits in the project.
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path("/home/kali/pq")
GRAPH_FILE = PROJECT_ROOT / ".opencode" / "graph.json"

def scan_rust_files():
    """Scan securevault-core for rust files."""
    core_path = PROJECT_ROOT / "securevault-core" / "src"
    files = []
    if core_path.exists():
        for f in core_path.rglob("*.rs"):
            files.append(str(f.relative_to(PROJECT_ROOT)))
    return files

def scan_android_files():
    """Scan android for kotlin/java files."""
    android_path = PROJECT_ROOT / "android" / "app" / "src"
    files = []
    if android_path.exists():
        for f in android_path.rglob("*.kt"):
            files.append(str(f.relative_to(PROJECT_ROOT)))
    return files

def scan_windows_files():
    """Scan windows for ts/tsx files."""
    windows_path = PROJECT_ROOT / "windows" / "src"
    files = []
    if windows_path.exists():
        for ext in ["*.ts", "*.tsx"]:
            for f in windows_path.rglob(ext):
                files.append(str(f.relative_to(PROJECT_ROOT)))
    return files

def update_graph():
    """Update the knowledge graph."""
    if not GRAPH_FILE.exists():
        print("Error: graph.json not found")
        sys.exit(1)

    with open(GRAPH_FILE, "r") as f:
        graph = json.load(f)

    graph["last_updated"] = datetime.now().isoformat()

    if "securevault-core" in graph.get("modules", {}):
        graph["modules"]["securevault-core"]["files"] = scan_rust_files()

    if "android" in graph.get("modules", {}):
        graph["modules"]["android"]["files"] = scan_android_files()

    if "windows" in graph.get("modules", {}):
        graph["modules"]["windows"]["files"] = scan_windows_files()

    with open(GRAPH_FILE, "w") as f:
        json.dump(graph, f, indent=2)

    print(f"Graph updated: {len(scan_rust_files())} rust, {len(scan_android_files())} kotlin, {len(scan_windows_files())} ts/tsx files")

if __name__ == "__main__":
    update_graph()
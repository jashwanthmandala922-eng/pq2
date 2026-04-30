#!/usr/bin/env python3
"""
Log a code change to the knowledge graph.
Usage: python3 log-change.py "<file>" "<description>" "<how>"
Example: python3 log-change.py "securevault-core/src/crypto/mod.rs" "Added new crypto module" "Created poly.rs with NTT polynomial operations"
"""

import json
import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path("/home/kali/pq")
GRAPH_FILE = PROJECT_ROOT / ".opencode" / "graph.json"

def log_change(file_path: str, description: str, how: str):
    """Log a change to the graph."""
    with open(GRAPH_FILE, "r") as f:
        graph = json.load(f)

    if "changes" not in graph:
        graph["changes"] = []

    change = {
        "timestamp": datetime.now().isoformat(),
        "file": file_path,
        "description": description,
        "how": how
    }

    graph["changes"].insert(0, change)  # newest first
    graph["last_updated"] = datetime.now().isoformat()

    with open(GRAPH_FILE, "w") as f:
        json.dump(graph, f, indent=2)

    print(f"Logged change: {file_path}")
    print(f"  Description: {description}")
    print(f"  How: {how}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 log-change.py <file> <description> <how>")
        sys.exit(1)
    
    log_change(sys.argv[1], sys.argv[2], sys.argv[3])
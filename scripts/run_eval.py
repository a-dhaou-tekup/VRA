"""Generate predictions.json for eval_agent.py by running every question in
agent_eval_dataset.yaml through the VRA agent orchestrator.

Calls the orchestrator directly (no HTTP server required — same code path as
POST /api/agent/chat). Results are written to predictions.json in the format
eval_agent.py expects:

    [
      {
        "id":           "L03",
        "answer":       "There are 4 open critical jobs: ...",
        "tools_called": [{"name": "list_jobs", "args": {"status": "open", ...}}],
        "contexts":     ["...advisory chunk text...", ...]
      },
      ...
    ]

Usage:
    python scripts/run_eval.py [--out predictions.json] [--ids L01,L02,...]

Options:
    --out  <path>   Output file (default: predictions.json)
    --ids  <list>   Comma-separated subset of item IDs to run (default: all)
    --quiet         Suppress per-item progress lines
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("PLATFORM_DB_PATH", "data/cache/platform.db")

try:
    import yaml
except ImportError:
    print("pip install pyyaml"); sys.exit(1)

from agent.orchestrator import run_agent  # noqa: E402


def load_dataset(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)["items"]


def run_all(dataset: list[dict], ids: list[str] | None, quiet: bool) -> list[dict]:
    predictions = []
    total = 0

    for item in dataset:
        if ids and item["id"] not in ids:
            continue

        total += 1
        q   = item["question"]
        iid = item["id"]

        if not quiet:
            print(f"  [{iid}] {q[:72]}{'…' if len(q) > 72 else ''}", flush=True)

        t0 = time.monotonic()
        try:
            result = run_agent(q, role="analyst", username="eval_harness")
        except Exception as exc:
            result = {
                "answer":       f"ERROR: {exc}",
                "tools_called": [],
                "contexts":     [],
                "iterations":   0,
                "mode":         "error",
                "model":        "unknown",
            }

        elapsed = time.monotonic() - t0

        # Contexts: for RAGAS the scorer expects plain text strings, not chunk dicts.
        raw_contexts = result.get("contexts", [])
        text_contexts = [
            c["text"] if isinstance(c, dict) else str(c)
            for c in raw_contexts
        ]

        pred = {
            "id":           iid,
            "answer":       result.get("answer", ""),
            "tools_called": result.get("tools_called", []),
            "contexts":     text_contexts,
            # Extra metadata (ignored by eval_agent.py scorer, useful for debug)
            "_meta": {
                "mode":       result.get("mode"),
                "iterations": result.get("iterations"),
                "model":      result.get("model"),
                "elapsed_s":  round(elapsed, 1),
            },
        }
        predictions.append(pred)

        if not quiet:
            tc_names = [c["name"] for c in pred["tools_called"]]
            print(
                f"         mode={pred['_meta']['mode']}  "
                f"iters={pred['_meta']['iterations']}  "
                f"tools={tc_names}  "
                f"time={elapsed:.1f}s"
            )

    if not quiet:
        print(f"\n  Done: {total} items processed.")

    return predictions


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out",   default="predictions.json")
    ap.add_argument("--ids",   default=None,
                    help="Comma-separated subset, e.g. L01,C01,M01")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    dataset_path = ROOT / "agent_eval_dataset.yaml"
    dataset      = load_dataset(dataset_path)

    ids = [x.strip() for x in args.ids.split(",")] if args.ids else None

    print(f"VRA Eval Harness — {len(dataset)} items in dataset")
    if ids:
        print(f"  Running subset: {ids}")
    print()

    predictions = run_all(dataset, ids, args.quiet)

    out_path = Path(args.out)
    out_path.write_text(json.dumps(predictions, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Written {len(predictions)} predictions -> {out_path}")


if __name__ == "__main__":
    main()

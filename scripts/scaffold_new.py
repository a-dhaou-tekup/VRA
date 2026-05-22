"""scripts/scaffold_new.py — Create new directories and placeholder files.

Run once from the project root to create any missing directories:
    python scripts/scaffold_new.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent

NEW_DIRS = [
    "data/logs",
    "data/uploads",
    "data/rag_corpus/nvd_advisories",
    "data/rag_corpus/cisa_kev_notes",
    "data/rag_corpus/vendor_advisories",
    "src/rag",
    "frontend/src/api",
    "frontend/src/components",
    "frontend/src/pages",
]

def main():
    for d in NEW_DIRS:
        path = ROOT / d
        path.mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {path}")

        # .gitkeep for data dirs
        if d.startswith("data/"):
            gk = path / ".gitkeep"
            if not gk.exists():
                gk.touch()

    # __init__.py for src/rag
    rag_init = ROOT / "src" / "rag" / "__init__.py"
    if not rag_init.exists():
        rag_init.touch()
        print(f"  ✓ {rag_init}")

    print("\nScaffold complete.")

if __name__ == "__main__":
    main()

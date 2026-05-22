"""Index all advisory text files in data/rag_corpus/ into ChromaDB.

Run after build_vuln_enriched.py and fetch_cisa_advisories.py to populate
the vector store before starting the API.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

from rag.indexer import index_corpus, get_collection_stats

result = index_corpus()
print(f"✅ Indexed {result['files_indexed']} files · {result['chunks_indexed']} chunks · Collection: {result['collection']}")
stats = get_collection_stats()
print(f"📊 Total chunks in collection: {stats['total_chunks']}")

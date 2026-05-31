"""RAG Corpus Indexer.

Chunks advisory text files, embeds them with all-MiniLM-L6-v2,
and upserts into a ChromaDB persistent collection.
"""

import logging
from pathlib import Path
from typing import Optional

import torch
import yaml
import chromadb
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

_collection: Optional[chromadb.Collection] = None
_embedder: Optional[SentenceTransformer] = None
_named_collections: dict[str, chromadb.Collection] = {}  # multi-collection cache

_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "policy.yaml"

# Canonical collection names for multi-collection RAG
COLLECTION_CVE         = "cve_descriptions"
COLLECTION_VENDOR      = "vendor_advisories"
COLLECTION_RUNBOOKS    = "internal_runbooks"
COLLECTION_LEGACY      = "vra_advisories"   # original — kept for inspection

ALL_COLLECTIONS = [COLLECTION_CVE, COLLECTION_VENDOR, COLLECTION_RUNBOOKS]


def _load_config() -> dict:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return cfg["rag"]


def _get_chroma_client() -> chromadb.PersistentClient:
    """Return a ChromaDB persistent client rooted at chroma_persist_dir."""
    config = _load_config()
    persist_dir = Path(__file__).parent.parent.parent / config["chroma_persist_dir"]
    persist_dir.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(persist_dir))


def get_collection() -> chromadb.Collection:
    """Return (or create) the legacy singleton collection ``vra_advisories``.

    Kept for backward compatibility with hybrid_search and retriever modules
    that still query the legacy collection path.
    """
    global _collection
    if _collection is not None:
        return _collection
    client = _get_chroma_client()
    _collection = client.get_or_create_collection(name=COLLECTION_LEGACY)
    logger.info("ChromaDB collection '%s' ready", COLLECTION_LEGACY)
    return _collection


def get_named_collection(name: str) -> chromadb.Collection:
    """Return (or create) a named ChromaDB collection.

    Caches by name to avoid repeated client calls.
    Raises ValueError for unrecognised collection names.
    """
    global _named_collections
    if name in _named_collections:
        return _named_collections[name]
    allowed = ALL_COLLECTIONS + [COLLECTION_LEGACY]
    if name not in allowed:
        raise ValueError(f"Unknown collection '{name}'. Allowed: {allowed}")
    client = _get_chroma_client()
    _named_collections[name] = client.get_or_create_collection(name=name)
    logger.info("ChromaDB collection '%s' ready", name)
    return _named_collections[name]


def infer_collection_for_file(filepath: Path) -> str:
    """Determine the target collection for a corpus file based on its path.

    Heuristic (documented — same logic used in migrate_collections.py):
      data/rag_corpus/nvd_advisories/*   → cve_descriptions
      data/rag_corpus/cisa_kev_notes/*   → cve_descriptions
      data/rag_corpus/vendor_advisories/* → vendor_advisories
      data/runbooks/*                    → internal_runbooks
      anything else                      → cve_descriptions (safe default)
    """
    p = str(filepath).replace("\\", "/").lower()
    if "vendor_advisories" in p:
        return COLLECTION_VENDOR
    if "runbooks" in p:
        return COLLECTION_RUNBOOKS
    # nvd_advisories, cisa_kev_notes, unknown → CVE descriptions
    return COLLECTION_CVE


def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> list[str]:
    """Split text into overlapping word-based chunks."""
    words = text.split()
    chunks: list[str] = []
    start = 0
    while start < len(words):
        end = start + chunk_size
        chunks.append(" ".join(words[start:end]))
        start += chunk_size - overlap
    return [c for c in chunks if c.strip()]


def get_embedder() -> SentenceTransformer:
    """Return (or initialise) the singleton SentenceTransformer embedder."""
    global _embedder
    if _embedder is not None:
        return _embedder

    config = _load_config()
    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info(
        "Loading embedding model '%s' on device '%s'",
        config["embedding_model"],
        device,
    )
    _embedder = SentenceTransformer(config["embedding_model"], device=device)
    return _embedder


def index_file(
    filepath: Path,
    metadata: dict = None,
    collection_name: str | None = None,
) -> int:
    """Read a .txt file, chunk it, embed it, and upsert into ChromaDB.

    Parameters
    ----------
    filepath:
        Path to the text file to index.
    metadata:
        Extra metadata to attach to every chunk.
    collection_name:
        Target ChromaDB collection.  If ``None``, inferred from *filepath*
        via :func:`infer_collection_for_file`.  Pass ``COLLECTION_LEGACY``
        explicitly to write to the old ``vra_advisories`` collection.

    Returns the number of chunks indexed.
    """
    text = filepath.read_text(encoding="utf-8")
    chunks = chunk_text(text)
    if not chunks:
        return 0

    # Infer collection and provenance if not given
    if collection_name is None:
        collection_name = infer_collection_for_file(filepath)

    stem     = filepath.stem
    source_id = stem  # e.g. "CVE-2024-3400" or "patch-management"

    embedder = get_embedder()
    embeddings = embedder.encode(chunks, show_progress_bar=False).tolist()

    collection = get_named_collection(collection_name)
    ids = [f"{stem}_{i}" for i in range(len(chunks))]

    base_meta = dict(metadata) if metadata else {}
    base_meta.update({
        "source_file":  str(filepath),
        "source_class": collection_name,
        "source_id":    source_id,
    })
    metadatas = [{**base_meta, "chunk_index": i} for i in range(len(chunks))]

    collection.upsert(
        ids=ids,
        embeddings=embeddings,
        documents=chunks,
        metadatas=metadatas,
    )
    logger.debug("Indexed %d chunks from '%s' → %s", len(chunks), filepath.name, collection_name)

    # Also write to legacy vra_advisories for backward compatibility with
    # hybrid_search which still queries that collection.
    if collection_name != COLLECTION_LEGACY:
        try:
            legacy = get_named_collection(COLLECTION_LEGACY)
            legacy.upsert(ids=ids, embeddings=embeddings,
                          documents=chunks, metadatas=metadatas)
        except Exception as leg_exc:
            logger.warning("Legacy mirror write failed (non-fatal): %s", leg_exc)

    # Mirror into FTS5 for hybrid BM25 retrieval
    try:
        from rag.fts import write_chunks as fts_write
        fts_write(list(zip(ids, chunks)), source_class=collection_name)
        logger.debug("FTS5[%s]: wrote %d chunks from '%s'",
                     collection_name, len(chunks), filepath.name)
    except Exception as fts_exc:
        logger.warning(
            "FTS5 mirror write failed for '%s' (non-fatal): %s", filepath.name, fts_exc
        )

    return len(chunks)


def index_corpus(corpus_dir: Path = None) -> dict:
    """Walk all .txt files in corpus_dir recursively and index each one.

    Returns a summary dict with files_indexed, chunks_indexed, and collection name.
    """
    config = _load_config()
    if corpus_dir is None:
        corpus_dir = Path(__file__).parent.parent.parent / config["corpus_dir"]
    corpus_dir = Path(corpus_dir)

    # Absolute path to chroma_db so we can skip it during glob
    chroma_abs = str(
        (Path(__file__).parent.parent.parent / config["chroma_persist_dir"]).resolve()
    )

    txt_files = list(corpus_dir.rglob("*.txt"))
    logger.info("Found %d .txt files in '%s'", len(txt_files), corpus_dir)

    files_indexed = 0
    chunks_indexed = 0

    for filepath in txt_files:
        # Skip anything inside the chroma_db directory
        if chroma_abs in str(filepath.resolve()):
            continue
        try:
            n = index_file(filepath)
            chunks_indexed += n
            files_indexed += 1
        except Exception as exc:
            logger.warning("Failed to index '%s': %s", filepath, exc)

    logger.info(
        "Corpus indexing complete: %d files, %d chunks", files_indexed, chunks_indexed
    )
    return {
        "files_indexed": files_indexed,
        "chunks_indexed": chunks_indexed,
        "collection": "vra_advisories",
    }


def get_collection_stats() -> dict:
    """Return basic statistics about the legacy ChromaDB collection."""
    config = _load_config()
    collection = get_collection()
    return {
        "total_chunks":    collection.count(),
        "collection_name": COLLECTION_LEGACY,
        "embedding_model": config["embedding_model"],
    }


def get_all_collection_stats() -> list[dict]:
    """Return counts for all collections (legacy + three new ones).

    Used by the ``GET /api/rag/collections`` admin endpoint.
    """
    config = _load_config()
    embedding_model = config["embedding_model"]

    _DESCRIPTIONS = {
        COLLECTION_LEGACY:  "Legacy unified collection (preserved for A/B comparison)",
        COLLECTION_CVE:     "NVD/MITRE CVE entries and CISA KEV notes",
        COLLECTION_VENDOR:  "Vendor security advisories (Red Hat, Microsoft, Debian, …)",
        COLLECTION_RUNBOOKS:"Internal remediation runbooks and asset-specific guidance",
    }

    result = []
    for name in [COLLECTION_LEGACY] + ALL_COLLECTIONS:
        try:
            col   = get_named_collection(name)
            count = col.count()
        except Exception as exc:
            logger.warning("Could not stat collection '%s': %s", name, exc)
            count = -1
        result.append({
            "name":            name,
            "count":           count,
            "description":     _DESCRIPTIONS.get(name, ""),
            "embedding_model": embedding_model,
        })
    return result

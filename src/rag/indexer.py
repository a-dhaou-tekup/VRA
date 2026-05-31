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

_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "policy.yaml"


def _load_config() -> dict:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return cfg["rag"]


def get_collection() -> chromadb.Collection:
    """Return (or create) the singleton ChromaDB collection."""
    global _collection
    if _collection is not None:
        return _collection

    config = _load_config()
    persist_dir = Path(__file__).parent.parent.parent / config["chroma_persist_dir"]
    persist_dir.mkdir(parents=True, exist_ok=True)

    client = chromadb.PersistentClient(path=str(persist_dir))
    _collection = client.get_or_create_collection(name="vra_advisories")
    logger.info("ChromaDB collection 'vra_advisories' ready at %s", persist_dir)
    return _collection


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


def index_file(filepath: Path, metadata: dict = None) -> int:
    """Read a .txt file, chunk it, embed it, and upsert into ChromaDB.

    Returns the number of chunks indexed.
    """
    text = filepath.read_text(encoding="utf-8")
    chunks = chunk_text(text)
    if not chunks:
        return 0

    embedder = get_embedder()
    embeddings = embedder.encode(chunks, show_progress_bar=False).tolist()

    collection = get_collection()
    stem = filepath.stem
    ids = [f"{stem}_{i}" for i in range(len(chunks))]

    base_meta = dict(metadata) if metadata else {}
    base_meta["source_file"] = str(filepath)
    metadatas = [{**base_meta, "chunk_index": i} for i in range(len(chunks))]

    collection.upsert(
        ids=ids,
        embeddings=embeddings,
        documents=chunks,
        metadatas=metadatas,
    )
    logger.debug("Indexed %d chunks from '%s'", len(chunks), filepath.name)

    # Mirror into FTS5 for hybrid BM25 retrieval
    try:
        from rag.fts import write_chunks as fts_write
        fts_write(list(zip(ids, chunks)))
        logger.debug("FTS5: wrote %d chunks from '%s'", len(chunks), filepath.name)
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
    """Return basic statistics about the ChromaDB collection."""
    config = _load_config()
    collection = get_collection()
    return {
        "total_chunks": collection.count(),
        "collection_name": "vra_advisories",
        "embedding_model": config["embedding_model"],
    }

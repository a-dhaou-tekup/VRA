"""Diagnostic script — run from project root: python scripts/_diag_rag.py"""
import sys, json, logging, requests, yaml
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
logging.basicConfig(level=logging.WARNING)

def ok(msg):  print(f"  [OK]   {msg}")
def fail(msg): print(f"  [FAIL] {msg}")
def info(msg): print(f"  [INFO] {msg}")

print("\n--- 1. Imports ---")
try:
    from rag.recommender import generate_recommendation
    ok("rag.recommender imports")
except Exception as e:
    fail(f"rag.recommender: {e}")

print("\n--- 2. Ollama ---")
try:
    r = requests.get("http://localhost:11434/api/tags", timeout=5)
    models = [m["name"] for m in r.json().get("models", [])]
    ok(f"Ollama up — models: {models}")
except Exception as e:
    fail(f"Ollama: {e}")

print("\n--- 3. Config ---")
cfg_path = ROOT / "config" / "policy.yaml"
with open(cfg_path) as f:
    cfg = yaml.safe_load(f)["rag"]
info(f"ollama_url : {cfg.get('ollama_url')}")
info(f"model      : {cfg.get('model')}")
info(f"corpus_dir : {cfg.get('corpus_dir')}")
info(f"chroma_dir : {cfg.get('chroma_persist_dir')}")

print("\n--- 4. ChromaDB collection ---")
try:
    from rag.indexer import get_collection
    col = get_collection()
    ok(f"collection count = {col.count()}")
except Exception as e:
    fail(f"ChromaDB: {e}")

print("\n--- 5. RAG corpus .txt files ---")
corpus = ROOT / cfg.get("corpus_dir", "data/rag_corpus")
chroma = ROOT / cfg.get("chroma_persist_dir", "data/rag_corpus/chroma_db")
txt_files = [f for f in corpus.rglob("*.txt") if str(chroma) not in str(f)]
info(f"corpus path  : {corpus}")
info(f"corpus exists: {corpus.exists()}")
info(f".txt files   : {len(txt_files)}")
if txt_files:
    for f in txt_files[:5]:
        info(f"  {f.name}")

print("\n--- 6. Minimal Ollama chat ---")
try:
    resp = requests.post(
        f"{cfg['ollama_url']}/api/chat",
        json={
            "model": cfg["model"],
            "stream": False,
            "messages": [{"role": "user", "content": "Reply with one word: ready"}],
        },
        timeout=120,
    )
    info(f"HTTP status: {resp.status_code}")
    d = resp.json()
    content = d.get("message", {}).get("content", "(empty)")
    ok(f"Response: {content[:100]}")
except Exception as e:
    fail(f"{type(e).__name__}: {e}")

print("\n--- 7. Full pipeline on synthetic job ---")
fake_job = {
    "job_id": "diag-test",
    "main_product": "Apache Log4j",
    "cve_list": '["CVE-2021-44228"]',
    "max_risk_level": "CRITICAL",
    "kev_present": 1,
    "risk_score_max": 9.8,
    "business_unit": "IT",
    "affected_asset_count": 1,
}
try:
    from api.services.rag_service import generate_recommendation as svc_gen
    import time
    t = time.monotonic()
    result = svc_gen(fake_job)
    elapsed = int((time.monotonic() - t) * 1000)
    info(f"Elapsed: {elapsed} ms")
    info(f"model  : {result.get('model', result.get('_meta', {}).get('model'))}")
    meta = result.get("_meta", {})
    if meta:
        info(f"chunks : {meta.get('chunks_used')}")
        info(f"tokens : prompt={meta.get('prompt_tokens')} response={meta.get('response_tokens')}")
    info(f"summary: {str(result.get('summary', result.get('recommendation', '')))[:150]}")
except Exception as e:
    import traceback
    fail(f"{type(e).__name__}: {e}")
    traceback.print_exc()

print()

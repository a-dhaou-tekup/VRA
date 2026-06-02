"""
VRA Agent Evaluation Harness
============================================================================
Measures the tool-calling chatbot against agent_eval_dataset.yaml.

Two metric families:

  DETERMINISTIC (offline, no LLM needed) -- the primary defense-day numbers:
    * tool_selection_accuracy : did the agent call exactly the expected tool set?
    * tool precision / recall / F1 : over tool names (handles multi-tool items)
    * arg_match_rate : did expected_args appear in the call args?
    * answer_match_rate : for lookups with answer_match (numeric/contains/regex)

  RAGAS (needs an LLM judge + embeddings; guarded behind --ragas) -- for the
  advice/compliance answers:
    * faithfulness, answer_correctness, context_precision/recall
    * (agent metrics: ToolCallAccuracy / AgentGoalAccuracy use MultiTurnSample)
  NOTE: RAGAS's API has changed across versions. The block below targets the
  0.2.x EvaluationDataset/SingleTurnSample API; pin your version and verify the
  metric import paths. This block is NOT exercised by `selftest` (no LLM here).

Prediction format (one per dataset id), from your agent's response trace:
  {
    "id": "L03",
    "answer": "There are 4 open critical jobs: ...",
    "tools_called": [{"name": "list_jobs", "args": {"status":"open","risk_level":"CRITICAL"}}],
    "contexts": ["...retrieved passage...", "..."]   # for advice/compliance
  }

Usage:
  python eval_agent.py selftest                 # offline self-test (mock data)
  python eval_agent.py score predictions.json   # score recorded predictions
  python eval_agent.py score predictions.json --ragas   # + RAGAS (needs install/LLM)
"""
import json
import re
import sys
import statistics

try:
    import yaml
except ImportError:
    yaml = None


# ----------------------------- data loading --------------------------------
def load_dataset(path="agent_eval_dataset.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)["items"]


def load_predictions(path):
    with open(path, encoding="utf-8") as f:
        preds = json.load(f)
    return {p["id"]: p for p in preds}


# ----------------------------- deterministic scoring -----------------------
def tool_names(calls):
    return [c["name"] for c in (calls or [])]


def prf(expected, actual):
    """Precision/recall/F1 over tool-name sets."""
    e, a = set(expected), set(actual)
    if not e and not a:
        return 1.0, 1.0, 1.0
    tp = len(e & a)
    prec = tp / len(a) if a else 0.0
    rec = tp / len(e) if e else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return prec, rec, f1


def args_match(expected_args, calls):
    """True if every expected (k,v) appears in at least one call's args."""
    if not expected_args:
        return None  # not applicable
    flat = {}
    for c in (calls or []):
        for k, v in (c.get("args") or {}).items():
            flat[k] = v
    for k, v in expected_args.items():
        if k not in flat:
            return False
        # loose, case-insensitive string compare
        if str(flat[k]).strip().lower() != str(v).strip().lower():
            return False
    return True


def answer_matches(answer_match, answer):
    if not answer_match:
        return None
    mode = answer_match.get("mode")
    val = answer_match.get("value")
    answer = answer or ""
    if val is None:
        return None  # dynamic value not frozen -> skip, score tools only
    if mode == "numeric":
        nums = re.findall(r"-?\d+(?:\.\d+)?", answer)
        return str(val) in nums
    if mode == "contains":
        return str(val).lower() in answer.lower()
    if mode == "regex":
        return re.search(val, answer) is not None
    return None


def score_deterministic(dataset, preds):
    rows = []
    for item in dataset:
        p = preds.get(item["id"], {})
        exp_tools = item.get("expected_tools", [])
        act_tools = tool_names(p.get("tools_called"))
        sel_exact = set(exp_tools) == set(act_tools)
        pr, rc, f1 = prf(exp_tools, act_tools)
        am = args_match(item.get("expected_args"), p.get("tools_called"))
        ans = answer_matches(item.get("answer_match"), p.get("answer"))
        rows.append({
            "id": item["id"], "type": item["type"],
            "sel_exact": sel_exact, "precision": pr, "recall": rc, "f1": f1,
            "arg_match": am, "answer_match": ans,
        })
    return rows


def summarize(rows):
    def mean(xs):
        xs = [x for x in xs if x is not None]
        return statistics.mean(xs) if xs else float("nan")

    print(f"\nItems scored: {len(rows)}")
    print(f"  Tool-selection accuracy (exact set): {mean([r['sel_exact'] for r in rows]):.0%}")
    print(f"  Tool precision: {mean([r['precision'] for r in rows]):.2f}"
          f"  recall: {mean([r['recall'] for r in rows]):.2f}"
          f"  F1: {mean([r['f1'] for r in rows]):.2f}")
    arg = [r["arg_match"] for r in rows if r["arg_match"] is not None]
    if arg:
        print(f"  Arg-match rate (where applicable): {mean(arg):.0%}  (n={len(arg)})")
    ans = [r["answer_match"] for r in rows if r["answer_match"] is not None]
    if ans:
        print(f"  Answer-match rate (frozen lookups): {mean(ans):.0%}  (n={len(ans)})")
    # per-type breakdown
    print("\n  By type:")
    types = sorted(set(r["type"] for r in rows))
    for t in types:
        sub = [r for r in rows if r["type"] == t]
        print(f"    {t:11s} n={len(sub):2d}  sel_acc={mean([r['sel_exact'] for r in sub]):.0%}"
              f"  F1={mean([r['f1'] for r in sub]):.2f}")
    # flag misses for review
    misses = [r["id"] for r in rows if not r["sel_exact"]]
    if misses:
        print(f"\n  Tool-selection misses to review: {', '.join(misses)}")


# ----------------------------- RAGAS (guarded) -----------------------------
def run_ragas(dataset, preds):
    """
    Faithfulness / answer-correctness / context metrics for advice & compliance
    answers. Requires `pip install ragas` and a configured judge LLM + embeddings.
    Targets the ragas 0.2.x API; verify against your installed version.
    """
    try:
        from ragas import evaluate, EvaluationDataset
        from ragas.dataset_schema import SingleTurnSample
        from ragas.metrics import faithfulness, answer_correctness, context_precision
    except Exception as e:
        print(f"[ragas] not available / API mismatch: {e}")
        print("        pip install ragas and configure a judge LLM (e.g. local Ollama).")
        return

    samples = []
    for item in dataset:
        if item["type"] not in ("advice", "compliance", "multi"):
            continue
        p = preds.get(item["id"])
        if not p:
            continue
        samples.append(SingleTurnSample(
            user_input=item["question"],
            response=p.get("answer", ""),
            retrieved_contexts=p.get("contexts", []) or [],
            reference=item.get("reference", ""),
        ))
    if not samples:
        print("[ragas] no advice/compliance predictions to score.")
        return
    ds = EvaluationDataset(samples=samples)
    # NOTE: pass a configured llm=/embeddings= (e.g. langchain-ollama) per ragas docs.
    result = evaluate(ds, metrics=[faithfulness, answer_correctness, context_precision])
    print("\n[ragas] grounded-answer metrics:")
    print(result)


# ----------------------------- self test -----------------------------------
def selftest():
    """Offline check that the deterministic scorer works, using mock data."""
    dataset = [
        {"id": "L03", "type": "lookup", "expected_tools": ["list_jobs"],
         "expected_args": {"status": "open", "risk_level": "CRITICAL"}},
        {"id": "L02", "type": "lookup", "expected_tools": ["get_sla_compliance"],
         "answer_match": {"mode": "regex", "value": r"\d{1,3}\s?%"}},
        {"id": "A01", "type": "advice", "expected_tools": ["search_knowledge"]},
        {"id": "M01", "type": "multi", "expected_tools": ["list_jobs", "search_knowledge"]},
    ]
    preds = {
        "L03": {"id": "L03", "answer": "4 open critical jobs.",
                "tools_called": [{"name": "list_jobs",
                                  "args": {"status": "open", "risk_level": "CRITICAL"}}]},
        "L02": {"id": "L02", "answer": "Our SLA compliance is 87%.",
                "tools_called": [{"name": "get_sla_compliance", "args": {}}]},
        "A01": {"id": "A01", "answer": "Prioritize KEV + exposed first.",
                "tools_called": [{"name": "search_knowledge", "args": {"q": "prioritize"}}],
                "contexts": ["Prioritize by contextual risk..."]},
        # M01: agent missed search_knowledge -> should show as partial
        "M01": {"id": "M01", "answer": "Here are the jobs.",
                "tools_called": [{"name": "list_jobs", "args": {}}]},
    }
    rows = score_deterministic(dataset, preds)
    summarize(rows)
    assert rows[0]["sel_exact"] and rows[0]["arg_match"]
    assert rows[1]["answer_match"]
    assert not rows[3]["sel_exact"] and rows[3]["recall"] == 0.5  # missed 1 of 2 tools
    print("\nselftest: OK")


# ----------------------------- cli -----------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(0)
    cmd = sys.argv[1]
    if cmd == "selftest":
        selftest()
    elif cmd == "score":
        if yaml is None:
            print("pip install pyyaml"); sys.exit(1)
        dataset = load_dataset()
        preds = load_predictions(sys.argv[2])
        rows = score_deterministic(dataset, preds)
        summarize(rows)
        if "--ragas" in sys.argv:
            run_ragas(dataset, preds)
    else:
        print(__doc__)

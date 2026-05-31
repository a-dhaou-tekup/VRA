# VRA Knowledge Graph

## Graph model

The graph is a directed NetworkX `DiGraph` built from `platform.db` at startup and refreshed every 60 seconds (configurable via `GRAPH_REFRESH_INTERVAL_SECONDS`).

### Node kinds

| Kind | Source table | Size in UI |
|------|-------------|------------|
| `cve` | `findings.cve_id` | Medium (r=7) |
| `component` | `findings.component` | Small (r=5) |
| `asset` | `assets` | Large (r=10) |
| `owner` | `assets.business_owner / owning_team` | Largest (r=12) |
| `service` | `services` | Largest (r=12) |

### Edge kinds

| Kind | Meaning |
|------|---------|
| `finding_of` | CVE → Asset (this CVE was found on this asset) |
| `runs` | Asset → Component (this asset runs this software) |
| `owned_by` | Asset/Service → Owner |
| `serves` | Asset → Service (via `asset_services`) |
| `depends_on` | Service → Service (via `service_dependencies`) |

### New schema tables (Prompt #8)

```sql
services(id TEXT PK, name TEXT, owner_id TEXT, description TEXT, created_at TEXT)
asset_services(asset_id TEXT, service_id TEXT, PK(asset_id, service_id))
service_dependencies(parent_service_id TEXT, child_service_id TEXT, dep_type TEXT, PK(...))
```

Run `python scripts/seed_demo_graph.py` to populate demo data (8 services, links to existing assets, 5 dependency edges).

## Queries

### `blast_radius(finding_id, depth=2)`

Bounded BFS from the affected asset in the **undirected** projection of the graph. Depth ≤ 4 to prevent runaway traversal.

At depth=2 a typical result includes: the CVE node, the affected asset, its owner, the services it serves, and any services that depend on those services.

Performance target: < 200 ms at depth ≤ 3. If exceeded, a warning is logged.

### `similar_findings(finding_id, k=10)`

Hybrid similarity combining:
- **Embedding** (weight 0.6, env `EMBED_SIM_WEIGHT`): queries the RAG multi-collection store with `{cve_id} {component}` and maps the RRF score to a normalised [0,1] similarity.
- **Graph** (weight 0.4, env `GRAPH_SIM_WEIGHT`): Jaccard similarity over the 2-hop neighbourhood sets of the two findings' asset nodes.

The score breakdown (`{embed, graph}`) is returned per result so analysts can see which signal drove the match.

## API

| Method | Path | RBAC | Notes |
|--------|------|------|-------|
| `POST` | `/api/graph/refresh` | admin | Synchronous rebuild; returns node/edge counts |
| `GET` | `/api/findings/{id}/blast-radius?depth=2` | any authenticated | Returns `{nodes, edges, elapsed_ms}` |
| `GET` | `/api/findings/{id}/similar?k=10` | any authenticated | Returns scored list with breakdown |

## Frontend (Finding Detail page)

Route: `/findings/:id`

- **AI triage panel** — shows the current `auto_triage` suggestion and justification.
- **Similar findings** — top-5 matches with score breakdown (embed + graph).
- **Blast Radius tab** — `react-force-graph-2d` canvas. Colour = node kind. Size = node importance. Click a node → side panel with all attributes. Depth selector (1/2/3).

```
npm install   # installs react-force-graph-2d
```

## Single-process limitation

The graph cache (`api/services/graph/cache.py`) is **process-local**. Each uvicorn worker maintains an independent copy; cache invalidation via `POST /api/graph/refresh` only rebuilds the graph in the worker that handles the request.

For a single-worker demo deployment this is acceptable. For a multi-worker production deployment:

**Recommended upgrade path:**
1. Extract the graph into a separate long-running process (a "graph service") that exposes `build`, `invalidate`, and `query` over a lightweight IPC channel (e.g., Redis pub/sub or a Unix socket).
2. All API workers connect to this single process for graph data.
3. Cache invalidation becomes a message to the shared process.

At VRA's current data volume (< 10 000 assets, < 100 000 findings) the in-memory approach is appropriate; do not introduce a graph database until query complexity justifies it.

## Demo seed script

```bash
python scripts/seed_demo_graph.py
```

Populates 8 services (Authentication, API Gateway, Database primary/replica, Cache, CI/CD, Logging, Monitoring), links the first 20 assets round-robin, and creates 5 meaningful dependency edges:
- API Gateway → Authentication
- API Gateway → Primary DB
- Primary DB → DB Replica
- Authentication → Cache Cluster
- Monitoring → Logging

After seeding, trigger a graph rebuild:

```bash
curl -X POST http://localhost:8000/api/graph/refresh \
  -H "Authorization: Bearer <admin-token>"
```

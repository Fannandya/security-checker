# AI Agent Guidelines - Security Checker (OSC)

## 📌 Graphify Guidelines & Token Optimization (MANDATORY FOR ALL AGENTS)

Projects in this repository maintain an active knowledge graph stored in `graphify-out/`. To prevent excessive token usage and maintain system alignment across sessions, **ALL AGENTS MUST ADHERE TO THE FOLLOWING PROTOCOL**:

### 1. New Session Initialization (Wajib Patokan Awal / New Session)
- **Always start with Graphify**: Before performing extensive codebase searches or reading large files into context, check if `graphify-out/graph.json` exists.
- **Token-Efficient Querying**: Use targeted CLI commands to fetch scoped subgraphs instead of reading raw code:
  - Query specific components/topics: `graphify query "<question>"`
  - Find relationships between nodes: `graphify path "<nodeA>" "<nodeB>"`
  - Understand specific concepts: `graphify explain "<concept>"`
- **Architecture Overview**: Read `graphify-out/GRAPH_REPORT.md` or consult `graphify-out/wiki/index.md` (if present) for initial structural navigation instead of browsing raw source files line by line.

### 2. Mandatory Post-Task Knowledge Graph Update (Wajib Update Graphify)
- **Always update after code modifications**: Whenever you add, modify, or delete any code, test, or structure in the project, you **MUST** run:
  ```bash
  graphify update .
  ```
- Running `graphify update .` is AST-only (fast, zero API cost) and ensures the graph remains perfectly synchronized for the next session or agent.

---

## 🚀 Quick Reference Commands
- Test suite execution: `./venv/bin/pytest`
- CLI test: `python3 osc.py --help` or `python -m osc --help`
- Graph update: `graphify update .`

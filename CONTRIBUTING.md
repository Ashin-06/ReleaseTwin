# Contributing

Use a Python 3.10+ virtual environment and install with `python -m pip install -e .`. Run `python -m unittest discover -s tests -v`, `python -m ruff check --select F,E9 .`, `node --check releasetwin/static/app.js`, and `python -m releasetwin benchmark` before submitting a change. Install ruff separately for development.

Preserve deterministic results: do not add network calls, implicit environment inputs, or timestamps to engine results. Add a meaningful failing case and its repaired/control outcome when changing enforcement. Keep input budgets, evidence replay, JSON escaping, Host/origin/session checks, and the non-execution boundary intact. Update the method and fixtures when policy semantics change.

Use synthetic data in issues. Do not submit signing secrets, account tokens, real user exports, or proprietary artifacts. For a security problem, first provide a minimal synthetic reproduction to the repository owner through an available private channel; do not publish sensitive evidence in a public issue.

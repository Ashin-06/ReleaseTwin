# Changelog

## 1.0.1 — 2026-10-15

- Preserve raw editor JSON through strict server validation, including duplicate keys and overflowing numeric literals.
- Keep the previous successful result explicitly labeled when a new run fails; initialize action availability correctly.
- Add recovery checks for malformed requests and stronger engine regression coverage.

- Detect executable permission additions alongside content changes; reject ambiguous archive hierarchies and malformed compression streams.

## 1.0.0 — 2026-10-15

- Deterministic ReleaseTwin engine and documented input contract.
- Responsive local workbench, scenario library, findings, ledger filtering, and CSV export.
- Saved evidence, HTML reports, hash verification, deterministic replay, and verified ZIP export.
- CLI workflows, reproducible fixtures, independent controls, threat model, and cross-platform CI.

# Architecture and local API

`releasetwin/engine.py` owns validation, deterministic execution, presets, and benchmark generation. Engine-specific modules implement policy or artifact primitives. `lab.py` owns canonical JSON, reports, evidence, CLI dispatch, and the loopback HTTP server. `static/` is dependency-free HTML/CSS/JavaScript. Each repository is independently installable and has no dependency on the other workbenches.

```text
CLI / local browser -> validated input -> engine -> summary + findings + events + details
                                             -> evidence + manifest -> replay verification
```

## HTTP contract

All routes require an exact local Host header with the listening port. GET `/api/meta` returns the app metadata, presets, capabilities, and per-process token. JSON POST requests require `X-Lab-Token` and a same-origin Origin if present. Each input is bounded to 12 MiB; engines apply smaller domain budgets. Use the browser UI or a local client; no CORS support is provided.

| Route | Behavior |
| --- | --- |
| GET `/` | Workbench |
| GET `/api/meta` | Metadata, presets, and local session token |
| POST `/api/run` | Validate and return a deterministic result |
| POST `/api/save` | Re-execute input, save a new case, return report/bundle links (201) |
| GET `/api/cases` | List local saved case metadata |
| GET `/api/cases/{id}/verify` | Check hashes and replay |
| GET `/api/cases/{id}/report` | Standalone HTML report |
| GET `/api/cases/{id}/bundle` | Verify and export fixed-file ZIP |

Case identifiers are generated 32-character lowercase hexadecimal strings; clients cannot supply server filesystem paths. TenantScope additionally exposes POST `/api/minimize` for a validated failing input. Invalid inputs return JSON errors (400); rejected Host/origin/token checks return 403; wrong media type 415; oversized bodies 413; exhausted analysis slots 429; unknown routes 404. The API is local and single-user.

## Persistence

Browser cases default to `.lab/cases`; CLI `serve --data-dir PATH` changes the local root. The browser has no delete endpoint. Back up or remove cases using ordinary OS tools after stopping the server. `run`, `demo`, and engine-specific comparisons accept a new explicit output directory. Do not store operator private keys in an evidence directory.

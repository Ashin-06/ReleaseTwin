# ReleaseTwin: threat model

## Local workbench boundary

The server binds only to `127.0.0.1`. Exact Host validation, same-origin checks, a per-process session token, strict JSON parsing, a 12 MiB body limit, four concurrent analyses, socket timeouts, and a restrictive content security policy reduce exposure to hostile browser requests. This is a single-user research workbench. Do not publish its port, place it behind a public reverse proxy, or treat the token as multi-user authentication. A process already running as your OS user can read local evidence and obtain a session token.

Scenario content, embedded artifacts, and logical application state can be included in saved evidence. Use synthetic inputs when sharing. No telemetry, external requests, or uploaded-code execution are performed by the workbench. Python dependencies are installed separately by the operator.

## Evidence integrity

An evidence directory contains exactly `input.json`, `result.json`, `report.html`, and `manifest.json`. The manifest records app/version, creation time, and SHA-256 hashes of the other three files. `verify` checks the fixed inventory, hashes, and deterministic replay, including the generated report. Unexpected files and symbolic links fail verification. Export verifies first and never adds arbitrary paths.

These hashes are **not an authenticated signature**, and the creation time is a local clock reading. A person able to replace all files can create a new internally consistent experiment. Verification establishes consistency and reproducibility for this implementation, not authorship or trusted time. Keep the original input and trusted software version when reproducing older evidence.

## Engine boundary

See [Method](docs/METHOD.md) for model assumptions, trust inputs, resource limits, and exclusions. Review those assumptions before interpreting any finding.

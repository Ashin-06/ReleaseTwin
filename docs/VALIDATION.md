# Version 1.0.1 validation

The local regression suite passes 33 tests. Regression checks cover content plus executable-mode changes, ambiguous directory hierarchies, special entries, corrupt deflate streams, unreadable walks, pinned signatures, and invalid-attestation output preservation.

All bundled scenarios were also executed through the real dashboard. Browser checks confirmed strict duplicate-key rejection in Run and Format, preservation of rejected editor input, clear labeling of the previous successful result, and recovery on the next valid input. CLI demo, benchmark, evidence replay, and verified ZIP export passed. GitHub Actions runs the committed suite independently on Windows/Ubuntu and Python 3.10/3.12.

The shared JSON parser rejects duplicate keys, NaN/Infinity, and overflow literals such as `1e999`. Evidence tests cover tampering, self-consistent result forgery rejected on replay, unsafe manifests, existing-destination preservation, and styled reports under a restrictive content policy. Request tests cover local Host restrictions, origin/session checks, malformed and duplicate Content-Length values, size limits, JSON errors, and recovery after rejected requests.

The audit also exercised real ZIP file uploads and filtered CSV download. A synthetic actor named `=SUM(1,1)` was escaped in the downloaded CSV and only the selected finding row was exported. New cases were saved in all three workbenches. These manual browser checks are point-in-time checks; the CI suite validates engines and HTTP workflows, and checks frontend syntax, but does not run an automated browser matrix.

## Reproducing older evidence

Replay is pinned to the software version recorded in the case manifest. Keep the original case files and use the matching release tag to verify an older case. Upgrading the application does not overwrite old evidence. A version mismatch is an explicit refusal to claim reproduction with a different implementation.

## Limits

Passing these checks supports the documented contracts and supplied/generated scenarios. It does not establish freedom from all defects, a production deployment assessment, or source-to-binary equivalence. Model and trust boundaries remain documented in METHOD.md and THREAT_MODEL.md.

# ReleaseTwin: method and limits

## Artifact comparison

Paths are portable NFC-normalized relative paths. Traversal, absolute/backslash paths, reserved Windows filenames, case collisions, duplicate files, parent-file conflicts, symlinks, encrypted entries, excessive compression ratios, and size-budget violations are rejected. Limits apply equally to CLI and browser: **4 MiB ZIP**, 8 MiB individual uncompressed file, 32 MiB total uncompressed content, 1000 entries, compression ratio at most 200:1.

File inventory equality compares SHA-256 content and the executable bit. Whole-ZIP equality is reported separately because ZIP metadata can differ. Empty directories, timestamps, ownership, ACLs, and non-executable permission bits are not part of file equality. Directory packaging uses sorted files, stored compression, and a fixed ZIP timestamp; acquire a stable tree before analysis. Concurrent adversarial filesystem mutation is outside this model.

## Provenance schema and trust

The custom schema-v1 envelope contains `payload`, `key_id`, and base64 `signature`. The payload contains integer `schema_version: 1`, `repository`, full lowercase 40- or 64-hex `revision`, `builder`, and `artifact_sha256`. Ed25519 signs UTF-8 JSON with sorted keys, compact separators, and no non-finite values. `key_id` is `ed25519:` plus the SHA-256 of raw public key bytes.

Verification requires a separately acquired PEM public key and a policy with exact repository/revision/builder values. It validates signature, key identity, exact candidate ZIP digest, and all policy fields. There is no embedded-key auto-trust, certificate chain, key discovery, transparency log, or revocation service. This format is not a SLSA certification or proof that a builder reproduced the stated source. The included deterministic demo key is public fixture material and must never be used to sign a real release.

## Behavior trace schema

Supply both `baseline_behavior` and `candidate_behavior`, each `{"schema_version":1,"cases":[...]}`. Up to 200 uniquely identified cases contain `id`, integer `exit_code`, and lowercase 64-hex `stdout_sha256`/`stderr_sha256`. The tool compares the recorded values and added/removed cases. It does not run tests, authenticate traces, establish environment equivalence, or measure coverage.

## Browser and CLI input

JSON fields `baseline_zip`/`candidate_zip` are base64 ZIP bytes. Provenance fields `attestation`, `trusted_key` (PEM string), and `policy` are all required together. The browser file controls replace the corresponding ZIP field. When substituting an artifact, also replace or remove the fixture provenance group; a stale fixture signature should fail. CLI `compare` accepts ZIP paths or stable directories and reads the same JSON/PEM fields from explicit files.

`keygen` writes a fresh Ed25519 pair to a new directory. Set `RELEASETWIN_KEY_PASSWORD` to encrypt the private PKCS8 PEM; otherwise it is unencrypted. POSIX creation mode is 0600; on Windows apply appropriate account ACLs yourself. Keep private keys outside repositories, artifacts, and evidence bundles. `attest` signs an existing ZIP only, so the digest is the exact distributed byte sequence.

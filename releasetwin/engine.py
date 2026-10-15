"""Artifact differential analysis plus pinned-key provenance and recorded behavior."""

import base64
import copy
import hashlib
import io
import os
import stat
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .artifacts import MAX_ARCHIVE, inventory_zip, read_artifact
from .lab import canonical, fields, integer, read_json, text
from .provenance import sign, verify

APP_NAME = "ReleaseTwin"
TAGLINE = "Inspect what changed in a release and whether its signed origin matches your policy."
PORT = 8763
CAPABILITIES = [
    "Compare bounded ZIPs or local directories by normalized path, SHA-256 content, size, and executable bit.",
    "Verify Ed25519 provenance against a separately trusted public key and expected repository, full revision, builder, and artifact digest.",
    "Compare externally recorded behavior cases by exit code and output digests; uploaded code is never executed.",
    "Reject traversal, duplicate/case-colliding paths, symlinks, encrypted archives, and decompression budget violations.",
    "Matching inventories or a valid signature do not prove a binary was built from the claimed source. No SLSA certification or malware verdict is implied.",
]


def _decode(value):
    if not isinstance(value, str) or len(value) > 4 * ((MAX_ARCHIVE + 2) // 3):
        raise ValueError("Archive base64 exceeds the compressed budget")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("Invalid archive base64") from exc


def _behavior(value):
    fields(value, ("schema_version", "cases"))
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("Unsupported behavior schema")
    if not isinstance(value["cases"], list) or len(value["cases"]) > 200:
        raise ValueError("Use at most 200 recorded behavior cases")
    cases = {}
    for item in value["cases"]:
        fields(item, ("id", "exit_code", "stdout_sha256", "stderr_sha256"))
        ident = text(item["id"], "case id", 100)
        integer(item["exit_code"], "exit code", -255, 255)
        for key in ("stdout_sha256", "stderr_sha256"):
            digest = item[key]
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
            ):
                raise ValueError("Behavior output digests must be lowercase SHA-256")
        if ident in cases:
            raise ValueError("Duplicate behavior case id")
        cases[ident] = item
    return cases


def execute(request):
    fields(
        request,
        ("baseline_zip", "candidate_zip"),
        (
            "attestation",
            "trusted_key",
            "policy",
            "baseline_behavior",
            "candidate_behavior",
        ),
    )
    baseline, candidate = (
        _decode(request["baseline_zip"]),
        _decode(request["candidate_zip"]),
    )
    left, right = inventory_zip(baseline), inventory_zip(candidate)
    events = []
    counts = {
        "added": 0,
        "removed": 0,
        "modified": 0,
        "mode_changed": 0,
        "unchanged": 0,
    }
    for path in sorted(set(left) | set(right)):
        a, b = left.get(path), right.get(path)
        change = (
            "added"
            if a is None
            else "removed"
            if b is None
            else "modified"
            if a["sha256"] != b["sha256"]
            else "mode_changed"
            if a["executable"] != b["executable"]
            else "unchanged"
        )
        counts[change] += 1
        events.append(
            {
                "path": path,
                "change": change,
                "baseline_sha256": a["sha256"] if a else "",
                "candidate_sha256": b["sha256"] if b else "",
                "baseline_bytes": a["bytes"] if a else 0,
                "candidate_bytes": b["bytes"] if b else 0,
                "candidate_executable": b["executable"] if b else False,
                "baseline_executable": a["executable"] if a else False,
            }
        )
    findings = []
    changed = sum(v for k, v in counts.items() if k != "unchanged")
    if changed:
        findings.append(
            {
                "severity": "medium",
                "title": f"{changed} file-level differences",
                "detail": "Differences require review against the release policy. A change is not automatically malicious.",
            }
        )
    executables = [
        e["path"]
        for e in events
        if e["candidate_executable"] and not e["baseline_executable"]
    ]
    if executables:
        findings.append(
            {
                "severity": "high",
                "title": "New executable capability in the candidate",
                "detail": ", ".join(executables[:20]),
            }
        )
    byte_match = hashlib.sha256(baseline).digest() == hashlib.sha256(candidate).digest()
    if not byte_match and not changed:
        findings.append(
            {
                "severity": "low",
                "title": "ZIP bytes differ while inventories agree",
                "detail": "Archive metadata or compression differs. Content-level agreement is not a byte-for-byte reproducible build.",
            }
        )
    provenance = {"ok": None, "checks": []}
    supplied = any(
        request.get(k) is not None for k in ("attestation", "trusted_key", "policy")
    )
    if supplied:
        if not all(
            request.get(k) is not None for k in ("attestation", "trusted_key", "policy")
        ):
            raise ValueError("Supply attestation, trusted_key, and policy together")
        provenance = verify(
            candidate, request["attestation"], request["trusted_key"], request["policy"]
        )
        if not provenance["ok"]:
            findings.append(
                {
                    "severity": "high",
                    "title": "Candidate provenance failed policy verification",
                    "detail": "; ".join(
                        c["check"] for c in provenance["checks"] if not c["ok"]
                    ),
                }
            )
    else:
        findings.append(
            {
                "severity": "info",
                "title": "Origin not verified",
                "detail": "No complete trusted-key provenance policy was supplied. Artifact comparison alone does not authenticate a release.",
            }
        )
    behavior_changes = 0
    if ("baseline_behavior" in request) != ("candidate_behavior" in request):
        raise ValueError("Supply both recorded behavior traces")
    if "baseline_behavior" in request:
        a, b = (
            _behavior(request["baseline_behavior"]),
            _behavior(request["candidate_behavior"]),
        )
        for ident in sorted(set(a) | set(b)):
            if a.get(ident) != b.get(ident):
                behavior_changes += 1
                events.append(
                    {
                        "path": ident,
                        "change": "behavior_changed",
                        "baseline_sha256": hashlib.sha256(
                            canonical(a[ident])
                        ).hexdigest()
                        if ident in a
                        else "",
                        "candidate_sha256": hashlib.sha256(
                            canonical(b[ident])
                        ).hexdigest()
                        if ident in b
                        else "",
                    }
                )
        if behavior_changes:
            findings.append(
                {
                    "severity": "high",
                    "title": f"{behavior_changes} recorded behavior differences",
                    "detail": "Exit codes or output digests differ, or cases were added/removed. Trace authenticity and test coverage must be established independently.",
                }
            )
    return {
        "summary": {
            "baseline_files": len(left),
            "candidate_files": len(right),
            "changed_files": changed,
            "identical_zip": byte_match,
            "provenance": "verified"
            if provenance["ok"]
            else "failed"
            if provenance["ok"] is False
            else "not supplied",
            "behavior_changes": behavior_changes,
        },
        "findings": findings,
        "events": events,
        "details": {
            "change_counts": counts,
            "provenance": provenance,
            "baseline_zip_sha256": hashlib.sha256(baseline).hexdigest(),
            "candidate_zip_sha256": hashlib.sha256(candidate).hexdigest(),
            "baseline_inventory": left,
            "candidate_inventory": right,
            "execution": "No uploaded code was executed; behavior traces are externally recorded assertions.",
        },
    }


def _zip(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, (body, executable) in sorted(files.items()):
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
            archive.writestr(info, body)
    return buffer.getvalue()


def presets():
    baseline = _zip(
        {
            "app.py": (b'print("release 1")\n', False),
            "config.json": (b'{"telemetry":false}\n', False),
        }
    )
    candidate = _zip(
        {
            "app.py": (b'print("release 2")\n', False),
            "config.json": (b'{"telemetry":true}\n', False),
            "scripts/start.sh": (b'#!/bin/sh\nprintf "synthetic fixture"\n', True),
        }
    )
    # Published, deterministic fixture material only; real operators use keygen.
    key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"ReleaseTwin public demo fixture").digest()
    )
    trusted = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    policy = {
        "repository": "https://example.invalid/owner/release-demo",
        "revision": "a" * 40,
        "builder": "local-demo-builder",
    }
    original = sign(baseline, policy, key)
    base = {
        "baseline_zip": base64.b64encode(baseline).decode(),
        "candidate_zip": base64.b64encode(candidate).decode(),
        "attestation": original,
        "trusted_key": trusted,
        "policy": policy,
    }
    clean = copy.deepcopy(base)
    clean["candidate_zip"] = clean["baseline_zip"]
    signed_change = copy.deepcopy(base)
    signed_change["attestation"] = sign(candidate, policy, key)
    behavior = copy.deepcopy(clean)
    empty = hashlib.sha256(b"").hexdigest()
    behavior["baseline_behavior"] = {
        "schema_version": 1,
        "cases": [
            {
                "id": "normal-output",
                "exit_code": 0,
                "stdout_sha256": hashlib.sha256(b"release 1\n").hexdigest(),
                "stderr_sha256": empty,
            }
        ],
    }
    behavior["candidate_behavior"] = copy.deepcopy(behavior["baseline_behavior"])
    behavior["candidate_behavior"]["cases"][0]["stdout_sha256"] = hashlib.sha256(
        b"unexpected output\n"
    ).hexdigest()
    return [
        {"id": ident, "title": title, "summary": description, "input": value}
        for ident, title, description, value in [
            (
                "tampered",
                "Changed release with a stale attestation",
                "Added executable files and changed configuration must also fail the old signed artifact digest.",
                base,
            ),
            (
                "clean",
                "Identical artifact and trusted provenance",
                "A byte-identical comparison with a valid signature and exact pinned policy.",
                clean,
            ),
            (
                "signed-change",
                "Authentic origin, different content",
                "A valid signature authenticates the signer’s claim; it does not make unexpected changes acceptable.",
                signed_change,
            ),
            (
                "behavior",
                "Identical artifact, inconsistent recorded behavior",
                "Compare independently supplied test traces without executing their code.",
                behavior,
            ),
        ]
    ]


def benchmark():
    return [{"scenario": p["id"], **execute(p["input"])["summary"]} for p in presets()]


def add_commands(commands):
    compare = commands.add_parser(
        "compare", help="Compare local ZIP files or stable directory trees"
    )
    compare.add_argument("baseline")
    compare.add_argument("candidate")
    compare.add_argument("--attestation")
    compare.add_argument("--trusted-key")
    compare.add_argument("--policy")
    compare.add_argument("--baseline-behavior")
    compare.add_argument("--candidate-behavior")
    compare.add_argument("--output", type=Path)
    keygen = commands.add_parser(
        "keygen", help="Generate an operator Ed25519 key pair in a new directory"
    )
    keygen.add_argument("directory", type=Path)
    attest = commands.add_parser(
        "attest", help="Sign the exact bytes of a local ZIP artifact"
    )
    attest.add_argument("artifact")
    attest.add_argument("--private-key", required=True)
    attest.add_argument("--policy", required=True)
    attest.add_argument("--out", required=True, type=Path)


def cli_request(args):
    password = os.getenv("RELEASETWIN_KEY_PASSWORD")
    if args.command == "keygen":
        args.directory.mkdir(parents=True, exist_ok=False)
        key = Ed25519PrivateKey.generate()
        encryption = (
            serialization.BestAvailableEncryption(password.encode())
            if password
            else serialization.NoEncryption()
        )
        private = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        )
        fd = os.open(
            args.directory / "signing.private.pem",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(fd, "wb") as output:
            output.write(private)
        (args.directory / "trusted.public.pem").write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        print(
            "Generated signing.private.pem and trusted.public.pem. Keep the private key outside release and evidence archives."
        )
        raise SystemExit(0)
    if args.command == "attest":
        artifact = read_artifact(args.artifact)
        if Path(args.artifact).is_dir():
            raise ValueError(
                "Attestation requires an existing ZIP; sign exactly the bytes you will distribute"
            )
        key = serialization.load_pem_private_key(
            Path(args.private_key).read_bytes(),
            password=password.encode() if password else None,
        )
        policy = read_json(Path(args.policy).read_bytes())
        signed = canonical(sign(artifact, policy, key))
        with args.out.open("xb") as output:
            output.write(signed)
        print(str(args.out))
        raise SystemExit(0)
    request = {
        "baseline_zip": base64.b64encode(read_artifact(args.baseline)).decode(),
        "candidate_zip": base64.b64encode(read_artifact(args.candidate)).decode(),
    }
    for option, name in [
        ("attestation", "attestation"),
        ("policy", "policy"),
        ("baseline_behavior", "baseline_behavior"),
        ("candidate_behavior", "candidate_behavior"),
    ]:
        value = getattr(args, option)
        if value:
            request[name] = read_json(Path(value).read_bytes())
    if args.trusted_key:
        request["trusted_key"] = Path(args.trusted_key).read_text(encoding="ascii")
    return request

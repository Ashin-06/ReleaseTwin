"""Ed25519 provenance with an explicit, externally supplied trusted public key."""

import base64
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .lab import canonical, fields, text


def fingerprint(key):
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()


def validate_policy(policy):
    fields(policy, ("repository", "revision", "builder"))
    for name in ("repository", "builder"):
        text(policy[name], name, 512)
    if not isinstance(policy["revision"], str) or not re.fullmatch(
        r"[0-9a-f]{40}|[0-9a-f]{64}", policy["revision"]
    ):
        raise ValueError(
            "revision must be a full lowercase 40- or 64-hex source commit"
        )


def sign(artifact, policy, key):
    validate_policy(policy)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("An Ed25519 private key is required")
    payload = {
        "schema_version": 1,
        **policy,
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
    }
    return {
        "payload": payload,
        "key_id": fingerprint(key.public_key()),
        "signature": base64.b64encode(key.sign(canonical(payload))).decode("ascii"),
    }


def verify(artifact, envelope, trusted_pem, policy):
    validate_policy(policy)
    checks = []

    def check(name, ok, detail):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    try:
        fields(envelope, ("payload", "key_id", "signature"))
        payload = envelope["payload"]
        fields(
            payload,
            ("schema_version", "repository", "revision", "builder", "artifact_sha256"),
        )
        if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
            raise ValueError("Unsupported provenance schema")
        if not isinstance(trusted_pem, str) or len(trusted_pem) > 4096:
            raise ValueError("A bounded trusted PEM public key is required")
        key = serialization.load_pem_public_key(trusted_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Trusted key must be Ed25519")
        check(
            "trusted_key",
            envelope["key_id"] == fingerprint(key),
            "Key identity must match the separately trusted public key.",
        )
        signature = base64.b64decode(envelope["signature"], validate=True)
        key.verify(signature, canonical(payload))
        check(
            "signature", True, "Ed25519 signature verified over the canonical payload."
        )
        check(
            "artifact_digest",
            payload["artifact_sha256"] == hashlib.sha256(artifact).hexdigest(),
            "Signed subject must match the exact candidate ZIP bytes.",
        )
        for name in ("repository", "revision", "builder"):
            check(
                name,
                payload[name] == policy[name],
                f"Signed {name} must equal the operator policy.",
            )
    except (ValueError, TypeError, KeyError, UnicodeError, InvalidSignature) as exc:
        check(
            "signature_or_structure",
            False,
            "Invalid signature or provenance structure: "
            + (str(exc) or type(exc).__name__),
        )
    return {"ok": bool(checks) and all(c["ok"] for c in checks), "checks": checks}

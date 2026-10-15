import base64
import copy
import hashlib
import io
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from releasetwin import engine
from releasetwin.artifacts import inventory_zip, pack_directory
from releasetwin.provenance import sign, verify


class ReleaseTests(unittest.TestCase):
    def preset(self, ident):
        return copy.deepcopy(
            next(p["input"] for p in engine.presets() if p["id"] == ident)
        )

    def test_clean_artifact_and_trusted_signature(self):
        result = engine.execute(self.preset("clean"))
        self.assertEqual(result["summary"]["provenance"], "verified")
        self.assertEqual(result["summary"]["changed_files"], 0)

    def test_altered_artifact_fails_signed_subject_binding(self):
        result = engine.execute(self.preset("tampered"))
        self.assertEqual(result["summary"]["provenance"], "failed")
        self.assertEqual(result["summary"]["changed_files"], 3)
        self.assertIn(
            "scripts/start.sh",
            [e["path"] for e in result["events"] if e.get("candidate_executable")],
        )

    def test_a_valid_signature_does_not_approve_different_content(self):
        result = engine.execute(self.preset("signed-change"))
        self.assertEqual(result["summary"]["provenance"], "verified")
        self.assertGreater(result["summary"]["changed_files"], 0)

    def test_wrong_trusted_key_and_wrong_policy_are_rejected(self):
        request = self.preset("clean")
        key = Ed25519PrivateKey.generate().public_key()
        request["trusted_key"] = key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        self.assertEqual(engine.execute(request)["summary"]["provenance"], "failed")
        request = self.preset("clean")
        request["policy"]["builder"] = "untrusted-builder"
        self.assertEqual(engine.execute(request)["summary"]["provenance"], "failed")

    def test_altered_signed_payload_fails_verification(self):
        request = self.preset("clean")
        request["attestation"]["payload"]["revision"] = "b" * 40
        self.assertEqual(engine.execute(request)["summary"]["provenance"], "failed")

    def test_recorded_behavior_changes_are_reported_without_execution(self):
        result = engine.execute(self.preset("behavior"))
        self.assertEqual(result["summary"]["behavior_changes"], 1)
        self.assertTrue(result["summary"]["identical_zip"])

    def zip_entries(self, entries):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, content, mode in entries:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                archive.writestr(info, content)
        return output.getvalue()

    def test_traversal_absolute_and_nonportable_paths_are_rejected(self):
        for path in (
            "../outside",
            "/absolute",
            "C:/drive",
            "a\\b",
            "a/./b",
            "NUL.txt",
            "file.",
            "a//b",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                # Windows ZipInfo normalizes backslashes when constructing a ZIP;
                # replace the on-disk filename bytes to exercise hostile input.
                raw = self.zip_entries(
                    [(path.replace("\\", "/"), b"x", stat.S_IFREG | 0o644)]
                )
                if "\\" in path:
                    raw = raw.replace(path.replace("\\", "/").encode(), path.encode())
                inventory_zip(raw)

    def test_case_collisions_symlinks_and_parent_file_conflicts(self):
        for entries in (
            [("A", b"x", 0), ("a", b"y", 0)],
            [("link", b"/outside", stat.S_IFLNK | 0o777)],
            [("a", b"x", 0), ("a/b", b"y", 0)],
            [("A", b"x", 0), ("a/b", b"y", 0)],
        ):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                inventory_zip(self.zip_entries(entries))

    def test_compression_bomb_is_bounded(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("large.txt", b"0" * 100000)
        with self.assertRaises(ValueError):
            inventory_zip(buffer.getvalue())

    def test_local_directory_pack_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "note.txt").write_text("hello")
            first = pack_directory(root)
            second = pack_directory(root)
            self.assertEqual(first, second)
            self.assertEqual(
                inventory_zip(first)["note.txt"]["sha256"],
                hashlib.sha256(b"hello").hexdigest(),
            )

    def test_generated_key_can_sign_and_verify_exact_artifact(self):
        request = self.preset("clean")
        artifact = base64.b64decode(request["candidate_zip"])
        key = Ed25519PrivateKey.generate()
        pem = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        envelope = sign(artifact, request["policy"], key)
        self.assertTrue(verify(artifact, envelope, pem, request["policy"])["ok"])

    def test_incomplete_provenance_and_invalid_behavior_fail_cleanly(self):
        request = self.preset("clean")
        del request["trusted_key"]
        with self.assertRaises(ValueError):
            engine.execute(request)
        request = self.preset("behavior")
        request["candidate_behavior"]["cases"][0]["stdout_sha256"] = "invalid"
        with self.assertRaises(ValueError):
            engine.execute(request)

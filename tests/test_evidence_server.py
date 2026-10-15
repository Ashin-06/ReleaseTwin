import copy
import hashlib
import http.client
import json
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from releasetwin import engine, lab


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.request = copy.deepcopy(engine.presets()[0]["input"])
        self.result = engine.execute(self.request)
        self.case = lab.save_case(self.root / "case", self.request, self.result, engine)

    def tearDown(self):
        self.temp.cleanup()

    def test_case_hashes_and_replay(self):
        self.assertTrue(lab.verify_case(self.case, engine)["ok"])

    def test_existing_case_is_not_overwritten(self):
        before = (self.case / "input.json").read_bytes()
        with self.assertRaises(FileExistsError):
            lab.save_case(self.case, self.request, self.result, engine)
        self.assertEqual(before, (self.case / "input.json").read_bytes())

    def test_tampered_result_is_detected(self):
        (self.case / "result.json").write_text("{}")
        self.assertFalse(lab.verify_case(self.case, engine)["ok"])

    def test_self_consistent_forgery_fails_replay(self):
        result = copy.deepcopy(self.result)
        result["summary"]["forged"] = True
        raw = lab.canonical(result)
        (self.case / "result.json").write_bytes(raw)
        manifest = lab.read_json((self.case / "manifest.json").read_bytes())
        manifest["files"]["result.json"] = hashlib.sha256(raw).hexdigest()
        (self.case / "manifest.json").write_bytes(lab.canonical(manifest))
        check = lab.verify_case(self.case, engine)
        self.assertFalse(check["ok"])
        self.assertIn("Replay disagrees", " ".join(check["problems"]))

    def test_missing_extra_and_unsafe_manifest_paths(self):
        (self.case / "extra").write_text("unrecorded")
        self.assertFalse(lab.verify_case(self.case, engine)["ok"])
        (self.case / "extra").unlink()
        manifest = lab.read_json((self.case / "manifest.json").read_bytes())
        manifest["files"]["../outside"] = "0" * 64
        (self.case / "manifest.json").write_bytes(lab.canonical(manifest))
        self.assertFalse(lab.verify_case(self.case, engine)["ok"])

    def test_bundle_includes_only_verified_files(self):
        import io

        with zipfile.ZipFile(io.BytesIO(lab.bundle_case(self.case, engine))) as archive:
            self.assertEqual(
                set(archive.namelist()),
                {"input.json", "result.json", "report.html", "manifest.json"},
            )

    def test_report_escapes_untrusted_text(self):
        result = copy.deepcopy(self.result)
        result["findings"] = [
            {
                "severity": "high",
                "title": "<script>alert(1)</script>",
                "detail": "<img src=x onerror=alert(1)>",
            }
        ]
        rendered = lab.report_html(engine, result)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img src=x", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_json_rejects_duplicate_keys_and_nonfinite_values(self):
        for body in (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":Infinity}',
            b'{"a":1e999}',
            b'{"a":-1e999}',
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                lab.read_json(body)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.server = lab.create_server(engine, 0, cls.temp.name)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.meta = json.loads(urlopen(cls.base + "/api/meta", timeout=5).read())

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temp.cleanup()

    def post(self, path, data, headers=None):
        values = {"Content-Type": "application/json", "X-Lab-Token": self.meta["token"]}
        values.update(headers or {})
        req = Request(
            self.base + path, data=lab.canonical(data), headers=values, method="POST"
        )
        try:
            response = urlopen(req, timeout=15)
        except HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read())

    def test_dashboard_is_accessible_with_strict_headers(self):
        with urlopen(self.base + "/", timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertIn(
                "frame-ancestors", response.headers["Content-Security-Policy"]
            )
            self.assertIn(b"Decision ledger", response.read())

    def test_real_analysis_endpoint_and_evidence_export(self):
        request = engine.presets()[0]["input"]
        status, result = self.post("/api/run", request)
        self.assertEqual(status, 200)
        self.assertEqual(result["summary"], engine.execute(request)["summary"])
        status, saved = self.post("/api/save", request)
        self.assertEqual(status, 201)
        with urlopen(
            self.base + f"/api/cases/{saved['id']}/verify", timeout=15
        ) as response:
            self.assertTrue(json.loads(response.read())["ok"])
        with urlopen(self.base + saved["report_url"], timeout=15) as response:
            body = response.read()
            policy = response.headers["Content-Security-Policy"]
            import base64

            style = body.split(b"<style>", 1)[1].split(b"</style>", 1)[0]
            digest = base64.b64encode(hashlib.sha256(style).digest()).decode("ascii")
            self.assertIn(f"style-src 'sha256-{digest}'", policy)
            self.assertIn("default-src 'none'", policy)
            self.assertNotIn("unsafe-inline", policy)
        with urlopen(self.base + saved["bundle_url"], timeout=15) as response:
            self.assertEqual(response.headers["Content-Type"], "application/zip")
            self.assertTrue(response.read().startswith(b"PK"))

    def test_cross_origin_and_missing_token_are_rejected(self):
        request = engine.presets()[0]["input"]
        self.assertEqual(
            self.post("/api/run", request, {"Origin": "https://attacker.invalid"})[0],
            403,
        )
        self.assertEqual(self.post("/api/run", request, {"X-Lab-Token": ""})[0], 403)

    def test_dns_rebinding_host_is_rejected(self):
        req = Request(
            self.base + "/api/meta",
            headers={"Host": f"localhost.attacker.invalid:{self.server.server_port}"},
        )
        with self.assertRaises(HTTPError) as caught:
            urlopen(req, timeout=5)
        self.assertEqual(caught.exception.code, 403)

    def test_invalid_input_is_clean_error(self):
        status, error = self.post("/api/run", {"unexpected": True})
        self.assertEqual(status, 400)
        self.assertIn("error", error)

    def test_malformed_and_duplicate_lengths_are_rejected(self):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=5
        )
        try:
            connection.putrequest("POST", "/api/run")
            connection.putheader("X-Lab-Token", self.meta["token"])
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "2")
            connection.putheader("Content-Length", "2")
            connection.endheaders(b"{}")
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
        finally:
            connection.close()

    def test_content_length_limit(self):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=5
        )
        try:
            connection.putrequest("POST", "/api/run")
            connection.putheader("X-Lab-Token", self.meta["token"])
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(lab.MAX_BODY + 1))
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 413)
            response.read()
        finally:
            connection.close()

    def test_raw_editor_json_is_strict_and_server_recovers(self):
        headers = {
            "Content-Type": "application/json",
            "X-Lab-Token": self.meta["token"],
        }
        for route in ("/api/run", "/api/parse"):
            for body in (b'{"duplicate":1,"duplicate":2}', b'{"value":1e999}', b"{"):
                request = Request(
                    self.base + route, data=body, headers=headers, method="POST"
                )
                with (
                    self.subTest(route=route, body=body),
                    self.assertRaises(HTTPError) as caught,
                ):
                    urlopen(request, timeout=5)
                self.assertEqual(caught.exception.code, 400)
                self.assertIn("error", json.loads(caught.exception.read()))
        status, parsed = self.post(
            "/api/parse", {"nested": {"a": [1, 2, 3]}, "label": "<script>"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(parsed["input"]["nested"]["a"], [1, 2, 3])
        self.assertEqual(self.post("/api/run", engine.presets()[0]["input"])[0], 200)

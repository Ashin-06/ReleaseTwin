"""Local CLI, loopback workbench, and reproducible evidence storage."""

import argparse
import base64
import hashlib
import html
import io
import json
import secrets
import sys
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

VERSION = "1.0.0"
MAX_BODY = 12 * 1024 * 1024


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(data):
    if len(data) > MAX_BODY:
        raise ValueError("JSON input exceeds the 12 MiB limit")

    def constant(value):
        raise ValueError(f"Non-finite JSON number: {value}")

    try:
        return json.loads(data, object_pairs_hook=_pairs, parse_constant=constant)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid or excessively nested JSON") from exc


def fields(value, required, optional=()):
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    missing = set(required) - set(value)
    extra = set(value) - set(required) - set(optional)
    if missing or extra:
        raise ValueError(
            f"Invalid fields: missing={sorted(missing)}, extra={sorted(extra)}"
        )


def integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer between {low} and {high}")
    return value


def text(value, name, maximum=200):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(
            f"{name} must be nonempty text of at most {maximum} characters"
        )
    return value


def report_html(engine, result):
    escape = lambda v: html.escape(str(v), quote=True)
    cards = "".join(
        f"<div><small>{escape(k.replace('_', ' '))}</small><strong>{escape(v)}</strong></div>"
        for k, v in result.get("summary", {}).items()
    )
    findings = (
        "".join(
            f"<li><b>{escape(f['severity'].upper())} · {escape(f['title'])}</b><p>{escape(f['detail'])}</p></li>"
            for f in result.get("findings", [])
        )
        or "<li>No findings in this run.</li>"
    )
    events = result.get("events", [])
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        f"<title>{escape(engine.APP_NAME)} report</title><style>"
        "body{max-width:1120px;margin:40px auto;padding:0 24px;font:15px/1.6 system-ui;color:#152238}"
        ".cards{display:flex;gap:12px;flex-wrap:wrap}.cards div{background:#eef3f8;padding:16px;border-radius:10px}"
        "small{display:block}strong{font-size:24px}pre{overflow:auto;padding:16px;background:#f4f6f8;white-space:pre-wrap}"
        "h1{letter-spacing:-1px}footer{color:#526077}</style>"
        f'<h1>{escape(engine.APP_NAME)}</h1><p>{escape(engine.TAGLINE)}</p><div class="cards">{cards}</div>'
        f"<h2>Findings</h2><ul>{findings}</ul><h2>Details</h2><pre>{escape(json.dumps(result.get('details', {}), indent=2, ensure_ascii=False))}</pre>"
        f"<h2>Decision ledger · {len(events)} events</h2><p>Showing at most 200 events. The complete ledger is in result.json.</p>"
        f"<pre>{escape(json.dumps(events[:200], indent=2, ensure_ascii=False))}</pre>"
        f"<footer>{escape(engine.APP_NAME)} {VERSION} · Controlled, reproducible analysis; consult THREAT_MODEL.md for limits.</footer></html>"
    )


def save_case(destination, request, result, engine):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()  # An existing case is never overwritten.
    files = {
        "input.json": canonical(request),
        "result.json": canonical(result),
        "report.html": report_html(engine, result).encode("utf-8"),
    }
    for name, body in files.items():
        (destination / name).write_bytes(body)
    manifest = {
        "schema_version": 1,
        "application": engine.APP_NAME,
        "version": VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "files": {
            name: hashlib.sha256(body).hexdigest() for name, body in files.items()
        },
    }
    (destination / "manifest.json").write_bytes(canonical(manifest))
    return destination


def verify_case(directory, engine, replay=True):
    directory = Path(directory)
    problems = []
    expected = {"input.json", "result.json", "report.html", "manifest.json"}
    if directory.is_symlink() or not directory.is_dir():
        return {"ok": False, "problems": ["Case must be a real directory"]}
    if {p.name for p in directory.iterdir()} != expected:
        return {"ok": False, "problems": ["Missing or extra case files"]}
    try:
        if any(
            (directory / name).is_symlink() or not (directory / name).is_file()
            for name in expected
        ):
            raise ValueError("Symlinks and non-files are not accepted")
        manifest = read_json((directory / "manifest.json").read_bytes())
        if (
            manifest.get("application") != engine.APP_NAME
            or manifest.get("schema_version") != 1
            or manifest.get("version") != VERSION
        ):
            raise ValueError("Wrong application, schema, or replay version")
        if set(manifest.get("files", {})) != expected - {"manifest.json"}:
            raise ValueError("Invalid manifest file list")
        for name, digest in manifest["files"].items():
            if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
                problems.append(f"Hash mismatch: {name}")
        if replay and not problems:
            request = read_json((directory / "input.json").read_bytes())
            result = engine.execute(request)
            if canonical(result) != (directory / "result.json").read_bytes():
                problems.append("Replay disagrees with recorded result")
            if (
                report_html(engine, result).encode("utf-8")
                != (directory / "report.html").read_bytes()
            ):
                problems.append("Report disagrees with replay")
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        problems.append(str(exc))
    return {
        "ok": not problems,
        "problems": problems,
        "replayed": replay and not problems,
    }


def bundle_case(directory, engine):
    check = verify_case(directory, engine)
    if not check["ok"]:
        raise ValueError("Case verification failed: " + "; ".join(check["problems"]))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(Path(directory).iterdir()):
            archive.writestr(path.name, path.read_bytes())
    return output.getvalue()


def create_server(engine, port, data_dir):
    root = Path(data_dir).resolve()
    static = Path(__file__).with_name("static")
    limit = threading.BoundedSemaphore(4)
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(8)

        def _send(
            self,
            status,
            body,
            content_type="application/json; charset=utf-8",
            report=False,
        ):
            if isinstance(body, (dict, list)):
                body = canonical(body)
            elif isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            policy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            if report:
                # Allow only this verified report's generated style block, not
                # arbitrary inline styles or scripts from scenario content.
                style = body.split(b"<style>", 1)[1].split(b"</style>", 1)[0]
                digest = base64.b64encode(hashlib.sha256(style).digest()).decode(
                    "ascii"
                )
                policy = f"default-src 'none'; style-src 'sha256-{digest}'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            self.send_header("Content-Security-Policy", policy)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _host(self):
            allowed = {
                f"localhost:{self.server.server_port}",
                f"127.0.0.1:{self.server.server_port}",
            }
            hosts = self.headers.get_all("Host", [])
            return len(hosts) == 1 and hosts[0] in allowed

        def do_GET(self):
            if not self._host():
                return self._send(
                    403, {"error": "Only exact localhost hosts are accepted"}
                )
            try:
                path = urlsplit(self.path).path
                if path in ("/", "/app.js", "/style.css"):
                    name = "index.html" if path == "/" else path[1:]
                    content_type = {
                        "index.html": "text/html; charset=utf-8",
                        "app.js": "text/javascript; charset=utf-8",
                        "style.css": "text/css; charset=utf-8",
                    }[name]
                    return self._send(200, (static / name).read_bytes(), content_type)
                if path == "/api/meta":
                    return self._send(
                        200,
                        {
                            "name": engine.APP_NAME,
                            "tagline": engine.TAGLINE,
                            "version": VERSION,
                            "token": token,
                            "presets": engine.presets(),
                            "capabilities": engine.CAPABILITIES,
                        },
                    )
                if path == "/api/cases":
                    cases = (
                        sorted(
                            (
                                p.name
                                for p in root.iterdir()
                                if p.is_dir()
                                and not p.is_symlink()
                                and len(p.name) == 32
                            ),
                            reverse=True,
                        )
                        if root.exists()
                        else []
                    )
                    return self._send(200, {"cases": cases[:100]})
                parts = path.strip("/").split("/")
                if len(parts) == 4 and parts[:2] == ["api", "cases"]:
                    case_id, kind = parts[2:]
                    if len(case_id) != 32 or any(
                        c not in "0123456789abcdef" for c in case_id
                    ):
                        raise ValueError("Invalid case identifier")
                    directory = root / case_id
                    if kind == "verify":
                        return self._send(200, verify_case(directory, engine))
                    if kind == "report":
                        if not verify_case(directory, engine)["ok"]:
                            raise ValueError("Case failed verification")
                        return self._send(
                            200,
                            (directory / "report.html").read_bytes(),
                            "text/html; charset=utf-8",
                            report=True,
                        )
                    if kind == "bundle":
                        return self._send(
                            200, bundle_case(directory, engine), "application/zip"
                        )
                return self._send(404, {"error": "Not found"})
            except (ValueError, OSError) as exc:
                return self._send(400, {"error": str(exc)})

        def do_POST(self):
            if not self._host():
                return self._send(
                    403, {"error": "Only localhost requests are accepted"}
                )
            origin = self.headers.get("Origin")
            allowed = {
                f"http://localhost:{self.server.server_port}",
                f"http://127.0.0.1:{self.server.server_port}",
            }
            if origin and origin not in allowed:
                return self._send(403, {"error": "Cross-origin requests are rejected"})
            if self.headers.get("X-Lab-Token") != token:
                return self._send(
                    403, {"error": "Missing local-session token; fetch /api/meta first"}
                )
            if self.headers.get_content_type() != "application/json":
                return self._send(415, {"error": "Use application/json"})
            if (
                self.headers.get("Transfer-Encoding")
                or len(self.headers.get_all("Content-Length", [])) != 1
            ):
                return self._send(
                    400,
                    {
                        "error": "A single Content-Length and no transfer encoding are required"
                    },
                )
            if not limit.acquire(blocking=False):
                return self._send(429, {"error": "Four analyses are already running"})
            try:
                size = int(self.headers["Content-Length"])
                if not 0 < size <= MAX_BODY:
                    return self._send(
                        413, {"error": "Payload must be between 1 byte and 12 MiB"}
                    )
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError("Incomplete body")
                data = read_json(raw)
                path = urlsplit(self.path).path
                if path == "/api/minimize" and hasattr(engine, "minimize"):
                    return self._send(200, engine.minimize(data))
                if path not in ("/api/run", "/api/save"):
                    return self._send(404, {"error": "Not found"})
                result = engine.execute(data)
                if path == "/api/run":
                    return self._send(200, result)
                case_id = uuid.uuid4().hex
                save_case(root / case_id, data, result, engine)
                return self._send(
                    201,
                    {
                        "id": case_id,
                        "report_url": f"/api/cases/{case_id}/report",
                        "bundle_url": f"/api/cases/{case_id}/bundle",
                        "summary": result["summary"],
                    },
                )
            except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
                return self._send(400, {"error": str(exc)})
            finally:
                limit.release()

        def log_message(self, fmt, *args):
            # Do not log input scenarios, tokens, archive contents, or file paths.
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def cli(engine):
    parser = argparse.ArgumentParser(description=engine.TAGLINE)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Start the local workbench")
    serve.add_argument("--port", type=int, default=engine.PORT)
    serve.add_argument("--data-dir", default=".lab/cases")
    run = commands.add_parser("run", help="Run a JSON input")
    run.add_argument("input", type=Path)
    run.add_argument(
        "--output", type=Path, help="New evidence directory; never overwritten"
    )
    demo = commands.add_parser("demo", help="Run a complete reproducible demonstration")
    demo.add_argument("--output", type=Path)
    commands.add_parser("benchmark", help="Run every bundled scenario")
    commands.add_parser("presets", help="Print bundled input scenarios")
    verify = commands.add_parser(
        "verify", help="Check hashes and independently replay a case"
    )
    verify.add_argument("directory", type=Path)
    bundle = commands.add_parser("bundle", help="Export a verified case as ZIP")
    bundle.add_argument("directory", type=Path)
    bundle.add_argument("output", type=Path)
    if hasattr(engine, "add_commands"):
        engine.add_commands(commands)
    args = parser.parse_args()
    try:
        if args.command == "serve":
            server = create_server(engine, args.port, args.data_dir)
            print(
                f"{engine.APP_NAME} {VERSION}: http://127.0.0.1:{server.server_port}",
                flush=True,
            )
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
        if args.command == "verify":
            check = verify_case(args.directory, engine)
            print(json.dumps(check, indent=2))
            return 0 if check["ok"] else 1
        if args.command == "bundle":
            verified_bundle = bundle_case(args.directory, engine)
            with args.output.open("xb") as target:
                target.write(verified_bundle)
            print(str(args.output))
            return 0
        if args.command == "presets":
            print(json.dumps(engine.presets(), indent=2))
            return 0
        if args.command == "benchmark":
            print(json.dumps(engine.benchmark(), indent=2))
            return 0
        if args.command in ("run", "demo"):
            request = (
                read_json(args.input.read_bytes())
                if args.command == "run"
                else engine.presets()[0]["input"]
            )
        else:
            request = engine.cli_request(args)
        result = engine.execute(request)
        if getattr(args, "output", None):
            save_case(args.output, request, result, engine)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 1 if result.get("exit_failure", False) else 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

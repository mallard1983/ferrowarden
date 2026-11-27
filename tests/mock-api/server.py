#!/usr/bin/env python3
"""
Mock API Server for Ferrowarden Integration Tests

Accepts any HTTP method on any path. Logs the full request — method, path,
headers, and body — in memory. Provides management endpoints so tests can
inspect exactly what Ferrowarden forwarded.

Why this exists:
  Ferrowarden's core security property is that credential values are
  substituted *before* the outbound request is sent, and are scrubbed
  *from* the inbound response. To verify this, tests need to see the
  actual HTTP request that left Ferrowarden's forward() handler. This
  server is that observer.

Management endpoints (not logged themselves):
  GET  /__requests__       — return all captured requests as JSON
  GET  /__requests__/last  — return the most recent captured request
  POST /__reset__          — clear the request log (call between tests)
  GET  /__health__         — liveness check
  GET  /__notifications__        — requests sent to the notification sink
  POST /__notifications__/reset  — clear the notification log

Notification sink: the test stack gives this container a second network alias,
"notify-sink", which Ferrowarden's notifier posts to. A request whose Host is
"notify-sink" is captured in its own log (the /__notifications__ endpoints),
not in the main one, so a notification that arrives while a test inspects
/__requests__/last cannot be mistaken for a forwarded request.

Login services (captured sessions, docs/sessions.md): two small services that
issue session tokens, so the integration tests can prove that a token captured
by Ferrowarden never reaches the agent and that `{{session:NAME}}` delivers the
exact value. Both accept the seeded `test_login_full` username and password and
nothing else. Every token they issue is listed at GET /__issued__ (a
management endpoint, for tests only) so a test can hand it to the secret gate.
  Portainer-like
    POST /api/auth                  JSON {"username","password"} -> {"jwt": ...}
                                    (a real-looking JWT that expires in an hour)
    GET  /api/portainer/endpoints   needs "Authorization: Bearer <that jwt>"
  Proxmox-like
    POST /api2/json/access/ticket   form body username=...&password=... ->
                                    {"data":{"ticket","CSRFPreventionToken"}} and
                                    Set-Cookie: PVEAuthCookie=<url-encoded ticket>
    GET  /api2/json/nodes           needs the cookie
    POST /api2/json/nodes/<n>/qemu/<id>/status/stop
                                    needs the cookie and the CSRFPreventionToken header
  PHP-like
    POST /api/php/login             -> {"token": ...} written like PHP's
                                    json_encode: every slash escaped with a backslash
    GET  /api/php/me                needs "Authorization: Bearer <that token>"
  A new service's setup API (credential creation, docs/managed-credentials.md)
    POST /api/created/setup         JSON {"password": ...} -> {"ok": true, "length": N}
                                    (the password is kept, and listed at
                                    GET /__issued__ as "created_password", so a
                                    test can compare it with what Vaultwarden
                                    stores and the secret gate can search for it)
  Careless targets
    GET  /api/reflect               returns every token it was sent in the body
                                    (raw, base64, URL-encoded), a header and an
                                    X-Reflected header
    GET  /api/reflect-error         the same in a 403 body
    GET  /api/leak-last-token       mentions the newest issued JWT although the
                                    request carried none

All other paths are captured and return 200 OK with {"captured": true, "id": N}.

Paths containing "/echo" are captured and respond with the full captured
request (headers, body, path) — like httpbin's /anything. Tests use this to
prove that credentials echoed back by a target are scrubbed before they reach
the agent. Paths containing "/echo-header" also copy every request header
value into a response header (X-Echo-<name>).
"""

import base64
import json
import secrets
import threading
import time
import os
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

# Thread-safe log of all captured requests.
# Each entry is a dict with: id, timestamp, method, path, headers, body.
_requests: list[dict] = []
_notifications: list[dict] = []
_lock = threading.Lock()
_counter = 0
_notify_counter = 0

NOTIFY_SINK_HOST = "notify-sink"

# The seeded `test_login_full` login (tests/seed/credentials.json): test data.
LOGIN_USER = "test-full-user"
LOGIN_PASSWORD = "test-full-pass-88880000"

# Tokens issued by the login services, newest last.
_issued: dict[str, list[str]] = {
    "portainer_jwt": [], "pve_ticket": [], "pve_csrf": [], "php_token": [],
    "created_password": [],
}


def _make_php_token() -> str:
    """An opaque standard-base64 token whose alphabet includes '/' and '+'."""
    while True:
        token = base64.b64encode(secrets.token_bytes(36)).decode()
        if "/" in token and "+" in token:
            return token


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt() -> str:
    """A JWT shaped like Portainer's, expiring in an hour (signature is random)."""
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(
        json.dumps(
            {"id": 1, "username": LOGIN_USER, "role": 1, "scope": "default",
             "exp": now + 3600, "iat": now},
            separators=(",", ":"),
        ).encode()
    )
    return f"{header}.{payload}.{_b64url(secrets.token_bytes(32))}"


def _make_ticket() -> tuple[str, str]:
    """A Proxmox-like (ticket, CSRFPreventionToken) pair."""
    stamp = "%08X" % int(time.time())
    ticket = f"PVE:{LOGIN_USER}@pam:{stamp}::" + base64.b64encode(secrets.token_bytes(48)).decode()
    csrf = f"{stamp}:" + base64.b64encode(secrets.token_bytes(24)).decode()
    return ticket, csrf


MANAGEMENT_PATHS = {
    "/__issued__",
    "/__issued__/reset",
    "/__requests__",
    "/__requests__/last",
    "/__reset__",
    "/__health__",
    "/__notifications__",
    "/__notifications__/reset",
}


class RequestHandler(BaseHTTPRequestHandler):
    """Handle every incoming HTTP request."""

    def log_message(self, fmt, *args):
        # Suppress default access log — structured output only
        pass

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return self.rfile.read(length).decode("utf-8", errors="replace")
        return ""

    def _send_json(self, status: int, data) -> None:
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_management(self) -> bool:
        """
        Handle management endpoints. Returns True if the request was handled
        (and should not be logged), False if it should fall through to capture.
        """
        path = self.path.split("?")[0]

        if path == "/__health__":
            with _lock:
                count = len(_requests)
            self._send_json(200, {"status": "ok", "captured_requests": count})
            return True

        if path == "/__requests__" and self.command == "GET":
            with _lock:
                data = list(_requests)
            self._send_json(200, data)
            return True

        if path == "/__requests__/last" and self.command == "GET":
            with _lock:
                data = _requests[-1] if _requests else None
            if data:
                self._send_json(200, data)
            else:
                self._send_json(404, {"error": "no requests captured yet"})
            return True

        if path == "/__notifications__" and self.command == "GET":
            with _lock:
                data = list(_notifications)
            self._send_json(200, data)
            return True

        if path == "/__notifications__/reset" and self.command == "POST":
            with _lock:
                cleared = len(_notifications)
                _notifications.clear()
            print(f"[reset] cleared {cleared} captured notifications", flush=True)
            self._send_json(200, {"cleared": cleared})
            return True

        if path == "/__issued__" and self.command == "GET":
            with _lock:
                data = {k: list(v) for k, v in _issued.items()}
            self._send_json(200, data)
            return True

        if path == "/__issued__/reset" and self.command == "POST":
            with _lock:
                for v in _issued.values():
                    v.clear()
            self._send_json(200, {"cleared": True})
            return True

        if path == "/__reset__" and self.command == "POST":
            with _lock:
                cleared = len(_requests)
                _requests.clear()
            print(f"[reset] cleared {cleared} captured requests", flush=True)
            self._send_json(200, {"cleared": cleared})
            return True

        return False

    def _is_notify_sink(self) -> bool:
        host = self.headers.get("Host", "").split(":")[0].strip().lower()
        return host == NOTIFY_SINK_HOST

    def _capture_notification(self, body: str) -> None:
        """Record a request made to the notification sink, in its own log."""
        global _notify_counter

        with _lock:
            _notify_counter += 1
            _notifications.append(
                {
                    "id": _notify_counter,
                    "timestamp": time.time(),
                    "method": self.command,
                    "path": self.path,
                    "headers": {k: v for k, v in self.headers.items()},
                    "body": body,
                }
            )
            entry_id = _notify_counter
        print(
            f"[notification #{entry_id}] {self.command} (body: {len(body)} bytes)",
            flush=True,
        )
        self._send_json(200, {"captured": True, "sink": "notifications", "id": entry_id})

    def _capture_and_respond(self) -> None:
        """Record this request and send a 200 echo response."""
        global _counter

        body = self._read_body()

        if self._is_notify_sink():
            self._capture_notification(body)
            return

        with _lock:
            _counter += 1
            entry = {
                "id": _counter,
                "timestamp": time.time(),
                "method": self.command,
                "path": self.path,
                # Convert header object to plain dict for JSON serialisation
                "headers": {k: v for k, v in self.headers.items()},
                "body": body,
            }
            _requests.append(entry)
            entry_id = _counter

        print(
            f"[captured #{entry_id}] {self.command} {self.path} "
            f"(body: {len(body)} bytes)",
            flush=True,
        )

        if self._login_services(entry):
            return

        # Echo back the entry id so tests can correlate
        if "/echo-header" in self.path:
            body = json.dumps(entry).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in entry["headers"].items():
                self.send_header(f"X-Echo-{k}", v)
            self.end_headers()
            self.wfile.write(body)
            return

        if "/echo" in self.path:
            self._send_json(200, entry)
            return

        self._send_json(200, {"captured": True, "id": entry_id})

    # ── Login services ────────────────────────────────────────────────────

    @staticmethod
    def _hdr(entry: dict, name: str) -> str:
        """A captured request header, whatever case the client sent its name in."""
        for k, v in entry["headers"].items():
            if k.lower() == name.lower():
                return v
        return ""

    def _csrf(self, entry: dict) -> str:
        return self._hdr(entry, "CSRFPreventionToken")

    def _bearer(self, entry: dict) -> str:
        auth = self._hdr(entry, "Authorization")
        return auth[7:] if auth.lower().startswith("bearer ") else ""

    def _pve_cookie(self, entry: dict) -> str:
        """The PVEAuthCookie value of the Cookie header, URL-decoded."""
        for part in self._hdr(entry, "Cookie").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "PVEAuthCookie":
                return urllib.parse.unquote(value)
        return ""

    def _login_services(self, entry: dict) -> bool:
        """Answer the login-service routes. True if the request was handled."""
        path = entry["path"].split("?")[0]
        method = entry["method"]
        body = entry["body"]

        if path == "/api/auth" and method == "POST":
            try:
                creds = json.loads(body)
            except ValueError:
                creds = {}
            if (creds.get("username") == LOGIN_USER
                    and creds.get("password") == LOGIN_PASSWORD):
                token = _make_jwt()
                with _lock:
                    _issued["portainer_jwt"].append(token)
                self._send_json(200, {"jwt": token})
            else:
                self._send_json(422, {"message": "Invalid credentials", "details": "Unauthorized"})
            return True

        if path == "/api/created/setup" and method == "POST":
            try:
                data = json.loads(body)
            except ValueError:
                data = {}
            password = data.get("password") if isinstance(data, dict) else None
            if isinstance(password, str) and password:
                with _lock:
                    _issued["created_password"].append(password)
                self._send_json(200, {"ok": True, "length": len(password)})
            else:
                self._send_json(422, {"ok": False, "message": "no password"})
            return True

        if path == "/api/php/login" and method == "POST":
            token = _make_php_token()
            with _lock:
                _issued["php_token"].append(token)
            data = json.dumps({"token": token, "ok": True}).replace("/", "\\/").encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return True

        if path == "/api/php/me" and method == "GET":
            with _lock:
                known = self._bearer(entry) in _issued["php_token"]
            self._send_json(200 if known else 401, {"verified": known})
            return True

        if path == "/api/portainer/endpoints" and method == "GET":
            token = self._bearer(entry)
            with _lock:
                known = token in _issued["portainer_jwt"]
            if known:
                self._send_json(200, {"verified": True, "endpoints": [{"Id": 1, "Name": "local"}]})
            else:
                self._send_json(401, {"message": "Invalid JWT token"})
            return True

        if path == "/api2/json/access/ticket" and method == "POST":
            form = urllib.parse.parse_qs(body)
            if (form.get("username", [""])[0] in (LOGIN_USER, f"{LOGIN_USER}@pam")
                    and form.get("password", [""])[0] == LOGIN_PASSWORD):
                ticket, csrf = _make_ticket()
                with _lock:
                    _issued["pve_ticket"].append(ticket)
                    _issued["pve_csrf"].append(csrf)
                data = json.dumps(
                    {"data": {"ticket": ticket, "CSRFPreventionToken": csrf,
                              "username": f"{LOGIN_USER}@pam"}}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                # Like Proxmox: the cookie carries the ticket URL-encoded.
                self.send_header(
                    "Set-Cookie",
                    f"PVEAuthCookie={urllib.parse.quote(ticket, safe='')}; path=/; "
                    "secure; HttpOnly; SameSite=Lax",
                )
                self.end_headers()
                self.wfile.write(data)
            else:
                self._send_json(401, {"data": None})
            return True

        if path == "/api2/json/nodes" and method == "GET":
            with _lock:
                known = self._pve_cookie(entry) in _issued["pve_ticket"]
            if known:
                self._send_json(200, {"data": [{"node": "pve", "status": "online"}]})
            else:
                self._send_json(401, {"data": None})
            return True

        if path.startswith("/api2/json/nodes/") and path.endswith("/status/stop") and method == "POST":
            with _lock:
                cookie_ok = self._pve_cookie(entry) in _issued["pve_ticket"]
                csrf_ok = self._csrf(entry) in _issued["pve_csrf"]
            if cookie_ok and csrf_ok:
                self._send_json(200, {"data": "UPID:pve:00000001:stop"})
            elif cookie_ok:
                self._send_json(401, {"data": None, "message": "No CSRF prevention token"})
            else:
                self._send_json(401, {"data": None})
            return True

        if path in ("/api/reflect", "/api/reflect-error"):
            sent = {
                "authorization": self._bearer(entry),
                "cookie": self._pve_cookie(entry),
                "csrf": self._csrf(entry),
            }
            sent = {k: v for k, v in sent.items() if v}
            out = {
                "received": sent,
                "base64": {k: base64.b64encode(v.encode()).decode() for k, v in sent.items()},
                "url_encoded": {k: urllib.parse.quote(v, safe="") for k, v in sent.items()},
            }
            data = json.dumps(out).encode()
            self.send_response(403 if path.endswith("-error") else 200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for k, v in sent.items():
                self.send_header("X-Reflected-" + k.capitalize(), v)
            self.end_headers()
            self.wfile.write(data)
            return True

        if path == "/api/leak-last-token" and method == "GET":
            with _lock:
                last = _issued["portainer_jwt"][-1] if _issued["portainer_jwt"] else ""
            self._send_json(200, {"last_token": last, "again": [last]})
            return True

        return False

    def _dispatch(self) -> None:
        path = self.path.split("?")[0]
        if path in MANAGEMENT_PATHS or path.startswith("/__"):
            if not self._handle_management():
                self._capture_and_respond()
        else:
            self._capture_and_respond()

    # Wire every HTTP method to the same dispatcher
    def do_GET(self):    self._dispatch()
    def do_POST(self):   self._dispatch()
    def do_PUT(self):    self._dispatch()
    def do_PATCH(self):  self._dispatch()
    def do_DELETE(self): self._dispatch()
    def do_HEAD(self):   self._dispatch()
    def do_OPTIONS(self):self._dispatch()


def main() -> None:
    port = int(os.environ.get("MOCK_API_PORT", 7777))
    host = os.environ.get("MOCK_API_HOST", "0.0.0.0")

    server = HTTPServer((host, port), RequestHandler)
    print(f"Mock API server listening on {host}:{port}", flush=True)
    print("Management endpoints:", flush=True)
    print("  GET  /__requests__       — all captured requests", flush=True)
    print("  GET  /__requests__/last  — most recent request", flush=True)
    print("  POST /__reset__          — clear log", flush=True)
    print("  GET  /__health__         — liveness check", flush=True)
    print("  GET  /__notifications__  — requests to the notify-sink alias", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

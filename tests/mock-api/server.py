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

All other paths are captured and return 200 OK with {"captured": true, "id": N}.

Paths containing "/echo" are captured and respond with the full captured
request (headers, body, path) — like httpbin's /anything. Tests use this to
prove that credentials echoed back by a target are scrubbed before they reach
the agent. Paths containing "/echo-header" also copy every request header
value into a response header (X-Echo-<name>).
"""

import json
import threading
import time
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

# Thread-safe log of all captured requests.
# Each entry is a dict with: id, timestamp, method, path, headers, body.
_requests: list[dict] = []
_notifications: list[dict] = []
_lock = threading.Lock()
_counter = 0
_notify_counter = 0

NOTIFY_SINK_HOST = "notify-sink"

MANAGEMENT_PATHS = {
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

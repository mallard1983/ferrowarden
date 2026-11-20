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

All other paths are captured and return 200 OK with a JSON echo.
"""

import json
import threading
import time
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

# Thread-safe log of all captured requests.
# Each entry is a dict with: id, timestamp, method, path, headers, body.
_requests: list[dict] = []
_lock = threading.Lock()
_counter = 0

MANAGEMENT_PATHS = {"/__requests__", "/__requests__/last", "/__reset__", "/__health__"}


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

        if path == "/__reset__" and self.command == "POST":
            with _lock:
                cleared = len(_requests)
                _requests.clear()
            print(f"[reset] cleared {cleared} captured requests", flush=True)
            self._send_json(200, {"cleared": cleared})
            return True

        return False

    def _capture_and_respond(self) -> None:
        """Record this request and send a 200 echo response."""
        global _counter

        body = self._read_body()

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
    server.serve_forever()


if __name__ == "__main__":
    main()

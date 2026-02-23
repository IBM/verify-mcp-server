#!/usr/bin/env python3
"""
tests/test_sse_e2e.py
End-to-end SSE (HTTP) transport test for the Verify MCP Server.
Starts the server on port 8004, sends MCP messages over SSE, checks results.
"""
import asyncio
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import httpx

PORT = 8004
BASE = f"http://localhost:{PORT}"

# ── helpers ──────────────────────────────────────────────────────────────────

def start_server():
    env = {**os.environ, "MCP_TRANSPORT": "sse", "MCP_PORT": str(PORT)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "src"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=os.path.dirname(os.path.dirname(__file__)),
    )
    # Wait for startup using TCP probe (SSE /sse keeps connection open; use port probe)
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=1):
                time.sleep(0.5)  # let uvicorn finish binding
                return proc
        except (ConnectionRefusedError, OSError):
            pass
        time.sleep(0.3)
    proc.kill()
    raise RuntimeError("SSE server did not start in 15 s")


def stop_server(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


# ── SSE session helper ────────────────────────────────────────────────────────

class SSESession:
    """
    Opens GET /sse in a background thread (keeping the connection alive),
    extracts the session-unique messages URL, and exposes send() for POSTs.
    """
    def __init__(self, base_url: str):
        self._base = base_url
        self._msg_url: str | None = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._client = httpx.Client(timeout=None)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        # Wait up to 5 s for the endpoint event
        if not self._ready.wait(timeout=5):
            raise RuntimeError("SSE: no endpoint event received in 5 s")

    def _run(self):
        try:
            with self._client.stream("GET", f"{self._base}/sse") as resp:
                for line in resp.iter_lines():
                    if line.startswith("data:") and "/messages/" in line:
                        self._msg_url = self._base + line[5:].strip()
                        self._ready.set()
                    if self._stop.is_set():
                        break
        except Exception:
            self._ready.set()  # unblock if error

    @property
    def msg_url(self) -> str | None:
        return self._msg_url

    def send(self, payload: dict) -> int:
        r = self._client.post(self._msg_url, json=payload, timeout=10)
        return r.status_code

    def close(self):
        self._stop.set()
        self._client.close()
        self._thread.join(timeout=3)


# ── tests ────────────────────────────────────────────────────────────────────

PASS = []
FAIL = []

def check(name, condition, detail=""):
    if condition:
        PASS.append(name)
        print(f"  ✅  {name}")
    else:
        FAIL.append(name)
        print(f"  ❌  {name}  {detail}")


def run_tests():
    print("\n=== Verify MCP Server — SSE E2E Tests ===\n")

    # 1. SSE endpoint responds 200 (HEAD-style check — use stream to get headers quickly)
    try:
        with httpx.Client(timeout=3) as c:
            with c.stream("GET", f"{BASE}/sse") as r:
                check("SSE /sse returns 200", r.status_code == 200)
                check("SSE Content-Type is text/event-stream",
                      "text/event-stream" in r.headers.get("content-type", ""))
    except Exception as e:
        check("SSE /sse returns 200", False, str(e))

    # 2–6. Open a persistent SSE session and send MCP messages
    session = None
    try:
        session = SSESession(BASE)
        check("SSE endpoint event received", session.msg_url is not None,
              f"url={session.msg_url}")

        # 3. initialize
        sc = session.send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "e2e-test", "version": "1.0"},
                "capabilities": {}
            }
        })
        check("initialize accepted (202)", sc == 202, f"got {sc}")

        # 4. initialized notification
        sc = session.send({
            "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}
        })
        check("initialized notification accepted (202)", sc == 202, f"got {sc}")

        # 5. tools/list
        sc = session.send({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
        })
        check("tools/list accepted (202)", sc == 202, f"got {sc}")

        # 6. verify_execute (live call)
        sc = session.send({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "verify_execute",
                "arguments": {
                    "endpoint_id": "getOIDCDiscovery",
                    "params": {}
                }
            }
        })
        check("verify_execute (getOIDCDiscovery) accepted (202)", sc == 202, f"got {sc}")

    except Exception as e:
        check("SSE session", False, str(e))
    finally:
        if session:
            session.close()

    print(f"\n{'='*44}")
    print(f"  PASSED: {len(PASS)}   FAILED: {len(FAIL)}")
    print(f"{'='*44}\n")
    return len(FAIL) == 0


if __name__ == "__main__":
    print("Starting SSE server on port", PORT)
    proc = start_server()
    print(f"Server PID {proc.pid} running\n")
    try:
        ok = run_tests()
    finally:
        stop_server(proc)
        print("Server stopped.")
    sys.exit(0 if ok else 1)

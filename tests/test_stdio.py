"""Stdio MCP protocol test for Verify MCP Server.

Spawns the server as a subprocess, sends MCP JSON-RPC messages over stdin,
and validates the responses for all 4 tools.
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
PYTHON = ROOT / ".venv" / "bin" / "python3"


async def send_recv(proc, msg: dict) -> dict:
    """Send a JSON-RPC message and read the response."""
    line = json.dumps(msg) + "\n"
    proc.stdin.write(line.encode())
    await proc.stdin.drain()
    response_line = await proc.stdout.readline()
    return json.loads(response_line)


async def run_tests():
    print("Starting Verify MCP Server in stdio mode...")
    proc = await asyncio.create_subprocess_exec(
        str(PYTHON), "-m", "src",
        cwd=str(ROOT),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    errors = []

    try:
        # ── 1. Initialize ─────────────────────────────────────────────
        print("\n[1] MCP initialize handshake...")
        init_resp = await send_recv(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        })
        assert init_resp.get("result", {}).get("serverInfo", {}).get("name") == "Verify MCP Server", \
            f"Bad serverInfo: {init_resp}"
        print(f"   Server: {init_resp['result']['serverInfo']}")

        # Send initialized notification
        proc.stdin.write((json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode())
        await proc.stdin.drain()

        # ── 2. List tools ─────────────────────────────────────────────
        print("\n[2] tools/list...")
        tools_resp = await send_recv(proc, {
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        })
        tools = tools_resp.get("result", {}).get("tools", [])
        tool_names = [t["name"] for t in tools]
        expected = {"verify_discover", "verify_list_categories", "verify_get_api_details", "verify_execute"}
        missing = expected - set(tool_names)
        assert not missing, f"Missing tools: {missing}"
        print(f"   Tools registered: {tool_names}")

        # ── 3. verify_list_categories ─────────────────────────────────
        print("\n[3] verify_list_categories...")
        cats_resp = await asyncio.wait_for(
            send_recv(proc, {
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "verify_list_categories", "arguments": {}},
            }),
            timeout=10,
        )
        cats_text = cats_resp["result"]["content"][0]["text"]
        cats_data = json.loads(cats_text)
        assert cats_data["total_categories"] >= 89, f"Expected >=89 categories, got {cats_data['total_categories']}"
        assert cats_data["total_endpoints"] >= 210, f"Expected >=210 endpoints, got {cats_data['total_endpoints']}"
        print(f"   Categories: {cats_data['total_categories']}, Endpoints: {cats_data['total_endpoints']}")

        # ── 4. verify_discover ────────────────────────────────────────
        print("\n[4] verify_discover (query=user)...")
        disc_resp = await asyncio.wait_for(
            send_recv(proc, {
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "verify_discover", "arguments": {"query": "user"}},
            }),
            timeout=10,
        )
        disc_data = json.loads(disc_resp["result"]["content"][0]["text"])
        assert disc_data["matches"] > 0, "Expected matches > 0"
        for ep in disc_data["endpoints"]:
            assert "endpoint_id" in ep and "method" in ep and "path" in ep
        print(f"   Matches: {disc_data['matches']}")

        # ── 5. verify_discover with method filter ─────────────────────
        print("\n[5] verify_discover (query=user, method=GET)...")
        disc2_resp = await asyncio.wait_for(
            send_recv(proc, {
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": "verify_discover", "arguments": {"query": "user", "method": "GET"}},
            }),
            timeout=10,
        )
        disc2_data = json.loads(disc2_resp["result"]["content"][0]["text"])
        for ep in disc2_data["endpoints"]:
            assert ep["method"] == "GET", f"Non-GET result: {ep}"
        print(f"   GET-only matches: {disc2_data['matches']}")

        # ── 6. verify_get_api_details ─────────────────────────────────
        print("\n[6] verify_get_api_details (getUsers)...")
        details_resp = await asyncio.wait_for(
            send_recv(proc, {
                "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                "params": {"name": "verify_get_api_details", "arguments": {"endpoint_id": "getUsers"}},
            }),
            timeout=10,
        )
        details_data = json.loads(details_resp["result"]["content"][0]["text"])
        assert details_data["method"] == "GET"
        assert details_data["path"] == "/v2.0/Users"
        assert "params" in details_data
        print(f"   {details_data['method']} {details_data['path']} — params: {list(details_data['params'].keys())}")

        # ── 7. verify_get_api_details (createUser — check required) ───
        print("\n[7] verify_get_api_details (createUser)...")
        cu_resp = await asyncio.wait_for(
            send_recv(proc, {
                "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": {"name": "verify_get_api_details", "arguments": {"endpoint_id": "createUser"}},
            }),
            timeout=10,
        )
        cu_data = json.loads(cu_resp["result"]["content"][0]["text"])
        assert "schemas" in cu_data["required"], f"schemas not required: {cu_data}"
        assert "userName" in cu_data["required"], f"userName not required: {cu_data}"
        print(f"   Required fields: {cu_data['required']}")

        # ── 8. verify_get_api_details (nonexistent — error handling) ──
        print("\n[8] verify_get_api_details (bad_endpoint_id — error handling)...")
        bad_resp = await asyncio.wait_for(
            send_recv(proc, {
                "jsonrpc": "2.0", "id": 8, "method": "tools/call",
                "params": {"name": "verify_get_api_details", "arguments": {"endpoint_id": "notAnEndpoint_xyz"}},
            }),
            timeout=10,
        )
        bad_data = json.loads(bad_resp["result"]["content"][0]["text"])
        assert "error" in bad_data, f"Expected error key: {bad_data}"
        print(f"   Error handled: {bad_data['error']}")

        # ── 9. verify_execute — live API: GET /v1.0/apiclients ────────
        print("\n[9] verify_execute (listAPIClients — live API call)...")
        exec_resp = await asyncio.wait_for(
            send_recv(proc, {
                "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                "params": {
                    "name": "verify_execute",
                    "arguments": {"endpoint_id": "listAPIClients", "params": {}},
                },
            }),
            timeout=30,
        )
        exec_text = exec_resp["result"]["content"][0]["text"]
        exec_data = json.loads(exec_text)
        # Should get a list or dict back (not an error with auth failure)
        assert "error" not in exec_data or "Unauthorized" not in str(exec_data), \
            f"Auth failed: {exec_data}"
        print(f"   Response type: {type(exec_data).__name__}, keys: {list(exec_data.keys()) if isinstance(exec_data, dict) else 'list'}")

        # ── 10. verify_execute — live API: GET /v2.0/Users ───────────
        print("\n[10] verify_execute (getUsers — live SCIM API call)...")
        users_resp = await asyncio.wait_for(
            send_recv(proc, {
                "jsonrpc": "2.0", "id": 10, "method": "tools/call",
                "params": {
                    "name": "verify_execute",
                    "arguments": {
                        "endpoint_id": "getUsers",
                        "params": {"count": 3},
                    },
                },
            }),
            timeout=30,
        )
        users_text = users_resp["result"]["content"][0]["text"]
        users_data = json.loads(users_text)
        assert "error" not in users_data or "Unauthorized" not in str(users_data), \
            f"Auth failed: {users_data}"
        print(f"   Response keys: {list(users_data.keys()) if isinstance(users_data, dict) else 'list'}")

        print("\n" + "="*50)
        print("ALL 10 TESTS PASSED")
        print("="*50)

    except Exception as e:
        errors.append(str(e))
        print(f"\nTEST FAILED: {e}")
        import traceback; traceback.print_exc()

    finally:
        proc.terminate()
        stderr = await proc.stderr.read()
        if stderr:
            print(f"\n--- Server stderr ---\n{stderr.decode()[-2000:]}")

    return len(errors) == 0


if __name__ == "__main__":
    ok = asyncio.run(run_tests())
    sys.exit(0 if ok else 1)

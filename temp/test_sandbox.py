#!/usr/bin/env python3
"""Kensho MCP sandbox test"""

import subprocess
import json

MCP_SERVER = r"D:\Programming\MCP\target\release\kensho-mcp.exe"
TEST_BINARY = r"D:\Programming\MCP\temp\test_binary\target\release\test_target.exe"

def send_request(proc, method, params=None):
    request = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params:
        request["params"] = params
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())

def main():
    print("Kensho MCP Sandbox Test")
    print("=" * 50)

    proc = subprocess.Popen(
        [MCP_SERVER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, bufsize=1,
        encoding='utf-8', errors='replace'
    )

    try:
        send_request(proc, "initialize")
        print("Initialized")

        # Test sandbox execution
        print("\nTesting run_in_sandbox...")
        resp = send_request(proc, "tools/call", {
            "name": "run_in_sandbox",
            "arguments": {
                "exe_path": TEST_BINARY,
                "args": "42",
                "memory_limit_mb": 256,
                "timeout_ms": 5000
            }
        })

        print(f"\nResponse:\n{json.dumps(resp, indent=2, ensure_ascii=False)}")

        if "error" in resp:
            print(f"\nError: {resp['error'].get('message')}")
        elif "result" in resp:
            text = resp["result"].get("content", [{}])[0].get("text", "{}")
            result = json.loads(text)
            print(f"\nSuccess: {result.get('success')}")
            print(f"Exit code: {result.get('exit_code')}")
            print(f"Process ID: {result.get('process_id')}")

    except Exception as e:
        print(f"Exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        proc.terminate()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run installer.exe in sandbox to identify it"""

import subprocess
import json
import time

MCP_SERVER = r"D:\Programming\MCP\target\release\kensho-mcp.exe"
INSTALLER = r"D:\Programming\MCP\temp\installer.exe"

def send_request(proc, method, params=None):
    request = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params:
        request["params"] = params
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())

def main():
    print("=" * 60)
    print("Installer Identification via Sandbox")
    print("=" * 60)

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
        print("Server initialized\n")

        # Run in sandbox with short timeout
        print(f"Running: {INSTALLER}")
        print("Sandbox config: 256MB memory, 5s timeout\n")

        resp = send_request(proc, "tools/call", {
            "name": "run_in_sandbox",
            "arguments": {
                "exe_path": INSTALLER,
                "memory_limit_mb": 256,
                "timeout_ms": 5000
            }
        })

        if "error" in resp:
            print(f"Error: {resp['error'].get('message')}")
            return

        text = resp["result"].get("content", [{}])[0].get("text", "{}")
        result = json.loads(text)

        print("Results:")
        print("-" * 40)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    except Exception as e:
        print(f"Exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        proc.terminate()

if __name__ == "__main__":
    main()

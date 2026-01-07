#!/usr/bin/env python3
"""Kensho MCP simple test - static analysis only"""

import subprocess
import json

MCP_SERVER = r"D:\Programming\MCP\target\release\kensho-mcp.exe"
TEST_BINARY = r"D:\Programming\MCP\temp\test_binary\target\release\test_target.exe"

def send_request(proc, method, params=None):
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
    }
    if params:
        request["params"] = params

    request_str = json.dumps(request) + "\n"
    proc.stdin.write(request_str)
    proc.stdin.flush()

    response_str = proc.stdout.readline()
    return json.loads(response_str)

def main():
    print("Kensho MCP Static Analysis Test")
    print("=" * 50)

    proc = subprocess.Popen(
        [MCP_SERVER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        encoding='utf-8',
        errors='replace'
    )

    try:
        # Initialize
        resp = send_request(proc, "initialize")
        print(f"Initialized: {resp.get('result', {}).get('serverInfo', {}).get('name')}")

        # Get tools
        resp = send_request(proc, "tools/list")
        tools = [t.get('name') for t in resp.get("result", {}).get("tools", [])]
        print(f"Tools ({len(tools)}): {', '.join(tools[:5])}...")

        # Binary summary
        print("\nBinary Summary:")
        resp = send_request(proc, "tools/call", {
            "name": "get_binary_summary",
            "arguments": {"path": TEST_BINARY}
        })
        if "result" in resp:
            text = resp["result"].get("content", [{}])[0].get("text", "{}")
            data = json.loads(text)
            for k, v in data.items():
                print(f"  {k}: {v}")

        print("\nStatic analysis test completed successfully!")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    main()

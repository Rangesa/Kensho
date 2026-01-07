#!/usr/bin/env python3
"""Kensho MCP analyze_with_trace test"""

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
    print("=" * 60)
    print("Kensho MCP - Integrated Analysis Test")
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

        # Test analyze_with_trace
        print("Testing analyze_with_trace...")
        print("  Binary:", TEST_BINARY)
        print("  Entry point: 0x140017950")
        print()

        resp = send_request(proc, "tools/call", {
            "name": "analyze_with_trace",
            "arguments": {
                "exe_path": TEST_BINARY,
                "function_address": "0x140017950",
                "max_instructions": 100,
                "memory_limit_mb": 256,
                "detect_obfuscation": True
            }
        })

        if "error" in resp:
            print(f"Error: {resp['error'].get('message')}")
            return

        text = resp["result"].get("content", [{}])[0].get("text", "{}")
        result = json.loads(text)

        print("Results:")
        print("-" * 40)
        print(f"Success: {result.get('success')}")
        print(f"Function Address: {result.get('function_address')}")

        # Dynamic Analysis
        if "dynamic_analysis" in result:
            dyn = result["dynamic_analysis"]
            print("\n[Dynamic Analysis]")
            sandbox = dyn.get("sandbox", {})
            print(f"  Process ID: {sandbox.get('process_id')}")
            print(f"  Exit Code: {sandbox.get('exit_code')}")

            trace = dyn.get("trace", {})
            print(f"  Total Instructions: {trace.get('total_instructions')}")
            print(f"  Unique Addresses: {trace.get('unique_addresses')}")

            path = trace.get("execution_path", [])[:10]
            if path:
                print(f"  Execution Path (first 10): {path}")

            samples = trace.get("register_samples", [])
            if samples:
                print(f"  Register Samples:")
                for s in samples[:3]:
                    print(f"    {s.get('address')}: RAX={s.get('rax')}, RSP={s.get('rsp')}")

        # Static Analysis
        if "static_analysis" in result:
            stat = result["static_analysis"]
            print("\n[Static Analysis]")
            print(f"  Success: {stat.get('success')}")
            print(f"  P-code Count: {stat.get('pcode_count')}")
            print(f"  Block Count: {stat.get('block_count')}")

            obf = stat.get("obfuscation", {})
            if obf:
                print(f"  Obfuscation Detected: {obf.get('detected')}")
                print(f"  Obfuscation Score: {obf.get('score')}")
                patterns = obf.get("patterns", [])
                if patterns:
                    print(f"  Patterns: {len(patterns)} found")

        # Combined Insights
        if "combined_insights" in result:
            insights = result["combined_insights"]
            print("\n[Combined Insights]")
            for s in insights.get("summary", []):
                print(f"  - {s}")
            print(f"  Recommendation: {insights.get('recommendation')}")

        print("\n" + "=" * 60)
        print("Test completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"Exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        proc.terminate()

if __name__ == "__main__":
    main()

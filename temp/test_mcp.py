#!/usr/bin/env python3
"""
Kensho MCP テストスクリプト
動的解析+静的解析の統合機能をテスト
"""

import subprocess
import json
import sys

MCP_SERVER = r"D:\Programming\MCP\target\release\kensho-mcp.exe"
TEST_BINARY = r"D:\Programming\MCP\temp\test_binary\target\release\test_target.exe"

def send_request(proc, method, params=None):
    """MCPリクエストを送信してレスポンスを取得"""
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
    print("=" * 60)
    print("Kensho MCP 統合解析テスト")
    print("=" * 60)

    # MCPサーバー起動
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
        # 1. 初期化
        print("\n[1] Initialize...")
        resp = send_request(proc, "initialize")
        print(f"Server: {resp.get('result', {}).get('serverInfo', {}).get('name', 'unknown')}")

        # 2. ツール一覧
        print("\n[2] List tools...")
        resp = send_request(proc, "tools/list")
        tools = resp.get("result", {}).get("tools", [])
        print(f"Available tools: {len(tools)}")
        for tool in tools:
            print(f"  - {tool.get('name')}")

        # 3. バイナリサマリー
        print("\n[3] Get binary summary...")
        resp = send_request(proc, "tools/call", {
            "name": "get_binary_summary",
            "arguments": {"path": TEST_BINARY}
        })
        if "result" in resp:
            content = resp["result"].get("content", [{}])[0].get("text", "{}")
            summary = json.loads(content)
            print(f"Format: {summary.get('format')}")
            print(f"Entry point: {summary.get('entry_point')}")
            print(f"Functions: {summary.get('function_count')}")

        # 4. 静的解析（デコンパイル）
        print("\n[4] Decompile function...")
        resp = send_request(proc, "tools/call", {
            "name": "decompile_function",
            "arguments": {
                "path": TEST_BINARY,
                "function_address": "0x140017950",
                "max_instructions": 100
            }
        })
        if "result" in resp:
            content = resp["result"].get("content", [{}])[0].get("text", "{}")
            result = json.loads(content)
            print(f"P-code count: {result.get('pcode_count')}")
            print(f"Block count: {result.get('block_count')}")

        # 5. サンドボックス実行テスト
        print("\n[5] Run in sandbox...")
        resp = send_request(proc, "tools/call", {
            "name": "run_in_sandbox",
            "arguments": {
                "exe_path": TEST_BINARY,
                "args": "100",
                "memory_limit_mb": 256,
                "timeout_ms": 10000
            }
        })
        if "result" in resp:
            content = resp["result"].get("content", [{}])[0].get("text", "{}")
            result = json.loads(content)
            print(f"Success: {result.get('success')}")
            print(f"Exit code: {result.get('exit_code')}")
            print(f"Process ID: {result.get('process_id')}")
        elif "error" in resp:
            print(f"Error: {resp['error'].get('message')}")

        # 6. 統合解析テスト
        print("\n[6] Analyze with trace (integrated)...")
        resp = send_request(proc, "tools/call", {
            "name": "analyze_with_trace",
            "arguments": {
                "exe_path": TEST_BINARY,
                "function_address": "0x140017950",
                "max_instructions": 200,
                "memory_limit_mb": 256,
                "detect_obfuscation": True
            }
        })
        if "result" in resp:
            content = resp["result"].get("content", [{}])[0].get("text", "{}")
            result = json.loads(content)
            print(f"Success: {result.get('success')}")

            if "dynamic_analysis" in result:
                dyn = result["dynamic_analysis"]
                print(f"\nDynamic Analysis:")
                print(f"  Process ID: {dyn.get('sandbox', {}).get('process_id')}")
                trace = dyn.get("trace", {})
                print(f"  Total instructions: {trace.get('total_instructions')}")
                print(f"  Unique addresses: {trace.get('unique_addresses')}")
                if trace.get("execution_path"):
                    print(f"  First 5 addresses: {trace.get('execution_path', [])[:5]}")

            if "static_analysis" in result:
                stat = result["static_analysis"]
                print(f"\nStatic Analysis:")
                print(f"  Success: {stat.get('success')}")
                print(f"  P-code count: {stat.get('pcode_count')}")
                print(f"  Block count: {stat.get('block_count')}")
                if stat.get("obfuscation"):
                    obf = stat["obfuscation"]
                    print(f"  Obfuscation detected: {obf.get('detected')}")
                    print(f"  Obfuscation score: {obf.get('score')}")

            if "combined_insights" in result:
                insights = result["combined_insights"]
                print(f"\nCombined Insights:")
                for s in insights.get("summary", []):
                    print(f"  - {s}")
                print(f"  Recommendation: {insights.get('recommendation')}")
        elif "error" in resp:
            print(f"Error: {resp['error'].get('message')}")

        print("\n" + "=" * 60)
        print("Test completed!")
        print("=" * 60)

    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    main()

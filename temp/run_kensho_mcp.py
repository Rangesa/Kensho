import subprocess
import json
import sys
import os

# Path to the compiled MCP binary
MCP_BINARY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "target", "release", "kensho-mcp.exe")

def run_mcp_tool(tool_name, arguments):
    """
    Runs a tool on the Kensho MCP server.
    """
    if not os.path.exists(MCP_BINARY_PATH):
        print(f"Error: MCP binary not found at {MCP_BINARY_PATH}")
        print("Please build it first with: cargo build --release --bin kensho-mcp")
        return

    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }

    try:
        # Start the MCP server process
        process = subprocess.Popen(
            [MCP_BINARY_PATH],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8' # Ensure UTF-8 encoding
        )

        # Send request and get response
        stdout, stderr = process.communicate(input=json.dumps(request))

        if stderr:
            # MCP server might log info to stderr, which is fine
            # print(f"[MCP Stderr]: {stderr}", file=sys.stderr)
            pass

        response = json.loads(stdout)

        if "error" in response:
            print(f"MCP Error: {json.dumps(response['error'], indent=2)}")
        elif "result" in response:
            # Extract content from result
            content = response["result"].get("content", [])
            for item in content:
                if item.get("type") == "text":
                    print(item.get("text"))
                else:
                    print(f"[{item.get('type')} data]")
        else:
            print(f"Unexpected response: {stdout}")

    except Exception as e:
        print(f"Execution failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_kensho_mcp.py <tool_name> [key=value ...]")
        print("\nExamples:")
        print('  python run_kensho_mcp.py get_binary_summary path="C:\\Windows\\System32\\notepad.exe"')
        print('  python run_kensho_mcp.py list_strings path="target.exe" min_length=10')
        sys.exit(1)

    tool = sys.argv[1]
    args = {}
    
    # Parse arguments (key=value)
    for arg in sys.argv[2:]:
        if "=" in arg:
            key, value = arg.split("=", 1)
            # Try to convert integer strings to int
            if value.isdigit():
                value = int(value)
            args[key] = value
        else:
            print(f"Warning: Ignoring invalid argument format '{arg}'. Use key=value.")

    run_mcp_tool(tool, args)

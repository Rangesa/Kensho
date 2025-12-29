#!/usr/bin/env python3
"""Remove BOM and invisible characters from files"""
import sys

def fix_file(filepath):
    try:
        # Read with UTF-8 BOM handling
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            content = f.read()

        # Remove any remaining BOM
        content = content.lstrip('\ufeff')

        # Write back cleanly
        with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
            f.write(content)

        print(f"Fixed: {filepath}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == '__main__':
    files = [
        r"D:\Programming\MCP\src\decompiler_prototype\ssa_advanced.rs",
        r"D:\Programming\MCP\src\decompiler_prototype\nzmask.rs",
        r"D:\Programming\MCP\src\decompiler_prototype\control_flow.rs",
    ]
    for f in files:
        fix_file(f)

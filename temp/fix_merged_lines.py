#!/usr/bin/env python3
"""Fix lines where doc comments and code are merged"""
import re
import sys

def fix_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            content = f.read()

        # Pattern: /// comment followed immediately by code on same line (no newline)
        # Match: /// [anything] followed by 4+ spaces and then "pub fn" or other code
        pattern = r'(///[^\n]*?)(\s{4,})(pub\s+fn|pub\s+struct|impl\s+)'

        def replacer(match):
            comment = match.group(1)
            spaces = match.group(2)
            code_start = match.group(3)
            # Replace with comment, newline, and properly indented code
            return f"{comment}\n    {code_start}"

        fixed_content = re.sub(pattern, replacer, content)

        with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
            f.write(fixed_content)

        print(f"Fixed: {filepath}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    files = [
        r"D:\Programming\MCP\src\decompiler_prototype\ssa_advanced.rs",
        r"D:\Programming\MCP\src\decompiler_prototype\nzmask.rs",
    ]
    for f in files:
        fix_file(f)

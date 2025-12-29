#!/usr/bin/env python3
"""Remove all garbled (non-ASCII) doc comments"""
import re

def fix_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            lines = f.readlines()

        fixed_lines = []
        for line in lines:
            # Check if this is a doc comment line
            if line.strip().startswith('///'):
                # Check if it contains non-ASCII characters (garbled)
                if any(ord(c) > 127 for c in line):
                    # Replace with English placeholder
                    indent = len(line) - len(line.lstrip())
                    fixed_lines.append(' ' * indent + '/// [Documentation removed due to encoding issues]\n')
                    continue
            fixed_lines.append(line)

        with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
            f.writelines(fixed_lines)

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

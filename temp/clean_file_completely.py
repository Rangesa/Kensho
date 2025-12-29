#!/usr/bin/env python3
"""Completely clean files by removing all non-ASCII comments and fixing merged lines"""
import re

def clean_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            content = f.read()

        # Remove BOM
        content = content.lstrip('\ufeff')

        # Split into lines
        lines = content.split('\n')
        cleaned_lines = []

        for line in lines:
            # Skip empty lines
            if not line.strip():
                cleaned_lines.append('')
                continue

            # Check if this is a doc comment
            if line.strip().startswith('///'):
                # Check if it contains non-ASCII
                if any(ord(c) > 127 for c in line):
                    # Skip this line entirely
                    continue
                # Otherwise keep it
                cleaned_lines.append(line)
            else:
                cleaned_lines.append(line)

        # Join back
        content = '\n'.join(cleaned_lines)

        # Write back
        with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
            f.write(content)

        print(f"Cleaned: {filepath}")
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
        clean_file(f)

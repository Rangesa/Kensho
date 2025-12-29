#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fix encoding issues in Rust source files by removing BOM and replacing garbled comments"""

import os
import re
import sys

def fix_file_encoding(filepath):
    """Fix a single file's encoding issues"""
    try:
        # Read file with UTF-8 (ignoring BOM if present)
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            content = f.read()

        # Remove UTF-8 BOM if it somehow slipped through
        if content.startswith('\ufeff'):
            content = content[1:]

        # Replace garbled Japanese comments with English placeholders
        # Pattern matches: /// followed by garbled text (non-ASCII characters)
        def replace_comment(match):
            # Extract the comment content
            comment_text = match.group(1)
            # If it contains garbled characters, replace with generic comment
            if any(ord(c) > 127 for c in comment_text):
                return "/// [Comment removed due to encoding issues]\n"
            return match.group(0)

        # Replace doc comments with garbled text
        content = re.sub(r'///(.*)$', replace_comment, content, flags=re.MULTILINE)

        # Write back without BOM
        with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
            f.write(content)

        print(f"Fixed: {filepath}")
        return True
    except Exception as e:
        print(f"Error fixing {filepath}: {e}")
        return False

def main():
    """Fix all Rust files in decompiler_prototype directory"""
    base_dir = r"D:\Programming\MCP\src\decompiler_prototype"

    if not os.path.exists(base_dir):
        print(f"Directory not found: {base_dir}")
        return 1

    rust_files = []
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.rs'):
                rust_files.append(os.path.join(root, file))

    print(f"Found {len(rust_files)} Rust files")

    fixed_count = 0
    for filepath in rust_files:
        if fix_file_encoding(filepath):
            fixed_count += 1

    print(f"\nFixed {fixed_count}/{len(rust_files)} files")
    return 0

if __name__ == '__main__':
    sys.exit(main())

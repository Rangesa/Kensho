#!/usr/bin/env python3
"""Strip all garbled comments from Rust files"""
import re
import sys

def strip_garbled_comments(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            content = f.read()

        # Remove BOM
        content = content.lstrip('\ufeff')

        lines = content.split('\n')
        cleaned_lines = []

        for line in lines:
            # Check if line contains /// comment
            if '///' in line:
                # Check if it has non-ASCII characters
                if any(ord(c) > 127 for c in line):
                    # Find the /// position
                    comment_start = line.find('///')

                    # Check if there's code after the comment on same line
                    # Pattern: /// comment    code
                    # We want to keep only the code part

                    # Split by multiple spaces (typically 4+ spaces separate comment from code)
                    parts = re.split(r'(\s{4,})', line)

                    # If we have parts and the last part looks like code (starts with pub/fn/impl/etc)
                    if len(parts) >= 3 and re.match(r'\s*(pub|fn|impl|struct|enum|const|let|if|for|while)', parts[-1]):
                        # Keep only the code part with proper indentation
                        indent = len(line) - len(line.lstrip())
                        cleaned_lines.append(' ' * indent + parts[-1])
                    else:
                        # Just remove the entire line
                        pass
                else:
                    # ASCII comment, keep it
                    cleaned_lines.append(line)
            else:
                # No comment, keep the line
                cleaned_lines.append(line)

        # Join back
        content = '\n'.join(cleaned_lines)

        # Write back
        with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
            f.write(content)

        print(f"Stripped: {filepath}")
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
        strip_garbled_comments(f)

    print("\nDone! All garbled comments removed.")

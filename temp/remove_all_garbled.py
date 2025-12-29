#!/usr/bin/env python3
"""Completely remove all garbled content from Rust files"""
import re

def clean_file_completely(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            content = f.read()

        # Remove BOM
        content = content.lstrip('\ufeff')

        # Split into lines
        lines = content.split('\n')
        cleaned_lines = []

        for line in lines:
            # Skip completely empty lines
            if not line.strip():
                cleaned_lines.append('')
                continue

            # Check if line has non-ASCII characters (garbled)
            has_garbled = any(ord(c) > 127 for c in line)

            if has_garbled:
                # If this is a comment line (starts with // or ///), skip it entirely
                stripped = line.lstrip()
                if stripped.startswith('///') or stripped.startswith('//'):
                    continue

                # If line contains both garbled text and code, extract only ASCII parts
                # This handles cases like: "// garbled    pub fn name() {"
                # Try to extract code patterns
                code_pattern = r'\b(pub\s+fn|fn|impl|struct|enum|const|let|if|for|while|match|return)\b.*$'
                match = re.search(code_pattern, line)
                if match:
                    # Extract the code part
                    code = match.group(0)
                    # Get indentation from original line
                    indent = len(line) - len(line.lstrip())
                    cleaned_lines.append(' ' * indent + code)
                    continue

                # Otherwise, skip garbled line entirely
                continue

            # Line is clean, keep it
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
        clean_file_completely(f)

    print("\nAll garbled content removed!")

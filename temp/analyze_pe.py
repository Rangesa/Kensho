#!/usr/bin/env python3
"""question.exe PE解析スクリプト"""
import struct
import sys

def read_pe(filename):
    with open(filename, 'rb') as f:
        # DOS header
        f.seek(0x3C)
        pe_offset = struct.unpack('<I', f.read(4))[0]

        # PE signature
        f.seek(pe_offset)
        pe_sig = f.read(4)
        if pe_sig != b'PE\x00\x00':
            print(f"エラー: PEシグネチャが見つかりません: {pe_sig}")
            return

        # COFF header
        machine = struct.unpack('<H', f.read(2))[0]
        num_sections = struct.unpack('<H', f.read(2))[0]
        time_date = struct.unpack('<I', f.read(4))[0]
        ptr_sym = struct.unpack('<I', f.read(4))[0]
        num_sym = struct.unpack('<I', f.read(4))[0]
        size_opt = struct.unpack('<H', f.read(2))[0]
        characteristics = struct.unpack('<H', f.read(2))[0]

        # Optional header
        magic = struct.unpack('<H', f.read(2))[0]
        if magic == 0x20b:  # PE32+
            f.read(22)  # Skip to entry point
            entry_point = struct.unpack('<I', f.read(4))[0]
            f.read(8)  # Skip base of code/data
            image_base = struct.unpack('<Q', f.read(8))[0]
        else:  # PE32
            f.read(22)
            entry_point = struct.unpack('<I', f.read(4))[0]
            f.read(4)
            f.read(4)
            image_base = struct.unpack('<I', f.read(4))[0]

        print("=" * 60)
        print(f"   question.exe PE解析")
        print("=" * 60)
        print(f"\n📋 基本情報:")
        print(f"  Machine: 0x{machine:04X} ({'x64' if machine == 0x8664 else 'x86' if machine == 0x14c else 'Unknown'})")
        print(f"  セクション数: {num_sections}")
        print(f"  イメージベース: 0x{image_base:016X}")
        print(f"  エントリポイント (RVA): 0x{entry_point:08X}")
        print(f"  エントリポイント (VA): 0x{image_base + entry_point:016X}")

        # Section table
        section_table_offset = pe_offset + 24 + size_opt
        f.seek(section_table_offset)

        print(f"\n📂 セクション一覧:")
        print(f"  {'名前':<15} {'仮想アドレス':<14} {'仮想サイズ':<12} {'特性':<10}")
        print(f"  {'-' * 60}")

        sections = []
        for i in range(num_sections):
            name = f.read(8).rstrip(b'\x00').decode('ascii', errors='ignore')
            vsize = struct.unpack('<I', f.read(4))[0]
            vaddr = struct.unpack('<I', f.read(4))[0]
            raw_size = struct.unpack('<I', f.read(4))[0]
            raw_ptr = struct.unpack('<I', f.read(4))[0]
            f.read(12)  # Skip relocations and line numbers
            chars = struct.unpack('<I', f.read(4))[0]

            perms = ""
            if chars & 0x20000000: perms += "R"
            if chars & 0x40000000: perms += "W"
            if chars & 0x80000000: perms += "X"

            sections.append({
                'name': name,
                'vaddr': vaddr,
                'vsize': vsize,
                'raw_ptr': raw_ptr,
                'raw_size': raw_size,
                'chars': chars,
                'perms': perms
            })

            print(f"  {name:<15} 0x{vaddr:08X}    {vsize:>10} bytes {perms:<10}")

        # Find entry point section
        print(f"\n⚙️ エントリポイント詳細:")
        for sec in sections:
            if entry_point >= sec['vaddr'] and entry_point < sec['vaddr'] + sec['vsize']:
                print(f"  セクション: {sec['name']}")
                print(f"  セクション内オフセット: 0x{entry_point - sec['vaddr']:08X}")
                file_offset = sec['raw_ptr'] + (entry_point - sec['vaddr'])
                print(f"  ファイルオフセット: 0x{file_offset:08X}")

                # Read first bytes
                f.seek(file_offset)
                first_bytes = f.read(32)
                print(f"  最初の32バイト:")
                print(f"    ", end="")
                for i, b in enumerate(first_bytes):
                    print(f"{b:02X} ", end="")
                    if (i + 1) % 16 == 0 and i < 31:
                        print(f"\n    ", end="")
                print()
                break

        # String search
        print(f"\n🔤 興味深い文字列を検索中...")
        f.seek(0)
        data = f.read()

        keywords = [b'flag', b'key', b'password', b'secret', b'correct',
                   b'wrong', b'success', b'fail', b'input', b'check']

        found = []
        for keyword in keywords:
            idx = 0
            while True:
                idx = data.find(keyword, idx)
                if idx == -1:
                    break

                # Extract surrounding context
                start = max(0, idx - 10)
                end = min(len(data), idx + 50)
                context = data[start:end]

                # Check if printable ASCII
                try:
                    decoded = context.decode('ascii', errors='ignore')
                    if len(decoded.strip()) > 3:
                        found.append((idx, decoded.strip()))
                except:
                    pass

                idx += 1

        # Remove duplicates and show top results
        unique_found = []
        seen = set()
        for offset, text in found:
            if text not in seen:
                seen.add(text)
                unique_found.append((offset, text))

        print(f"  見つかった文字列 ({len(unique_found)} 個):")
        for i, (offset, text) in enumerate(unique_found[:20]):
            print(f"    [0x{offset:08X}] {text[:60]}")

        print(f"\n{'=' * 60}")
        print("解析完了！")
        print(f"{'=' * 60}")

if __name__ == '__main__':
    read_pe(r'D:\Programming\MCP\question.exe')

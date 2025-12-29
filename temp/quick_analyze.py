import struct
import sys

def analyze(filename):
    with open(filename, 'rb') as f:
        f.seek(0x3C)
        pe_offset = struct.unpack('<I', f.read(4))[0]
        f.seek(pe_offset)

        if f.read(4) != b'PE\x00\x00':
            print("Not a valid PE file")
            return

        machine = struct.unpack('<H', f.read(2))[0]
        num_sections = struct.unpack('<H', f.read(2))[0]
        f.read(12)
        size_opt = struct.unpack('<H', f.read(2))[0]
        f.read(2)

        magic = struct.unpack('<H', f.read(2))[0]
        f.read(22)
        entry_point = struct.unpack('<I', f.read(4))[0]

        if magic == 0x20b:
            f.read(8)
            image_base = struct.unpack('<Q', f.read(8))[0]
        else:
            f.read(8)
            image_base = struct.unpack('<I', f.read(4))[0]

        print("="*50)
        print("question.exe Analysis")
        print("="*50)
        print(f"Machine: {'x64' if machine == 0x8664 else 'x86'}")
        print(f"Sections: {num_sections}")
        print(f"Entry: 0x{image_base + entry_point:X}")
        print(f"Image Base: 0x{image_base:X}")

        # Read strings
        f.seek(0)
        data = f.read()

        keywords = [b'flag', b'password', b'correct', b'wrong', b'key']
        print(f"\nInteresting strings:")
        for kw in keywords:
            idx = data.find(kw)
            if idx != -1:
                ctx = data[max(0,idx-5):idx+40]
                try:
                    print(f"  [0x{idx:X}] {ctx.decode('ascii', errors='ignore').strip()}")
                except:
                    pass

analyze(r'D:\Programming\MCP\question.exe')

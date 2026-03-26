#!/usr/bin/env python3
import struct, sys

class NSO:
    def __init__(self, path):
        data = open(path, "rb").read()
        self.magic = data[0:4]
        self.version = struct.unpack("<I", data[4:8])[0]
        self.flags = struct.unpack("<I", data[0x0C:0x10])[0]

        self.text_off = struct.unpack("<I", data[0x10:0x14])[0]
        self.text_mem = struct.unpack("<I", data[0x14:0x18])[0]
        self.text_size = struct.unpack("<I", data[0x18:0x1C])[0]

        self.ro_off = struct.unpack("<I", data[0x20:0x24])[0]
        self.ro_mem = struct.unpack("<I", data[0x24:0x28])[0]
        self.ro_size = struct.unpack("<I", data[0x28:0x2C])[0]

        self.data_off = struct.unpack("<I", data[0x30:0x34])[0]
        self.data_mem = struct.unpack("<I", data[0x34:0x38])[0]
        self.data_size = struct.unpack("<I", data[0x38:0x3C])[0]

        self.text_compressed = self.flags & 1
        self.ro_compressed = (self.flags >> 1) & 1
        self.data_compressed = (self.flags >> 2) & 1

        self.text = data[self.text_off : self.text_off + self.text_size]
        self.rodata = data[self.ro_off : self.ro_off + self.ro_size]
        self.data = data[self.data_off : self.data_off + self.data_size]

    def hexdump(self, section_name="text", offset=0, length=64):
        blob = {"text": self.text, "rodata": self.rodata, "data": self.data}[section_name]
        for i in range(offset, offset + length, 16):
            chunk = blob[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"  {i:08x}  {hex_part} {ascii_part}")

if __name__ == "__main__":
    nso = NSO(sys.argv[1])
    print(f"{nso.magic}  version={nso.version}  flags={nso.flags}")
    print(f"  compressed: text={nso.text_compressed} rodata={nso.ro_compressed} data={nso.data_compressed}")
    print(f".text:   {len(nso.text):>10} bytes  mem={nso.text_mem:#x}")
    print(f".rodata: {len(nso.rodata):>10} bytes  mem={nso.ro_mem:#x}")
    print(f".data:   {len(nso.data):>10} bytes  mem={nso.data_mem:#x}")
    print("=" * 60)
    nso.hexdump("text", 0, 64)

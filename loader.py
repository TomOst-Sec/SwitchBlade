#!/usr/bin/env python3
import struct, sys  # struct = read raw bytes as numbers, sys = command line args

class NSO:  # parser for Nintendo Switch NSO binaries
    def __init__(self, path):
        data = open(path, "rb").read()  # read entire file as raw bytes
        self.magic = data[0:4]  # first 4 bytes = file signature (should be "NSO0")
        self.version = struct.unpack("<I", data[4:8])[0]  # format version, little-endian u32
        self.flags = struct.unpack("<I", data[0x0C:0x10])[0]  # bitfield: which segments are compressed

        # .text segment = executable code (read+execute in memory)
        self.text_off = struct.unpack("<I", data[0x10:0x14])[0]  # where .text starts in the file
        self.text_mem = struct.unpack("<I", data[0x14:0x18])[0]  # where .text gets loaded in memory
        self.text_size = struct.unpack("<I", data[0x18:0x1C])[0]  # size of .text in bytes

        # .rodata segment = read-only data like strings and constants (read-only in memory)
        self.ro_off = struct.unpack("<I", data[0x20:0x24])[0]  # where .rodata starts in the file
        self.ro_mem = struct.unpack("<I", data[0x24:0x28])[0]  # where .rodata gets loaded in memory
        self.ro_size = struct.unpack("<I", data[0x28:0x2C])[0]  # size of .rodata in bytes

        # .data segment = mutable globals and statics (read+write in memory)
        self.data_off = struct.unpack("<I", data[0x30:0x34])[0]  # where .data starts in the file
        self.data_mem = struct.unpack("<I", data[0x34:0x38])[0]  # where .data gets loaded in memory
        self.data_size = struct.unpack("<I", data[0x38:0x3C])[0]  # size of .data in bytes

        # extract compression flags from the bitfield (bit 0 = text, bit 1 = ro, bit 2 = data)
        self.text_compressed = self.flags & 1  # 1 if .text is LZ4 compressed
        self.ro_compressed = (self.flags >> 1) & 1  # 1 if .rodata is LZ4 compressed
        self.data_compressed = (self.flags >> 2) & 1  # 1 if .data is LZ4 compressed

        # slice out the raw segment bytes from the file (still compressed if flags say so)
        self.text = data[self.text_off : self.text_off + self.text_size]
        self.rodata = data[self.ro_off : self.ro_off + self.ro_size]
        self.data = data[self.data_off : self.data_off + self.data_size]

    def hexdump(self, section_name="text", offset=0, length=64):
        """print raw bytes as hex + ascii, like the xxd command"""
        blob = {"text": self.text, "rodata": self.rodata, "data": self.data}[section_name]
        for i in range(offset, offset + length, 16):  # 16 bytes per row
            chunk = blob[i:i+16]  # grab one row of bytes
            hex_part = " ".join(f"{b:02x}" for b in chunk)  # each byte as 2-digit hex
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)  # printable chars or dots
            print(f"  {i:08x}  {hex_part} {ascii_part}")  # offset + hex + ascii

if __name__ == "__main__":  # only runs when you execute this file directly
    nso = NSO(sys.argv[1])  # parse the NSO file passed as command line arg
    print(f"{nso.magic}  version={nso.version}  flags={nso.flags}")  # header summary
    print("=" * 60)  # separator line
    print(f"  compressed: text={nso.text_compressed} rodata={nso.ro_compressed} data={nso.data_compressed}")
    print("=" * 60)  # separator line
    print(f".text:   {len(nso.text):>10} bytes  mem={nso.text_mem:#x}")  # segment sizes + load addresses
    print("=" * 60)  # separator line
    print(f".rodata: {len(nso.rodata):>10} bytes  mem={nso.ro_mem:#x}")
    print("=" * 60)  # separator line
    print(f".data:   {len(nso.data):>10} bytes  mem={nso.data_mem:#x}")
    print("=" * 60)  # separator line

    nso.hexdump("text", 0, 80)  # dump first 64 bytes of executable code



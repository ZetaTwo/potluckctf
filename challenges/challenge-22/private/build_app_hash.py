from elftools.elf.elffile import ELFFile, Segment
import hashlib

filename = "app.elf"

with open(filename, "rb") as f:
    firmware = ELFFile(f)
    cursor = 0
    sha256 = hashlib.sha256()
    for segment in firmware.iter_segments():
        if segment.header.p_type != 'PT_LOAD':
            continue
        sha256.update(segment.data())
    print(sha256.hexdigest())
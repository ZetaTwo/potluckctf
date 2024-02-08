from elftools.elf.elffile import ELFFile, Segment
from itertools import islice
import logging
from pwn import *
from pwnlib.util.packing import p32
import typing

def batched(it, size):
    it = iter(it)
    return iter(lambda: tuple(islice(it, size)), ())

CHUNKSZ = 0x100 - 8
def check_last(it: typing.Iterable[typing.Any]) -> typing.Generator[typing.Tuple[typing.Any, bool], None, None]:
    try:
        last = next(it)
    except StopIteration:
        return
    for item in it:
        yield (last, False)
        last = item
    yield (last, True)

def flash(filename, outputfilename):
    with open(filename, "rb") as inf, open(outputfilename, "w+") as outf:
        firmware = ELFFile(inf)        
        cursor = 0
        for segment in firmware.iter_segments():
            if segment.header.p_type != 'PT_LOAD':
                continue
            if segment.header.p_filesz == 0:
                continue
            skip = segment.header.p_paddr - cursor
            outf.write((b"\x01" + p32(skip)).hex() + "\n")
            skip = segment.header.p_memsz - segment.header.p_filesz
            for (chunk, is_last) in check_last(batched(segment.data(), CHUNKSZ)):
                outf.write(flat({
                    0: b'\x02',
                    1: p32(len(chunk)),
                    5: p32(0) if not is_last else p32(skip),
                    9: bytes(chunk),
                }).hex() + "\n")
            cursor += segment.header.p_memsz

        outf.write("03\n")

flash("app.elf", "app.fw")

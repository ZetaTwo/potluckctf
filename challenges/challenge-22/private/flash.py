from elftools.elf.elffile import ELFFile, Segment
from itertools import islice
import logging
from pwn import *
from pwnlib.util.packing import p32
import typing

r = remote('localhost', 1337)
r.sendlineafter(b"SEKURBUT> ", b"flash")

def batched(it, size):
    it = iter(it)
    return iter(lambda: tuple(islice(it, size)), ())

def is_valid_firmware(firmware: ELFFile) -> bool:
    if firmware.get_machine_arch() != "ARM":
        print("not arm")
        return False
    if firmware.elfclass != 32:
        print("not 32")
        return False
    if firmware.header.e_type != 'ET_EXEC':
        print("not exec")
        return False
    return True

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

def flash_segment(segment: Segment, cursor):
    skip = segment.header.p_paddr - cursor
    r.sendafter(b"FLASH> ", b"\x01" + p32(skip))
    skip = segment.header.p_memsz - segment.header.p_filesz
    for (chunk, is_last) in check_last(batched(segment.data(), CHUNKSZ)):
        r.sendafter(b"FLASH> ", flat({
            0: b'\x02',
            1: p32(len(chunk)),
            5: p32(0) if not is_last else p32(skip),
            9: bytes(chunk),
        }))
    return segment.header.p_memsz

def flash(filename):
    with open(filename, "rb") as f:
        firmware = ELFFile(f)
        if not is_valid_firmware(firmware):
            logging.error("Invalid Firmware!")
            return
        
        cursor = 0
        for segment in firmware.iter_segments():
            if segment.header.p_type != 'PT_LOAD':
                continue
            cursor = flash_segment(segment, cursor)

        r.sendafter(b"FLASH> ", b"\x03")
        r.interactive()

flash("app.elf")

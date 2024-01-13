import requests

from time import sleep
from struct import pack, unpack
from base64 import b64encode, b64decode
from multiprocessing import Pool

URL = "http://challenge29.play.potluckctf.com:31337"
CHAN_URL = f"{URL}/0x13370000"

CLEAR = b"\xff\xff\xff\xff\xff\xff\xff\xff"
hash_data = [
    [242, 39, 120, 8, 197, 92, 215, 51],
    [31, 161, 225, 35, 83, 185, 150, 95],
    [24, 15, 92, 157, 131, 137, 101, 156],
    [245, 157, 104, 226, 66, 227, 14, 21],
    [193, 227, 36, 190, 203, 79, 141, 106],
    [24, 51, 17, 135, 251, 2, 25, 23],
    [1, 3, 102, 246, 69, 254, 205, 166],
    [161, 143, 114, 120, 70, 164, 188, 79],
]


def demangle(val):
    val &= 0xffff_ffff_ffff_ffff
    val >>= 10
    val -= 0xdead
    val <<= 4
    val |= 0xc001c0de
    val ^= 0xbadc0ffee
    val -= 0x195c98dc4ba0346
    return val


def run(_x):
    s = requests.Session()

    assert s.get(f"{URL}/get_session").json()["status"] == "ok"

    resp = s.get(CHAN_URL).json()
    assert resp["status"] == "ok"
    assert b64decode(resp["value"].encode()) == b"letsa go"

    resp = s.put(CHAN_URL, json={"value": b64encode(b"herewego").decode()}).json()
    assert resp["status"] == "ok"

    resp = s.get(CHAN_URL).json()
    assert resp["status"] == "ok"
    value = b64decode(resp["value"].encode())
    while value == b"herewego":
        resp = s.get(CHAN_URL).json()
        assert resp["status"] == "ok"
        value = b64decode(resp["value"].encode())
        sleep(0.1)
    assert value == b"firmware"
    assert demangle(unpack("<Q", value)[0]) == 0xabad1dea

    print("So far so good")
    resp = s.put(CHAN_URL, json={"value": b64encode(CLEAR).decode()}).json()

    for x in hash_data:
        resp = s.put(CHAN_URL, json={"value": b64encode(bytearray(x)).decode()}).json()
        assert resp["status"] == "ok"
        sleep(0.01)

    resp = s.get(f"{URL}/0x4206900").json()
    assert resp["status"] == "ok"
    return b64decode(resp["value"]).decode()


with Pool(1) as p:
    print(p.map(run, [x for x in range(1)]))

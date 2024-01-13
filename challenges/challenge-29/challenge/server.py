#!/usr/bin/env python3

from time import time, sleep
from copy import deepcopy
from random import randrange
from struct import pack, unpack
from base64 import b64decode, b64encode
from secrets import token_hex
from threading import Lock, Thread

from flask import Flask, jsonify, request

app = Flask(__name__)

INDEX = """
How to use this API: <br>
First get a session via GET /get_session <br>
Whenever your emulator needs a value you can GET that value via /[address]. <br>
Whenever you have to provide a value you can PUT that value via /[address]
and a {"value": base64encode(bytes(data))} json body.
"""

FLAG = b"potluck{R3h05TinG_4s_4_S3rv1c3_1s_7h3_Fu7ur3!!!}"
FLAG_ADDR = 0x4206900
CHAN_ADDR = 0x13370000
KEYS = [
    0xdf0daa10347ab87f, 0x586b014bf3481377, 0x19a0f34aff026e11,
    0x1923a1b9ce913901, 0x69acddd49b2d42ce, 0x130302fa7d44e95f,
    0x3775a93df30254b2, 0xc2232db846840fbc, 0x6d9d19ef552f2cd1,
    0x448454a3057e7a4b, 0x62edd63d06bd6722, 0xf09cf2055b4291aa,
    0xe921923ca836f1b4, 0x23d26f58e0b3ee11, 0xa08b46ac8f41638b,
    0x5cc8833d7fb109e5, 0x9fb172d7bb5f0d8d, 0x9efebfd06e2f56c9,
    0xb4dd588661791926, 0x972f8dd9c50c0b28, 0x91eab1824d8d198d,
    0xaf3c5a331adc3adf, 0x419e9d0aa61b94c9, 0x25589aa7dc9ad5c6,
    0x10454b69afd84398, 0x52619e770a4001db, 0x120bac5945104972,
    0xe1665533717afde9, 0x884a2bf853f1c68c, 0x619ec0a3b8cfa381,
    0xa832be9e97546e03, 0xefe552c07c254704, 0xddd71a2e4729156d,
    0x390e464178f3476c, 0xfc4c1b163550f8a1, 0x664c310b83252df4,
    0x68d81b5e90007780, 0x344bf81564afeddc, 0xd42d31aac8a1b1e3,
    0x5ad3b1ebc681fa66, 0xbd4f80368bbe3bec, 0x708d255118648028,
    0x42874564c0b98344, 0xe36ab55a69149fcd, 0xbe8d8adeec16d951,
    0x32ba3994058e219e, 0x79d8cce2d5dd8892, 0xc0e24ed30f48173d,
    0xf5bc56fcc6716318, 0xfdc4df4a42ac08ce, 0x86e34973e1c90040,
    0xbd1eb4ed1a8d656b, 0xb5bff43f1d561ea4, 0x4859614a1446cf8c,
    0xa3391af2d78cb8ec, 0xfa4fb8d78f500cc3, 0x2d528b667bae3aab,
    0xb7dcbaaa0f025487, 0x257f4b068ea73509, 0xe2e42f2ab02710b8,
    0x925567b775f00566, 0xbb9deb10c46bb00e, 0x3e6abe6f9589bc91,
    0x15aa3ec11d66aecc, 0x52c00308ca5b2d44, 0x957ace9d7e24d37c,
    0xe17bc36d6e51a8f9, 0x76b9270492e67082, 0x10a5e9d348ed8a54,
    0xb2a64cbb4020f37b, 0xbfc8bd3b0845704b, 0x96089dc85b0249d9,
    0x868e988abe0f896d, 0x36a72814a92a4d09, 0x85abb1aa3db75f8b,
    0x6f04f545ab84c6e0, 0x1b8aadfa8026cdb9, 0x45004833370a8be1,
    0xe49775555c60bd88, 0x6428cf791495f80b, 0x5dae577e49e8eb17,
    0x54506e36249f0b3a, 0x47802b06dd33999a, 0x237f20db5c1b5a15,
    0x279c12706ca9e33f, 0x79751e80e6f15bc7, 0x30bd226535b89ae6,
    0xec1e8e47d6f005da, 0xb648c9626cb28187, 0x7736e672c3e77755,
    0xd30ccde6a5e7993e, 0xc9cbf4e9c5c241c5, 0x1491a482739c4769,
    0xbc9f740354cceb30, 0x24dd93953b91c2ff, 0x154652354ca0ef3e,
    0x2978434a83b404cc, 0xb2aef23bce67af2c, 0x6d2683c22588e7cc,
    0xf6126940f8d52958, 0x965336cddc8d85b2, 0xe2c0e130d9085b5b,
    0x95d11b893b9d03de, 0xd8d1ccdecc70b49d, 0x70742ea5644621bd,
    0xbde36edbdd33909f, 0x531f8869dc6f7d16, 0xfd7d8c1ee91035ec,
    0x3647e07f06e72b26, 0x511c6ba7b794729e, 0x4ce2598178eae695,
    0x818addaff67c5f18, 0xaed90ffbc64e4571, 0x74ba848e42bcc451,
    0xbbda59d3e9324c19, 0xc925baed6d3a6932, 0x41e8788aebbc1939,
    0x89bd595f5f6e7d66, 0x50e1bbbd7c945ff7, 0x380f520cfc848bc2,
    0x6d7f25be1c04407c, 0xe73cc1011f685dc8, 0x39fdeb5232a05a51,
    0x4e248e05f593708e, 0x33deddcb0e2875fe, 0x2c473c61f5e26c95,
    0x2020393b6cc625a8, 0x2307c0f48bd2a40f, 0xb1e53027e2c567d6,
    0x202a324c8f6f559c, 0x87a7cf2dc70eacb3, 0x72cf70ffa54171b7,
    0xb3fb60278cc1e962, 0x74e05b572adde686, 0x61e6a72c23e66688,
    0x800589074b0ef19c, 0x762dd664cff25904, 0xe58968e49bb09d1c,
    0xf16a01e94b0cff58, 0xa5e78ef7aca07f93, 0x7fa7130601d0604d,
    0x56b491979fe2cad5, 0xb3a920ad1359579e, 0x41ed1749c6442e8e,
    0xe3162e44fcda2038, 0xe0ee005bb20933d0, 0x18366ff35a44a5f1,
    0x3eafc4de35a9d328, 0xe06b646f2ae0f0f6, 0x7c4300b4f9e55b89,
    0x4cd6ac89221325cc, 0x4526dfa3698b0321, 0x26dcb370d3c72cc6,
    0x225fd41d177840cd, 0x525f1508a5d3e33a, 0x839ab0fc23ffc3ac,
    0xe1a50b26c8b76b2d, 0xc1201d4571109d83, 0xb066bb353cf813c5,
    0x79b71cbfeef95284, 0x1845bf4dd25cdf70, 0xc2ec5c020b710ac2,
    0x1694666018c3ffa4, 0x96981e65ca0bce80, 0xdb2b8a4c61771e87,
    0x7837de697bf87dbc, 0x1208387d211fbaf2, 0x912e9c7a1bc69ddf,
    0x95930bb22980c10a, 0xa923eb5475e80415, 0x8436b7ea0e2b53b9,
    0x6f1b1c1154d61f88, 0xf6c693d2292edbf5, 0xa09551571483d814,
    0x597f68d27f9cc7c8, 0x85e7b1294f87f79a, 0x8fd8f4110ca6e340,
    0x8118589ae6f79e58, 0x8f81266c82ac1135, 0xa11d104e76a86740,
    0xfb70eda253dff8ab, 0x35eee60c695fa82b, 0x13560685f8b40720,
    0xdad1c9a4b8d97cf4, 0x515fb4c1cbfe8eac, 0x45fdfe1fdefb2b3e,
    0x6618506143e2193f, 0xe337536d185b8ea3, 0x384f666163e7135e,
    0x63e5ba2e17829de0, 0x5004dcc18f4791c3, 0x9ab4431d199f9e18,
    0x67dc7fb4fb56abec, 0x8fc69b14ae5f4b65, 0x282cc6989cfb1c25,
    0x4c74bb6ad43d618e, 0x1e142238e2a64aee, 0x3f94e80737951d09,
    0xfb4320d5b4ca7bf3, 0x8db283a70a2a89c3, 0x23dd562c094ee3a2,
    0x33926b2b7cc840f0, 0xf7d54f11f1a61c9a, 0xab4c6285a099d137,
    0x9dc4cb384c3c6001, 0x1f66e40fd5d1ef8b, 0xa6abfb5b1f83ffb6,
    0xef34c59eaa34b031, 0x1e5e2733e8f7618f, 0x597533adba3c009f,
    0x77bea105eb64d0c0, 0x462f2872b358d543, 0xa450858aa3306b54,
    0x39023cab9f1e103d, 0x8a473bbecc13f6cd, 0x52314b178071bb59,
    0x5132d326824d55c8, 0x275b198f59c62fa4, 0x4df705afa445e936,
    0xb36d654ac86698f7, 0x9e83bb685f6f82dd, 0xbb2cbd84fda9011d,
    0x3d46043891e9381d, 0xb1769169c3599bd0, 0x1c5d2e9849be6cd6,
    0x6cd36e4a704247f7, 0xaf2daa3f2e6bfca5, 0xd751ee714998f14d,
    0x3c36f6393ebc47b4, 0xef0a6190f119ee02, 0xd2e6dd1cb2fc0210,
    0x88e5f954ae9e1834, 0x28ebbf8607a297c3, 0x962a160b8fa97a73,
    0xe4826f0370467774, 0xdfbe6b862adb860a, 0x5ccc3de81cf26f97,
    0x17b060fbbba8e625, 0xa404e93561cd781b, 0xb115f803e351ef51,
    0x70a7e03e9734e279, 0x1f00252f51755290, 0x422ae75c25b4a7f8,
    0x16175ae04737c02a, 0xcb8ae7f465d153a7, 0x9bba0c64b8cb08ed,
    0xcd7e17e910878b83, 0x1178469e0cb762a4, 0xe8edaacdd3ef0ffe,
    0xe8932b449b95059c, 0x9a1e4976c9bec89f, 0xafc0e51747b76bf8,
    0x3e26ff9f108a31f4, 0xe8923491513c8cf8, 0xc922d5039b86be75,
    0x713ac08aa57c2ab4
]

STATE_LOCK = Lock()
STATES = dict()
CANT_READ = b"\xff\xff\xff\xff\xff\xff\xff\xff"


class State:
    def __init__(self):
        self.mem = {
            CHAN_ADDR: b"letsa go",
            FLAG_ADDR: b"DEVICE HASN'T BOOTED DEVICE HASN'T BOOTED DEVICE"
        }
        self.seed = 0
        self.magic = 0
        self.stage = 0
        self.start_time = time()
        self.exited = False

    def rand(self):
        orig_seed = self.seed
        seed = self.seed
        seed ^= (seed << 13) & 0xffff_ffff_ffff_ffff
        seed ^= (seed >> 17)
        seed ^= (seed << 43) & 0xffff_ffff_ffff_ffff
        self.seed = seed
        return orig_seed

    def init_seed(self, seed):
        self.seed = seed
        for _ in range(1000):
            self.rand()

    def rand_u8(self):
        return self.rand() & 0xff


def number(value):
    base = 16 if value.startswith("0x") else 10
    try:
        return int(value, base)
    except ValueError:
        return None


def step_cpus():
    while True:
        new_states = deepcopy(STATES)
        for (session, state) in new_states.items():
            try:
                if time() - state.start_time > 60:
                    del STATES[session]
                    continue
                match state.stage:
                    case 0:
                        if state.mem[CHAN_ADDR] != b"letsa go":
                            state.stage += 1
                            STATES[session] = state
                    case 1:
                        if state.mem[CHAN_ADDR] == b"herewego":
                            state.mem[CHAN_ADDR] = b"firmware"
                            state.stage += 1
                            STATES[session] = state
                        elif state.mem[CHAN_ADDR] != CANT_READ:
                            state.exited = True
                            STATES[session] = state
                    case 2:
                        if state.mem[CHAN_ADDR] != b"firmware":
                            state.stage += 1
                            STATES[session] = state
                    case 3:
                        if state.mem[CHAN_ADDR] != CANT_READ:
                            seed = unpack("<Q", state.mem[CHAN_ADDR].ljust(8, b'\x00')[:8])[0]
                            state.init_seed(seed)
                            state.stage += 1
                            state.mem[CHAN_ADDR] = CANT_READ
                            STATES[session] = state

                    case 4 | 5 | 6 | 7 | 8 | 9 | 10:
                        if state.mem[CHAN_ADDR] != CANT_READ:
                            val = unpack("<Q", state.mem[CHAN_ADDR].ljust(8, b'\x00')[:8])[0]
                            key = KEYS[state.rand_u8()]
                            state.magic ^= val ^ key
                            state.stage += 1
                            state.mem[CHAN_ADDR] = CANT_READ
                            STATES[session] = state

                    case 11:
                        if state.magic == 0x93273f7fd2ec9c1e:
                            state.mem[FLAG_ADDR] = FLAG
                            STATES[session] = state
            except Exception as e:
                print(e)
        sleep(0.002)


@app.route("/<address>", methods=["GET"])
def get_value(address):
    ret = {"status": "error"}

    session = request.cookies.get("session")
    if session is None:
        ret["msg"] = "please provide a session cookie"
        return jsonify(ret)

    address = number(address)
    if address is None:
        ret["msg"] = "provided address is not a number"
        return jsonify(ret)

    state = STATES[session]

    if state.exited:
        ret["msg"] = "firmware crashed. please get a new session"
        return jsonify(ret)

    if address not in state.mem:
        state.mem[address] = pack("<Q", randrange(0x1000_0000, 0xffff_ffff_ffff_ffff))

    ret["status"] = "ok"
    ret["value"] = b64encode(state.mem[address]).decode()

    return jsonify(ret)


@app.route("/<address>", methods=["PUT"])
def set_value(address):
    ret = {"status": "error"}

    if not request.is_json:
        ret["msg"] = "request does not contain json, and thus no session"
        return jsonify(ret)

    session = request.cookies.get("session")
    if session is None:
        ret["msg"] = "please provide a session cookie"
        return jsonify(ret)

    address = number(address)
    if address is None:
        ret["msg"] = "provided address is not a number"
        return jsonify(ret)

    data = request.get_json()
    if "value" not in data:
        ret["msg"] = "please also provide the value (base64 encoded) in the json"
        return jsonify(ret)

    value = b64decode(data["value"].encode())

    state = STATES[session]

    if state.exited:
        ret["msg"] = "firmware crashed. please get a new session"
        return jsonify(ret)

    state.mem[address] = value

    ret["status"] = "ok"
    return jsonify(ret)


@app.route("/get_session", methods=["GET"])
def get_session():
    session = token_hex(32)

    with STATE_LOCK:
        STATES[session] = State()

    ret = jsonify({"status": "ok"})
    ret.set_cookie("session", session)
    return ret


@app.route("/", methods=["GET"])
def index():
    return INDEX


if __name__ == "__main__":
    Thread(target=step_cpus).start()

    data = [
        [31, 161, 225, 35, 83, 185, 150, 95],
        [24, 15, 92, 157, 131, 137, 101, 156],
        [245, 157, 104, 226, 66, 227, 14, 21],
        [193, 227, 36, 190, 203, 79, 141, 106],
        [24, 51, 17, 135, 251, 2, 25, 23],
        [1, 3, 102, 246, 69, 254, 205, 166],
        [161, 143, 114, 120, 70, 164, 188, 79]
    ]

    state = State()
    state.init_seed(unpack("<Q", bytearray([242, 39, 120, 8, 197, 92, 215, 51]))[0])
    print(state.seed)

    magic = 0
    for x in data:
        b = unpack("<Q", bytearray(x))[0]
        key = KEYS[state.rand_u8()]
        magic ^= b ^ key
        print(hex(b), hex(key), hex(magic))

    app.run("0.0.0.0")

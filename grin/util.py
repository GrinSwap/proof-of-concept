from binascii import unhexlify, hexlify
from enum import Enum
from hashlib import blake2b, sha256, new as hashlibnew
from http.server import BaseHTTPRequestHandler
import os

MILLI_GRIN_UNIT = 1000000
GRIN_UNIT = 1000000000


def absolute(*paths):
    op = os.path
    return op.realpath(op.abspath(op.join(op.dirname(__file__), "..", *paths)))


def kernel_sig_msg(fee: int, lock_height: int) -> bytearray:
    out = bytearray([0] * 32)
    out[16:24] = bytearray(fee.to_bytes(8, "big"))
    out[24:32] = bytearray(lock_height.to_bytes(8, "big"))
    return out


def hasher(data: bytearray) -> bytes:
    return blake2b(bytes(data), digest_size=32).digest()


def sort_by_hash(collection: list, secp=None) -> list:
    if secp is None:
        return sorted(collection, key=lambda x: x.hash())
    return sorted(collection, key=lambda x: x.hash(secp))


class UUID:
    def __init__(self, data: bytearray):
        assert len(data) == 16, "Invalid UUID size"
        self.uuid = data

    def __str__(self):
        hex = hexlify(self.uuid)
        return "{}-{}-{}-{}-{}".format(hex[0:8].decode(), hex[8:12].decode(), hex[12:16].decode(),
                                       hex[16:20].decode(), hex[20:32].decode())

    @staticmethod
    def random():
        return UUID(bytearray(os.urandom(16)))

    @staticmethod
    def from_str(hyphenated: str):
        parts = hyphenated.split("-")
        data = bytearray()
        for part in parts:
            data.extend(part.encode())
        return UUID(bytearray(unhexlify(data)))


class OrderedEnum(Enum):
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


def do_nothing(handler):
    handler.error_response()

http_callback_get = do_nothing
http_callback_post = do_nothing


def set_callback_get(name):
    global http_callback_get
    http_callback_get = name


def set_callback_post(name):
    global http_callback_post
    http_callback_post = name


class HTTPServerHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.responded = False
        super().__init__(request, client_address, server)

    def send_response(self, code, message=None):
        if not self.responded:
            self.responded = True
            super().send_response(code, message)

    def json_response(self, data):
        if self.responded:
            return
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def response(self, data):
        if self.responded:
            return
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(data)

    def error_response(self):
        if self.responded:
            return
        self.send_response(500)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"Error")

    def do_GET(self):
        http_callback_get(self)

    def do_POST(self):
        http_callback_post(self)


def hash160(data: bytearray) -> bytearray:
    h = hashlibnew("ripemd160")
    h.update(sha256(bytes(data)).digest())
    return bytearray(h.digest())


def hash256(data: bytearray) -> bytearray:
    return bytearray(sha256(sha256(bytes(data)).digest()).digest())


def base58check_encode(data: bytearray) -> bytes:
    checksum = hash256(data)
    data = data[:]
    data.extend(checksum[:4])
    return base58_encode(data)

BASE58_CHARS = bytearray(b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


def base58_encode(data: bytearray) -> bytes:
    leading_zero_count = 0
    leading_zeroes = True
    ret = bytearray()

    for d in data:
        carry = d
        if leading_zeroes and carry == 0:
            leading_zero_count += 1
        else:
            leading_zeroes = False

        for i in range(len(ret)):
            c = ret[i]*256 + carry
            ret[i] = c % 58
            carry = int(c / 58)

        while carry > 0:
            ret.append(carry % 58)
            carry = int(carry/58)

    for i in range(leading_zero_count):
        ret.append(0)
    ret.reverse()

    for i in range(len(ret)):
        ret[i] = BASE58_CHARS[ret[i]]

    return bytes(ret)


def base58check_decode(data: bytes) -> bytearray:
    res = base58_decode(data)
    assert len(res) >= 4
    checksum_start = len(res) - 4
    hash = hash256(res[:checksum_start])
    expected = hash[:4]
    actual = res[checksum_start:]
    assert expected == actual
    return res[:checksum_start]

BASE58_DIGITS = [
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None,
    None, 0, 1, 2, 3, 4, 5, 6,
    7, 8, None, None, None, None, None, None,
    None, 9, 10, 11, 12, 13, 14, 15,
    16, None, 17, 18, 19, 20, 21, None,
    22, 23, 24, 25, 26, 27, 28, 29,
    30, 31, 32, None, None, None, None, None,
    None, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, None, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54,
    55, 56, 57, None, None, None, None, None
]


def base58_decode(data: bytes) -> bytearray:
    size = int(1 + len(data) * 11 / 15)
    scratch = bytearray([0] * size)

    for d in bytearray(data):
        assert d < 128
        carry = BASE58_DIGITS[d]
        assert carry is not None
        for i in range(len(scratch)):
            carry += scratch[size-i-1]*58
            scratch[size-i-1] = carry.to_bytes(4, "little")[0]
            carry = int(carry/256)
        assert carry == 0

    res = bytearray()
    for d in bytearray(data):
        if d != BASE58_CHARS[0]:
            break
        res.append(0)
    skipping = True
    for d in scratch:
        if skipping:
            if d == 0:
                continue
            else:
                skipping = False
        res.append(d)
    return res


def var_int_encode(value: int) -> bytearray:
    data = bytearray()
    if value < 0xFD:
        data.extend(value.to_bytes(1, "little"))
    elif value <= 0xFFFF:
        data.append(0xFD)
        data.extend(value.to_bytes(2, "little"))
    elif value <= 0xFFFFFFFF:
        data.append(0xFE)
        data.extend(value.to_bytes(4, "little"))
    else:
        data.append(0xFF)
        data.extend(value.to_bytes(8, "little"))
    return data


def script_write_bytes(value: int) -> bytearray:
    data = bytearray()
    if value <= 0x4B:
        data.extend(value.to_bytes(1, "little"))
    elif value <= 0xFF:
        data.append(0x4C)
        data.extend(value.to_bytes(1, "little"))
    elif value <= 0xFFFF:
        data.append(0x4D)
        data.extend(value.to_bytes(2, "little"))
    else:
        data.append(0x4E)
        data.extend(value.to_bytes(4, "little"))
    return data

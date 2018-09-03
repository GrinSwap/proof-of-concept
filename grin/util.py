from binascii import unhexlify, hexlify
from enum import Enum
from hashlib import blake2b
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
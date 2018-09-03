from binascii import hexlify, unhexlify
from ._libsecp256k1 import ffi, lib

EC_COMPRESSED = lib.SECP256K1_EC_COMPRESSED
EC_UNCOMPRESSED = lib.SECP256K1_EC_UNCOMPRESSED

FLAG_NONE = lib.SECP256K1_CONTEXT_NONE
FLAG_SIGN = lib.SECP256K1_CONTEXT_SIGN
FLAG_VERIFY = lib.SECP256K1_CONTEXT_VERIFY
FLAG_ALL = FLAG_SIGN | FLAG_VERIFY

HAS_AGGSIG = True
HAS_BULLETPROOFS = False
HAS_COMMITMENT = False
HAS_ECDH = False
HAS_GENERATOR = False
HAS_RANGEPROOF = False
HAS_RECOVERY = True

MESSAGE_SIZE = 32
SECRET_KEY_SIZE = 32
PUBLIC_KEY_SIZE = 65
PUBLIC_KEY_SIZE_COMPRESSED = 33


class Secp256k1:
    def __init__(self, ctx, flags):
        self._destroy = None
        if ctx is None:
            assert flags in (FLAG_NONE, FLAG_SIGN, FLAG_VERIFY, FLAG_ALL)
            ctx = lib.secp256k1_context_create(flags)
        self.flags = flags
        self.ctx = ctx

    def __del__(self):
        if not hasattr(self, "_destroy"):
            return

        if self._destroy and self.ctx:
            self._destroy(self.ctx)
            self.ctx = None


class Message:
    def __init__(self, message: bytearray):
        assert len(message) == MESSAGE_SIZE, "Invalid message size"
        self.message = message

    def __eq__(self, other):
        return isinstance(other, Message) and self.message == other.message

    def __str__(self):
        return "Message<{}>".format(self.to_hex().decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self) -> bytearray:
        message = self.message[:]
        return message

    def to_hex(self) -> bytes:
        return hexlify(self.message)

    @staticmethod
    def from_bytearray(data: bytearray):
        message = bytearray([0] * MESSAGE_SIZE)
        for i in range(min(MESSAGE_SIZE, len(data))):
            message[i] = data[i]
        return Message(message)

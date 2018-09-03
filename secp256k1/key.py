from binascii import hexlify, unhexlify
from eth_hash.auto import keccak
from os import urandom
from secp256k1 import Secp256k1, SECRET_KEY_SIZE, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE_COMPRESSED, \
    EC_COMPRESSED, EC_UNCOMPRESSED
from ._libsecp256k1 import ffi, lib


class SecretKey:
    def __init__(self):
        # Byte array containing the key, use bytes() before passing to secp256k1
        self.key = bytearray([0] * SECRET_KEY_SIZE)

    def __eq__(self, other):
        return isinstance(other, SecretKey) and self.key == other.key

    def __str__(self):
        return "SecretKey<{}>".format(self.to_hex().decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self) -> bytearray:
        return self.key[:]

    def to_hex(self) -> bytes:
        return hexlify(self.key)

    def to_public_key(self, secp: Secp256k1):
        return PublicKey.from_secret_key(secp, self)

    def clone(self):
        obj = SecretKey()
        obj.key = self.key[:]
        return obj

    # b: a -> a+b
    def add_assign(self, secp: Secp256k1, other):
        assert isinstance(other, SecretKey)
        key = ffi.new("char [32]", bytes(self.key))
        res = lib.secp256k1_ec_privkey_tweak_add(secp.ctx, key, bytes(other.key))
        assert res, "Unable to add in place"
        self.key = bytearray(ffi.buffer(key, 32))

    # b: a+b
    def add(self, secp: Secp256k1, other):
        obj = self.clone()
        obj.add_assign(secp, other)
        return obj

    # b: a -> a*b
    def mul_assign(self, secp: Secp256k1, other):
        assert isinstance(other, SecretKey)
        key = ffi.new("char [32]", bytes(self.key))
        res = lib.secp256k1_ec_privkey_tweak_mul(secp.ctx, key, bytes(other.key))
        assert res, "Unable to multiply in place"
        self.key = bytearray(ffi.buffer(key, 32))

    # b: a*b
    def mul(self, secp: Secp256k1, other):
        obj = self.clone()
        obj.mul_assign(secp, other)
        return obj

    # a -> -a
    def negate_assign(self, secp: Secp256k1):
        key = ffi.new("char [32]", bytes(self.key))
        res = lib.secp256k1_ec_privkey_negate(secp.ctx, key)
        assert res, "Unable to negate in place"
        self.key = bytearray(ffi.buffer(key, 32))

    # -a
    def negate(self, secp: Secp256k1):
        obj = self.clone()
        obj.negate_assign(secp)
        return obj

    @staticmethod
    def from_bytearray(secp: Secp256k1, data: bytearray):
        assert len(data) == SECRET_KEY_SIZE, "Invalid private key size"
        res = lib.secp256k1_ec_seckey_verify(secp.ctx, bytes(data))
        assert res, "Invalid private key"
        obj = SecretKey()
        obj.key = data[:]
        return obj

    @staticmethod
    def from_hex(secp: Secp256k1, data: bytes):
        return SecretKey.from_bytearray(secp, bytearray(unhexlify(data)))

    @staticmethod
    def random(secp: Secp256k1):
        try:
            return SecretKey.from_bytearray(secp, bytearray(urandom(32)))
        except AssertionError:
            # There is a very small chance of producing a number larger than the curve order
            return SecretKey.random(secp)


class PublicKey:
    def __init__(self, secp: Secp256k1):
        self.key = ffi.new("secp256k1_pubkey *")
        self.secp = secp

    def __eq__(self, other):
        return self.to_bytearray(self.secp) == other.to_bytearray(other.secp)

    def __str__(self):
        return "PublicKey<{}>".format(self.to_hex(self.secp, compressed=True).decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self, secp: Secp256k1, compressed=True) -> bytearray:
        size = PUBLIC_KEY_SIZE_COMPRESSED if compressed else PUBLIC_KEY_SIZE
        flag = EC_COMPRESSED if compressed else EC_UNCOMPRESSED
        out = ffi.new("char [%d]" % size)
        out_size = ffi.new("size_t *", size)
        res = lib.secp256k1_ec_pubkey_serialize(secp.ctx, out, out_size, self.key, flag)
        assert res, "Unable to serialize"
        return bytearray(ffi.buffer(out, size))

    def to_hex(self, secp: Secp256k1, compressed=True) -> bytes:
        return hexlify(self.to_bytearray(secp, compressed))

    def clone(self, secp: Secp256k1):
        return PublicKey.from_bytearray(secp, self.to_bytearray(secp))

    # b: A -> A+b*G - Add a scalar in place
    def add_scalar_assign(self, secp: Secp256k1, other: SecretKey):
        res = lib.secp256k1_ec_pubkey_tweak_add(secp.ctx, self.key, bytes(other.key))
        assert res, "Unable to add scalar in place"

    # b: A+b*G - Add a scalar
    def add_scalar(self, secp: Secp256k1, other: SecretKey):
        obj = self.clone(secp)
        obj.add_scalar_assign(secp, other)
        return obj

    # B: A -> A+B - Add a public key in place
    def add_assign(self, secp: Secp256k1, other):
        obj = self.add(secp, other)
        self.key = obj.key

    # B: A+B - Add a public key
    def add(self, secp: Secp256k1, other):
        assert isinstance(other, PublicKey)
        obj = PublicKey.from_combination(secp, [self, other])
        return obj

    # b: A -> b*A - Multiple the public key by a scalar in place
    def mul_assign(self, secp: Secp256k1, other: SecretKey):
        res = lib.secp256k1_ec_pubkey_tweak_mul(secp.ctx, self.key, bytes(other.key))
        assert res, "Unable to multiply in place"

    # b: b*A - Multiple the public key by a scalar
    def mul(self, secp: Secp256k1, other: SecretKey):
        obj = self.clone(secp)
        obj.mul_assign(secp, other)
        return obj

    # A -> -A
    def negate_assign(self, secp: Secp256k1):
        res = lib.secp256k1_ec_pubkey_negate(secp.ctx, self.key)
        assert res, "Unable to negate in place"

    # -A
    def negate(self, secp: Secp256k1):
        obj = self.clone(secp)
        obj.negate_assign(secp)
        return obj

    @staticmethod
    def from_bytearray(secp: Secp256k1, data: bytearray):
        size = len(data)
        assert size in (PUBLIC_KEY_SIZE_COMPRESSED, PUBLIC_KEY_SIZE), "Invalid public key size"
        obj = PublicKey(secp)
        res = lib.secp256k1_ec_pubkey_parse(secp.ctx, obj.key, bytes(data), size)
        assert res, "Invalid public key"
        return obj

    @staticmethod
    def from_hex(secp: Secp256k1, data: bytes):
        return PublicKey.from_bytearray(secp, bytearray(unhexlify(data)))

    @staticmethod
    def from_secret_key(secp: Secp256k1, secret: SecretKey):
        obj = PublicKey(secp)
        res = lib.secp256k1_ec_pubkey_create(secp.ctx, obj.key, bytes(secret.key))
        assert res, "Invalid secret key"
        return obj

    @staticmethod
    def from_combination(secp: Secp256k1, pos_keys, neg_keys=None):
        assert len(pos_keys) > 0
        obj = PublicKey(secp)
        items = []
        for key in pos_keys:
            if isinstance(key, SecretKey):
                items.append(key.to_public_key(secp).key)
            else:
                assert isinstance(key, PublicKey), "Input not all instance of SecretKey or PublicKey"
                items.append(key.key)
        if isinstance(neg_keys, list):
            neg_sum = PublicKey.from_combination(secp, neg_keys)
            neg_sum.negate_assign(secp)
            items.append(neg_sum.key)
        res = lib.secp256k1_ec_pubkey_combine(secp.ctx, obj.key, items, len(items))
        assert res, "Unable to combine keys"
        return obj


class Signature:
    def __init__(self, signature: bytearray):
        self.signature = signature

    def __eq__(self, other):
        return isinstance(other, Signature) and self.signature == other.signature

    def __str__(self):
        return "Signature<{}>".format(self.to_hex().decode())

    def __repr__(self):
        return self.__str__()

    def scalar(self, secp: Secp256k1) -> SecretKey:
        return SecretKey.from_bytearray(secp, self.signature[:32])

    def to_bytearray(self, secp: Secp256k1, compact=False) -> bytearray:
        if not compact:
            return self.signature[:]
        signature = ffi.new("secp256k1_ecdsa_signature *", [bytes(self.signature)])
        output = ffi.new("char [64]")
        res = lib.secp256k1_ecdsa_signature_serialize_compact(secp.ctx, output, signature)
        assert res, "Unable to serialize signature"
        return bytearray(ffi.buffer(output, 64))

    def to_hex(self) -> bytes:
        return hexlify(self.signature)

    def normalize_s(self, secp: Secp256k1):
        signature_in = ffi.new("secp256k1_ecdsa_signature *", [bytes(self.signature)])
        signature_out = ffi.new("secp256k1_ecdsa_signature *")
        lib.secp256k1_ecdsa_signature_normalize(secp.ctx, signature_out, signature_in)
        self.signature = bytearray(ffi.buffer(signature_out, 64))

    @staticmethod
    def from_bytearray(secp: Secp256k1, signature: bytearray, compact=False):
        if not compact:
            return Signature(signature[:])
        signature_out = ffi.new("secp256k1_ecdsa_signature *")
        res = lib.secp256k1_ecdsa_signature_parse_compact(secp.ctx, signature_out, bytes(signature))
        assert res, "Unable to parse signature"
        return Signature(ffi.buffer(signature_out, 64))

    @staticmethod
    def from_hex(data: bytes):
        return Signature(unhexlify(data))


def ethereum_address(secp: Secp256k1, public_key: PublicKey) -> bytes:
    return b"0x"+hexlify(keccak(bytes(public_key.to_bytearray(secp, False)[1:]))[12:])

from binascii import hexlify, unhexlify
from hashlib import blake2b
from os import urandom
from typing import List
from secp256k1 import SECRET_KEY_SIZE
from secp256k1.key import SecretKey, PublicKey
from secp256k1.pedersen import Secp256k1, Commitment
from grin.extkey import ExtendedSecretKey, GrinHasher, ChildNumber

IDENTIFIER_SIZE = 17


class Identifier:
    def __init__(self):
        self.identifier = bytearray([0] * IDENTIFIER_SIZE)

    def __eq__(self, other):
        return isinstance(other, Identifier) and self.identifier == other.identifier

    def __str__(self):
        return "Identifier<{}>".format(self.to_hex().decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self) -> bytearray:
        identifier = self.identifier[:]
        return identifier

    def to_hex(self) -> bytes:
        return hexlify(self.identifier)

    def to_bip_32_string(self) -> str:
        path = KeychainPath.from_identifier(self)
        out = "m"
        for i in range(path.depth):
            out += "/"+str(path.path[i].to_index())
        return out

    def clone(self):
        return Identifier.from_bytearray(self.to_bytearray())

    def serialize_path(self) -> bytearray:
        return self.identifier[1:]

    def parent_path(self):
        path = KeychainPath.from_identifier(self)
        if path.depth > 0:
            path.path[path.depth - 1] = ChildNumber.from_index(0)
            path.depth = path.depth - 1
        return path.to_identifier()

    @staticmethod
    def from_bytearray(data: bytearray):
        obj = Identifier()
        for i in range(min(len(data), IDENTIFIER_SIZE)):
            obj.identifier[i] = data[i]
        return obj

    @staticmethod
    def from_hex(data: bytes):
        return Identifier.from_bytearray(bytearray(unhexlify(data)))

    @staticmethod
    def from_public_key(secp: Secp256k1, key: PublicKey):
        data = key.to_bytearray(secp)
        identifier = bytearray(blake2b(bytes(data), digest_size=IDENTIFIER_SIZE).digest())
        return Identifier.from_bytearray(identifier)

    @staticmethod
    def from_secret_key(secp: Secp256k1, key: SecretKey):
        public = key.to_public_key(secp)
        return Identifier.from_public_key(secp, public)

    @staticmethod
    def from_serialized_path(length: int, data: bytearray):
        identifier = bytearray()
        identifier.extend(int.to_bytes(length, 1, "big"))
        identifier.extend(data)
        return Identifier.from_bytearray(identifier)

    @staticmethod
    def random():
        return Identifier.from_bytearray(bytearray(urandom(IDENTIFIER_SIZE)))


class ChildKey:
    def __init__(self, n_child: int, root_key_id: Identifier, key_id: Identifier, key: ExtendedSecretKey):
        self.n_child = n_child
        self.root_key_id = root_key_id
        self.key_id = key_id
        self.key = key


# class ExtendedKey:
#     def __init__(self, secp: Secp256k1, derived: bytearray):
#         assert len(derived) == 64, "Invalid derived size"
#
#         key = SecretKey.from_bytearray(secp, derived[0:32])
#         identifier = Identifier.from_secret_key(secp, key)
#
#         self.n_child = 0
#         self.root_key_id = identifier.clone()
#         self.key_id = identifier.clone()
#         self.key = key
#         self.chain_code = derived[32:64]
#
#     def derive(self, secp: Secp256k1, n: int) -> ChildKey:
#         n_bytes = n.to_bytes(4, "big")
#         seed = self.key.to_bytearray()
#         seed.extend(n_bytes)
#         derived = bytearray(blake2b(bytes(seed), digest_size=32, key=bytes(self.chain_code)).digest())
#         key = SecretKey.from_bytearray(secp, derived)
#         key.add_assign(secp, self.key)
#         identifier = Identifier.from_secret_key(secp, key)
#         return ChildKey(n, self.root_key_id.clone(), identifier, key)
#
#     @staticmethod
#     def from_seed(secp: Secp256k1, seed: bytes, password=b""):
#         assert len(seed) in (16, 32, 64), "Invalid seed length"
#         derived = bytearray(blake2b(blake2b(seed, digest_size=64, key=password).digest(),
#                                     digest_size=64, key=b"Grin/MW Seed").digest())
#         return ExtendedKey(secp, derived)


class KeychainPath:
    def __init__(self, depth: int, path: List[ChildNumber]):
        self.depth = depth
        self.path = path

    def to_identifier(self) -> Identifier:
        data = bytearray()
        data.extend(self.depth.to_bytes(1, "big"))
        for i in range(4):
            data.extend(self.path[i].to_bytearray())
        return Identifier.from_bytearray(data)

    def last_path_index(self) -> int:
        if self.depth == 0:
            return 0
        return self.path[self.depth-1].to_index()

    @staticmethod
    def new(depth: int, d0: int, d1: int, d2: int, d3: int):
        return KeychainPath(depth, [
            ChildNumber.from_index(d0),
            ChildNumber.from_index(d1),
            ChildNumber.from_index(d2),
            ChildNumber.from_index(d3)
        ])

    @staticmethod
    def from_identifier(identifier: Identifier):
        data = identifier.to_bytearray()
        return KeychainPath(int.from_bytes(data[0:1], "big"), [
            ChildNumber.from_bytearray(data[1:5]),
            ChildNumber.from_bytearray(data[5:9]),
            ChildNumber.from_bytearray(data[9:13]),
            ChildNumber.from_bytearray(data[13:17])
        ])


class Keychain:
    def __init__(self, secp: Secp256k1, seed: bytes):
        self.secp = secp
        self.hasher = GrinHasher()
        self.master = ExtendedSecretKey.new_master(secp, self.hasher, bytearray(seed))

    def derive_key(self, identifier: Identifier) -> ExtendedSecretKey:
        path = KeychainPath.from_identifier(identifier)
        key = self.master
        for i in range(path.depth):
            key = key.ckd_secret(self.secp, self.hasher, path.path[i])
        return key

    def commit(self, amount: int, child_key: ChildKey) -> Commitment:
        return self.secp.commit(amount, child_key.key.secret_key)

    def blind_sum(self, blind_sum):
        assert isinstance(blind_sum, BlindSum)
        pos = []
        for child in blind_sum.positive_child_keys:
            pos.append(child.key.secret_key)
        for key in blind_sum.positive_blinding_factors:
            pos.append(key.to_secret_key(self.secp))
        neg = []
        for child in blind_sum.negative_child_keys:
            neg.append(child.key.secret_key)
        for key in blind_sum.negative_blinding_factors:
            neg.append(key.to_secret_key(self.secp))
        return BlindingFactor.from_secret_key(self.secp.blind_sum(pos, neg))

    @staticmethod
    def from_seed(secp: Secp256k1, seed: bytes):
        return Keychain(secp, seed)

    @staticmethod
    def root_key_id() -> Identifier:
        return KeychainPath.new(0, 0, 0, 0, 0).to_identifier()

    @staticmethod
    def derive_key_id(depth: int, d0: int, d1: int, d2: int, d3: int) -> Identifier:
        return KeychainPath.new(depth, d0, d1, d2, d3).to_identifier()


class BlindingFactor:
    def __init__(self):
        self.key = bytearray([0] * SECRET_KEY_SIZE)

    def __eq__(self, other):
        return isinstance(other, BlindingFactor) and self.to_bytearray() == other.to_bytearray()

    def __str__(self):
        return "BlindingFactor<{}>".format(self.to_hex().decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self) -> bytearray:
        return self.key[:]

    def to_hex(self) -> bytes:
        return hexlify(self.key)

    def to_secret_key(self, secp: Secp256k1) -> SecretKey:
        return SecretKey.from_bytearray(secp, self.to_bytearray())

    @staticmethod
    def from_bytearray(data: bytearray):
        obj = BlindingFactor()
        for i in range(min(len(data), SECRET_KEY_SIZE)):
            obj.key[i] = data[i]
        return obj

    @staticmethod
    def from_hex(data: bytes):
        return BlindingFactor.from_bytearray(bytearray(unhexlify(data)))

    @staticmethod
    def from_secret_key(key: SecretKey):
        return BlindingFactor.from_bytearray(key.to_bytearray())


class BlindSum:
    def __init__(self):
        self.positive_child_keys = []
        self.negative_child_keys = []
        self.positive_blinding_factors = []
        self.negative_blinding_factors = []

    def add_child_key(self, key: ChildKey):
        self.positive_child_keys.append(key)
        return self

    def sub_child_key(self, key: ChildKey):
        self.negative_child_keys.append(key)
        return self

    def add_blinding_factor(self, blind: BlindingFactor):
        self.positive_blinding_factors.append(blind)

    def sub_blinding_factor(self, blind: BlindingFactor):
        self.negative_blinding_factors.append(blind)

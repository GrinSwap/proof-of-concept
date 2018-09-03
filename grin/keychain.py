from hashlib import blake2b
from binascii import hexlify, unhexlify
from secp256k1 import SECRET_KEY_SIZE
from secp256k1.key import SecretKey, PublicKey
from secp256k1.pedersen import Secp256k1, Commitment

IDENTIFIER_SIZE = 10


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

    def clone(self):
        return Identifier.from_bytearray(self.to_bytearray())

    @staticmethod
    def from_bytearray(data: bytearray):
        assert isinstance(data, bytearray)
        obj = Identifier()
        for i in range(min(len(data), IDENTIFIER_SIZE)):
            obj.identifier[i] = data[i]
        return obj

    @staticmethod
    def from_hex(data: bytes):
        return Identifier.from_bytearray(bytearray(unhexlify(data)))

    @staticmethod
    def from_public_key(secp: Secp256k1, key: PublicKey):
        assert isinstance(secp, Secp256k1)
        assert isinstance(key, PublicKey)
        data = key.to_bytearray(secp)
        identifier = bytearray(blake2b(bytes(data), digest_size=IDENTIFIER_SIZE).digest())
        return Identifier.from_bytearray(identifier)

    @staticmethod
    def from_secret_key(secp: Secp256k1, key: SecretKey):
        assert isinstance(secp, Secp256k1)
        assert isinstance(key, SecretKey)
        public = key.to_public_key(secp)
        return Identifier.from_public_key(secp, public)


class ChildKey:
    def __init__(self, n_child: int, root_key_id: Identifier, key_id: Identifier, key: SecretKey):
        self.n_child = n_child
        self.root_key_id = root_key_id
        self.key_id = key_id
        self.key = key


class ExtendedKey:
    def __init__(self, secp: Secp256k1, derived: bytearray):
        assert len(derived) == 64, "Invalid derived size"

        key = SecretKey.from_bytearray(secp, derived[0:32])
        identifier = Identifier.from_secret_key(secp, key)

        self.n_child = 0
        self.root_key_id = identifier.clone()
        self.key_id = identifier.clone()
        self.key = key
        self.chain_code = derived[32:64]

    def derive(self, secp: Secp256k1, n: int) -> ChildKey:
        n_bytes = n.to_bytes(4, "big")
        seed = self.key.to_bytearray()
        seed.extend(n_bytes)
        derived = bytearray(blake2b(bytes(seed), digest_size=32, key=bytes(self.chain_code)).digest())
        key = SecretKey.from_bytearray(secp, derived)
        key.add_assign(secp, self.key)
        identifier = Identifier.from_secret_key(secp, key)
        return ChildKey(n, self.root_key_id.clone(), identifier, key)

    @staticmethod
    def from_seed(secp: Secp256k1, seed: bytes, password=b""):
        assert len(seed) in (16, 32, 64), "Invalid seed length"
        derived = bytearray(blake2b(blake2b(seed, digest_size=64, key=password).digest(),
                                    digest_size=64, key=b"Grin/MW Seed").digest())
        return ExtendedKey(secp, derived)


class Keychain:
    def __init__(self, secp: Secp256k1, seed: bytes, password=b""):
        self.secp = secp
        self.ext_key = ExtendedKey.from_seed(secp, seed, password=password)

    def derive(self, n: int) -> ChildKey:
        return self.ext_key.derive(self.secp, n)

    def commit(self, value: int, child: ChildKey) -> Commitment:
        return self.secp.commit(value, child.key)

    def commit_with_key(self, value: int, n: int) -> Commitment:
        child = self.derive(n)
        return self.commit(value, child)

    def blind_sum(self, blind_sum):
        assert isinstance(blind_sum, BlindSum)
        pos = []
        for child in blind_sum.positive_child_keys:
            pos.append(child.key)
        for key in blind_sum.positive_blinding_factors:
            pos.append(key.to_secret_key(self.secp))
        neg = []
        for child in blind_sum.negative_child_keys:
            neg.append(child.key)
        for key in blind_sum.negative_blinding_factors:
            neg.append(key.to_secret_key(self.secp))
        return BlindingFactor.from_secret_key(self.secp.blind_sum(pos, neg))

    @staticmethod
    def from_seed(secp: Secp256k1, seed: bytes, password=b""):
        return Keychain(secp, seed, password=password)


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

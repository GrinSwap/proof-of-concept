import abc
import hashlib
import hmac
from typing import List
from secp256k1 import Secp256k1
from secp256k1.key import SecretKey, PublicKey
from grin.util import base58check_encode, base58check_decode


class HardenedIndexError(Exception):
    pass


class ChildNumberRangeError(Exception):
    pass


class ChainCode:
    def __init__(self, chain_code: bytearray):
        assert len(chain_code) == 32
        self.chain_code = chain_code

    def __eq__(self, other):
        return isinstance(other, ChainCode) and self.chain_code == other.chain_code

    def to_bytearray(self) -> bytearray:
        return self.chain_code[:]

    @staticmethod
    def from_bytearray(data: bytearray):
        return ChainCode(data)


class Fingerprint:
    def __init__(self, data: bytearray):
        fingerprint = bytearray([0] * 4)
        for i in range(min(4, len(data))):
            fingerprint[i] = data[i]
        self.fingerprint = fingerprint

    def __eq__(self, other):
        return isinstance(other, Fingerprint) and self.fingerprint == other.fingerprint

    def to_bytearray(self) -> bytearray:
        return self.fingerprint[:]

    @staticmethod
    def from_bytearray(data: bytearray):
        return Fingerprint(data)

    @staticmethod
    def default():
        return Fingerprint(bytearray([0] * 4))


class ChildNumber:
    def __init__(self, index: int, hardened: bool):
        if not 0 <= index < 2**31:
            raise ChildNumberRangeError()
        self.index = index
        self.hardened = hardened

    def __eq__(self, other):
        return isinstance(other, ChildNumber) and self.index == other.index and self.hardened == other.hardened

    def __repr__(self):
        return "ChildNumber<{}{}>".format(self.index, "h" if self.hardened else "")

    def to_index(self) -> int:
        index = self.index
        if self.hardened:
            index += 2 ** 31
        return index

    def to_bytearray(self) -> bytearray:
        return bytearray(self.to_index().to_bytes(4, "big"))

    def is_normal(self) -> bool:
        return not self.hardened

    def is_hardened(self) -> bool:
        return self.hardened

    @staticmethod
    def from_normal_index(index: int):
        return ChildNumber(index, False)

    @staticmethod
    def from_hardened_index(index: int):
        return ChildNumber(index, True)

    @staticmethod
    def from_index(index: int):
        if index >= 2**31:
            return ChildNumber(index-2**31, True)
        else:
            return ChildNumber(index, False)

    @staticmethod
    def from_bytearray(data: bytearray):
        return ChildNumber.from_index(int.from_bytes(bytes(data), "big"))


class Hasher(abc.ABC):
    @abc.abstractmethod
    def network_secret(self) -> bytearray:
        pass

    @abc.abstractmethod
    def network_public(self) -> bytearray:
        pass

    @abc.abstractmethod
    def master_seed(self) -> bytearray:
        pass

    @abc.abstractmethod
    def init_sha512(self, seed: bytearray):
        pass

    @abc.abstractmethod
    def append_sha512(self, value: bytearray):
        pass

    @abc.abstractmethod
    def result_sha512(self) -> bytearray:
        pass

    @abc.abstractmethod
    def sha_256(self, input: bytearray) -> bytearray:
        pass

    @abc.abstractmethod
    def ripemd_160(self, input: bytearray) -> bytearray:
        pass


class GrinHasher(Hasher):
    def __init__(self):
        self.hmac = hmac.new(bytearray([0]*128), None, hashlib.sha512)

    def network_secret(self) -> bytearray:
        return bytearray([0x03, 0x3C, 0x04, 0xA4])

    def network_public(self) -> bytearray:
        return bytearray([0x03, 0x3C, 0x08, 0xDF])

    def master_seed(self) -> bytearray:
        return bytearray(b"IamVoldemort")

    def init_sha512(self, seed: bytearray):
        self.hmac = hmac.new(seed, None, hashlib.sha512)

    def append_sha512(self, value: bytearray):
        self.hmac.update(bytes(value))

    def result_sha512(self) -> bytearray:
        return bytearray(self.hmac.digest())

    def sha_256(self, data: bytearray) -> bytearray:
        return bytearray(hashlib.sha256(bytes(data)).digest())

    def ripemd_160(self, data: bytearray) -> bytearray:
        h = hashlib.new("ripemd160")
        h.update(bytes(data))
        return bytearray(h.digest())


class ReferenceHasher(Hasher):
    def __init__(self):
        self.hmac = hmac.new(bytearray([0]*128), None, hashlib.sha512)

    def network_secret(self) -> bytearray:
        return bytearray([0x04, 0x88, 0xAD, 0xE4])

    def network_public(self) -> bytearray:
        return bytearray([0x04, 0x88, 0xB2, 0x1E])

    def master_seed(self) -> bytearray:
        return bytearray(b"Bitcoin seed")

    def init_sha512(self, seed: bytearray):
        self.hmac = hmac.new(seed, None, hashlib.sha512)

    def append_sha512(self, value: bytearray):
        self.hmac.update(bytes(value))

    def result_sha512(self) -> bytearray:
        return bytearray(self.hmac.digest())

    def sha_256(self, data: bytearray) -> bytearray:
        return bytearray(hashlib.sha256(bytes(data)).digest())

    def ripemd_160(self, data: bytearray) -> bytearray:
        h = hashlib.new("ripemd160")
        h.update(bytes(data))
        return bytearray(h.digest())


class ExtendedSecretKey:
    def __init__(self, network: bytearray, depth: int, parent_fingerprint: Fingerprint, child_number: ChildNumber,
                 secret_key: SecretKey, chain_code: ChainCode):
        assert len(network) == 4
        assert 0 <= depth < 2**8
        self.network = network
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.secret_key = secret_key
        self.chain_code = chain_code

    def __eq__(self, other):
        return isinstance(other, ExtendedSecretKey) and self.network == other.network and self.depth == other.depth \
            and self.parent_fingerprint == other.parent_fingerprint and self.child_number == other.child_number \
            and self.secret_key == other.secret_key and self.chain_code == other.chain_code

    def to_bytearray(self) -> bytearray:
        data = bytearray()
        data.extend(self.network)
        data.extend(self.depth.to_bytes(1, "big"))
        data.extend(self.parent_fingerprint.to_bytearray())
        data.extend(self.child_number.to_bytearray())
        data.extend(self.chain_code.to_bytearray())
        data.append(0)
        data.extend(self.secret_key.to_bytearray())
        return data

    def to_base58check(self) -> bytes:
        return base58check_encode(self.to_bytearray())

    def derive_secret(self, secp: Secp256k1, hasher: Hasher, path: List[ChildNumber]):
        key = self
        for i in path:
            key = key.ckd_secret(secp, hasher, i)
        return key

    def ckd_secret(self, secp: Secp256k1, hasher: Hasher, i: ChildNumber):
        hasher.init_sha512(self.chain_code.to_bytearray())
        if i.is_normal():
            hasher.append_sha512(self.secret_key.to_public_key(secp).to_bytearray(secp))
        else:
            hasher.append_sha512(bytearray([0]))
            hasher.append_sha512(self.secret_key.to_bytearray())
        hasher.append_sha512(i.to_bytearray())
        hash = hasher.result_sha512()
        key = SecretKey.from_bytearray(secp, hash[:32])
        key.add_assign(secp, self.secret_key)
        return ExtendedSecretKey(self.network, self.depth + 1, self.fingerprint(secp, hasher),
                                 i, key, ChainCode.from_bytearray(hash[32:]))

    def fingerprint(self, secp: Secp256k1, hasher: Hasher) -> Fingerprint:
        return Fingerprint.from_bytearray(self.identifier(secp, hasher))

    def identifier(self, secp: Secp256k1, hasher: Hasher) -> bytearray:
        return hasher.ripemd_160(hasher.sha_256(self.secret_key.to_public_key(secp).to_bytearray(secp)))

    @staticmethod
    def new_master(secp: Secp256k1, hasher: Hasher, seed: bytearray):
        hasher.init_sha512(hasher.master_seed())
        hasher.append_sha512(seed)
        hash = hasher.result_sha512()
        return ExtendedSecretKey(hasher.network_secret(), 0, Fingerprint.default(), ChildNumber.from_normal_index(0),
                                 SecretKey.from_bytearray(secp, hash[:32]), ChainCode.from_bytearray(hash[32:]))

    @staticmethod
    def from_bytearray(secp: Secp256k1, data: bytearray):
        assert len(data) == 78
        return ExtendedSecretKey(data[:4], data[4], Fingerprint.from_bytearray(data[5:9]),
                                 ChildNumber.from_bytearray(data[9:13]), SecretKey.from_bytearray(secp, data[46:78]),
                                 ChainCode.from_bytearray(data[13:45]))

    @staticmethod
    def from_base58check(secp: Secp256k1, data: bytes):
        return ExtendedSecretKey.from_bytearray(secp, base58check_decode(data))


class ExtendedPublicKey:
    def __init__(self, network: bytearray, depth: int, parent_fingerprint: Fingerprint, child_number: ChildNumber,
                 public_key: PublicKey, chain_code: ChainCode):
        self.network = network
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.public_key = public_key
        self.chain_code = chain_code

    def __eq__(self, other):
        return isinstance(other, ExtendedPublicKey) and self.network == other.network and self.depth == other.depth \
            and self.parent_fingerprint == other.parent_fingerprint and self.child_number == other.child_number \
            and self.public_key == other.public_key and self.chain_code == other.chain_code

    def to_bytearray(self, secp: Secp256k1) -> bytearray:
        data = bytearray()
        data.extend(self.network)
        data.extend(self.depth.to_bytes(1, "big"))
        data.extend(self.parent_fingerprint.to_bytearray())
        data.extend(self.child_number.to_bytearray())
        data.extend(self.chain_code.to_bytearray())
        data.extend(self.public_key.to_bytearray(secp))
        return data

    def to_base58check(self, secp: Secp256k1) -> bytes:
        return base58check_encode(self.to_bytearray(secp))

    def derive_public(self, secp: Secp256k1, hasher: Hasher, path: List[ChildNumber]):
        key = self
        for i in path:
            key = key.ckd_public(secp, hasher, i)
        return key

    def ckd_public(self, secp: Secp256k1, hasher: Hasher, i: ChildNumber):
        if i.is_hardened():
            raise HardenedIndexError()

        hasher.init_sha512(self.chain_code.to_bytearray())
        hasher.append_sha512(self.public_key.to_bytearray(secp))
        hasher.append_sha512(i.to_bytearray())
        hash = hasher.result_sha512()
        key = SecretKey.from_bytearray(secp, hash[:32]).to_public_key(secp)
        key.add_assign(secp, self.public_key)

        return ExtendedPublicKey(self.network, self.depth + 1, self.fingerprint(secp, hasher),
                                 i, key, ChainCode.from_bytearray(hash[32:]))

    def fingerprint(self, secp: Secp256k1, hasher: Hasher) -> Fingerprint:
        return Fingerprint.from_bytearray(self.identifier(secp, hasher))

    def identifier(self, secp: Secp256k1, hasher: Hasher) -> bytearray:
        return hasher.ripemd_160(hasher.sha_256(self.public_key.to_bytearray(secp)))

    @staticmethod
    def from_secret(secp: Secp256k1, hasher: Hasher, key: ExtendedSecretKey):
        return ExtendedPublicKey(hasher.network_public(), key.depth, key.parent_fingerprint, key.child_number,
                                 key.secret_key.to_public_key(secp), key.chain_code)

    @staticmethod
    def from_bytearray(secp: Secp256k1, data: bytearray):
        assert len(data) == 78
        return ExtendedPublicKey(data[:4], data[4], Fingerprint.from_bytearray(data[5:9]),
                                 ChildNumber.from_bytearray(data[9:13]), PublicKey.from_bytearray(secp, data[45:78]),
                                 ChainCode.from_bytearray(data[13:45]))

    @staticmethod
    def from_base58check(secp: Secp256k1, data: bytes):
        return ExtendedPublicKey.from_bytearray(secp, base58check_decode(data))

from binascii import hexlify, unhexlify
from secp256k1 import Secp256k1 as Secp256k1_base, SECRET_KEY_SIZE
from secp256k1.key import SecretKey, PublicKey
from ._libsecp256k1 import ffi, lib

PEDERSEN_COMMITMENT_SIZE = 33
MAX_PROOF_SIZE = 675
PROOF_MSG_SIZE = 64
MAX_WIDTH = 1 << 20


# Pedersen Commitment xG+vH
class Commitment:
    def __init__(self, secp):
        assert isinstance(secp, Secp256k1)
        self.commitment = ffi.new("secp256k1_pedersen_commitment *")
        self.secp = secp

    def __eq__(self, other):
        return isinstance(other, Commitment) and self.to_bytearray(self.secp) == other.to_bytearray(other.secp)

    def __str__(self):
        return "Commitment<{}>".format(self.to_hex(self.secp).decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self, secp) -> bytearray:
        assert isinstance(secp, Secp256k1)
        out = ffi.new("char [%d]" % PEDERSEN_COMMITMENT_SIZE)
        res = lib.secp256k1_pedersen_commitment_serialize(secp.ctx, out, self.commitment)
        assert res, "Unable to serialize"
        return bytearray(ffi.buffer(out, PEDERSEN_COMMITMENT_SIZE))

    def to_hex(self, secp) -> bytes:
        return hexlify(self.to_bytearray(secp))

    def to_public_key(self, secp) -> PublicKey:
        assert isinstance(secp, Secp256k1)
        obj = PublicKey(secp)
        res = lib.secp256k1_pedersen_commitment_to_pubkey(secp.ctx, obj.key, self.commitment)
        assert res, "Unable to convert to public key"
        return obj

    @staticmethod
    def from_bytearray(secp, data: bytearray):
        assert isinstance(secp, Secp256k1)
        input = bytearray([0] * PEDERSEN_COMMITMENT_SIZE)
        for i in range(min(len(data), PEDERSEN_COMMITMENT_SIZE)):
            input[i] = data[i]
        obj = Commitment(secp)
        res = lib.secp256k1_pedersen_commitment_parse(secp.ctx, obj.commitment, bytes(input))
        assert res, "Invalid commitment"
        return obj

    @staticmethod
    def from_hex(secp, data: bytes):
        return Commitment.from_bytearray(secp, bytearray(unhexlify(data)))


class RangeProof:
    def __init__(self, proof: bytearray):
        self.proof = proof
        self.proof_len = len(proof)

    def __eq__(self, other):
        return isinstance(other, RangeProof) and self.proof == other.proof

    def __str__(self):
        return "RangeProof<len={}, {}>".format(self.proof_len, hexlify(self.proof[0:8]).decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self) -> bytearray:
        return self.proof[:]

    def to_hex(self) -> bytes:
        return hexlify(bytes(self.proof))

    @staticmethod
    def from_bytearray(data: bytearray):
        assert len(data) <= MAX_PROOF_SIZE, "Invalid proof size"
        return RangeProof(data)

    @staticmethod
    def from_hex(data: bytes):
        return RangeProof.from_bytearray(bytearray(unhexlify(data)))


class Secp256k1(Secp256k1_base):
    def __init__(self, ctx, flags):
        super().__init__(ctx, flags)
        self.GENERATOR_G = ffi.new("secp256k1_generator *", [bytes([
            0x0a,
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
            0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
            0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
        ])])
        self.GENERATOR_H = ffi.new("secp256k1_generator *", [bytes([
            0x11,
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
            0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
            0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
            0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0
        ])])

        self.gens = lib.secp256k1_bulletproof_generators_create(self.ctx, self.GENERATOR_G, 256)

    def commit(self, value: int, blind) -> Commitment:
        obj = Commitment(self)
        res = lib.secp256k1_pedersen_commit(self.ctx, obj.commitment, bytes(blind.key), value,
                                            self.GENERATOR_H, self.GENERATOR_G)
        assert res, "Unable to commit"
        return obj

    def commit_value(self, value: int) -> Commitment:
        blind = SecretKey()
        return self.commit(value, blind)

    def commit_sum(self, positives, negatives) -> Commitment:
        pos = []
        for positive in positives:
            assert isinstance(positive, Commitment)
            pos.append(positive.commitment)
        neg = []
        for negative in negatives:
            assert isinstance(negative, Commitment)
            neg.append(negative.commitment)
        commit_sum = Commitment(self)
        res = lib.secp256k1_pedersen_commit_sum(self.ctx, commit_sum.commitment, pos, len(pos), neg, len(neg))
        assert res, "Unable to sum commitments"
        return commit_sum

    def blind_sum(self, positives, negatives) -> SecretKey:
        keys = []
        for positive in positives:
            assert isinstance(positive, SecretKey)
            keys.append(ffi.new("char []", bytes(positive.key)))
        for negative in negatives:
            assert isinstance(negative, SecretKey)
            keys.append(ffi.new("char []", bytes(negative.key)))
        sum_key = ffi.new("char []", SECRET_KEY_SIZE)
        ret = lib.secp256k1_pedersen_blind_sum(self.ctx, sum_key, keys, len(keys), len(positives))
        assert ret, "Unable to sum blinding factors"
        return SecretKey.from_bytearray(self, bytearray(ffi.buffer(sum_key, SECRET_KEY_SIZE)))

    def sign_recoverable(self, secret_key: SecretKey, message: bytearray) -> bytearray:
        assert len(message) == 32, "Invalid message length"
        signature_obj = ffi.new("secp256k1_ecdsa_recoverable_signature *")
        res = lib.secp256k1_ecdsa_sign_recoverable(
            self.ctx, signature_obj, bytes(message), bytes(secret_key.key), ffi.NULL, ffi.NULL
        )
        assert res, "Unable to generate recoverable signature"
        signature_ptr = ffi.new("char []", 64)
        rec_id_ptr = ffi.new("int *")
        res = lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
            self.ctx, signature_ptr, rec_id_ptr, signature_obj
        )
        assert res, "Unable to serialize recoverable signature"
        signature = bytearray(ffi.buffer(signature_ptr, 64))
        signature.append(rec_id_ptr[0])
        return signature

    def bullet_proof(self, value: int, blind: SecretKey, nonce: SecretKey, extra_data: bytearray) -> RangeProof:
        proof_ptr = ffi.new("char []", MAX_PROOF_SIZE)
        proof_len_ptr = ffi.new("size_t *", MAX_PROOF_SIZE)
        blind_key = ffi.new("char []", bytes(blind.key))
        scratch = lib.secp256k1_scratch_space_create(self.ctx, 256 * MAX_WIDTH)
        res = lib.secp256k1_bulletproof_rangeproof_prove(
            self.ctx, scratch, self.gens, proof_ptr, proof_len_ptr, [value], ffi.NULL, [blind_key],
            1, self.GENERATOR_H, 64, bytes(nonce.key), bytes(extra_data), len(extra_data)
        )
        obj = RangeProof.from_bytearray(bytearray(ffi.buffer(proof_ptr, proof_len_ptr[0])))
        lib.secp256k1_scratch_space_destroy(scratch)
        assert res, "Unable to generate bulletproof"
        return obj

    def bullet_proof_multisig_1(self, nonce: SecretKey) -> (PublicKey, PublicKey):
        t_1 = PublicKey(self)
        t_2 = PublicKey(self)
        lib.secp256k1_bulletproof_rangeproof_1(self.ctx, self.gens, t_1.key, t_2.key, bytes(nonce.key))
        return t_1, t_2

    def bullet_proof_multisig_2(self, value: int, blind: SecretKey, commit: Commitment, nonce: SecretKey,
                                common_nonce: SecretKey, t_1: PublicKey, t_2: PublicKey,
                                extra_data: bytearray) -> SecretKey:
        scratch = lib.secp256k1_scratch_space_create(self.ctx, 256 * MAX_WIDTH)
        tau_x_ptr = ffi.new("char []", 32)
        blind_ptr = ffi.new("char []", bytes(blind.key))
        commit_public = commit.to_public_key(self)
        res = lib.secp256k1_bulletproof_rangeproof_2(
            self.ctx, scratch, self.gens, tau_x_ptr, t_1.key, t_2.key, [value], ffi.NULL, [blind_ptr],
            [commit_public.key], 1, self.GENERATOR_H, 64, bytes(nonce.key), bytes(common_nonce.key), bytes(extra_data),
            len(extra_data)
        )
        lib.secp256k1_scratch_space_destroy(scratch)
        assert res, "Unable to generate multisig bulletproof"
        return SecretKey.from_bytearray(self, bytearray(ffi.buffer(tau_x_ptr, 32)))

    def bullet_proof_multisig_3(self, value: int, blind: SecretKey, commit: Commitment, nonce: SecretKey,
                                common_nonce: SecretKey, t_1: PublicKey, t_2: PublicKey, tau_x: SecretKey,
                                extra_data: bytearray) -> RangeProof:
        scratch = lib.secp256k1_scratch_space_create(self.ctx, 256 * MAX_WIDTH)
        proof_ptr = ffi.new("char []", MAX_PROOF_SIZE)
        proof_len_ptr = ffi.new("size_t *", MAX_PROOF_SIZE)
        tau_x_ptr = ffi.new("char []", bytes(tau_x.to_bytearray()))
        blind_ptr = ffi.new("char []", bytes(blind.key))
        commit_public = commit.to_public_key(self)

        res = lib.secp256k1_bulletproof_rangeproof_3(
            self.ctx, scratch, self.gens, proof_ptr, proof_len_ptr, tau_x_ptr, t_1.key, t_2.key, [value], ffi.NULL,
            [blind_ptr], [commit_public.key], 1, self.GENERATOR_H, 64, bytes(nonce.key), bytes(common_nonce.key),
            bytes(extra_data), len(extra_data)
        )
        lib.secp256k1_scratch_space_destroy(scratch)
        assert res, "Unable to generate multisig bulletproof"
        return RangeProof.from_bytearray(bytearray(ffi.buffer(proof_ptr, proof_len_ptr[0])))

    def verify_bullet_proof(self, commit: Commitment, proof: RangeProof, extra_data: bytearray) -> bool:
        scratch = lib.secp256k1_scratch_space_create(self.ctx, 256 * MAX_WIDTH)
        res = lib.secp256k1_bulletproof_rangeproof_verify(
            self.ctx, scratch, self.gens, bytes(proof.proof), proof.proof_len, ffi.NULL, commit.commitment,
            1, 64, self.GENERATOR_H, bytes(extra_data), len(extra_data)
        )
        lib.secp256k1_scratch_space_destroy(scratch)
        assert res, "Unable to verify bulletproof"
        return True


def ethereum_signature(data: bytearray) -> (bytes, bytes, int):
    assert len(data) == 65
    r = b"0x"+hexlify(bytes(data[:32]))
    s = b"0x"+hexlify(bytes(data[32:64]))
    v = int.from_bytes(bytes(data[64:]), "big") + 27
    return r, s, v

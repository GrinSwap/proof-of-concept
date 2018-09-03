from hashlib import blake2b
from secp256k1.key import SecretKey, PublicKey
from secp256k1.pedersen import Secp256k1, Commitment, RangeProof
from grin.keychain import ChildKey, Identifier


def create_nonce(secp: Secp256k1, root_key: Identifier, commit: Commitment) -> SecretKey:
    return SecretKey.from_bytearray(secp, bytearray(
        blake2b(bytes(root_key.identifier), digest_size=32, key=bytes(commit.to_bytearray(secp))).digest()
    ))


def create_common_nonce(secp: Secp256k1, secret_key: SecretKey, public_key: PublicKey, commit: Commitment) -> SecretKey:
    common_key = public_key.mul(secp, secret_key)
    return SecretKey.from_bytearray(secp, bytearray(
        blake2b(bytes(common_key.to_bytearray(secp)), digest_size=32, key=bytes(commit.to_bytearray(secp))).digest()
    ))


def create(secp: Secp256k1, child: ChildKey, amount: int, commit: Commitment, extra_data: bytearray) -> RangeProof:
    nonce = create_nonce(secp, child.root_key_id, commit)
    return secp.bullet_proof(amount, child.key, nonce, extra_data)


def verify(secp: Secp256k1, commit: Commitment, proof: RangeProof, extra_data: bytearray) -> bool:
    return secp.verify_bullet_proof(commit, proof, extra_data)


class MultiPartyBulletProof:
    def __init__(self, secp: Secp256k1, child: ChildKey, public_key: PublicKey, amount: int, commit: Commitment):
        self.secp = secp
        self.child = child
        self.amount = amount
        self.commit = commit
        self.nonce = create_nonce(secp, child.root_key_id, commit)
        self.common_nonce = create_common_nonce(secp, self.child.key, public_key, commit)
        self.t_1 = None
        self.t_2 = None
        self.tau_x = None

    def step_1(self) -> (PublicKey, PublicKey):
        t_1, t_2 = self.secp.bullet_proof_multisig_1(self.nonce)
        return t_1, t_2

    def fill_step_1(self, t_1: PublicKey, t_2: PublicKey):
        self.t_1 = t_1
        self.t_2 = t_2

    def step_2(self) -> SecretKey:
        return self.secp.bullet_proof_multisig_2(self.amount, self.child.key, self.commit, self.nonce,
                                                 self.common_nonce, self.t_1, self.t_2, bytearray())

    def fill_step_2(self, tau_x: SecretKey):
        self.tau_x = tau_x

    def finalize(self) -> RangeProof:
        return self.secp.bullet_proof_multisig_3(self.amount, self.child.key, self.commit, self.nonce,
                                                 self.common_nonce, self.t_1, self.t_2, self.tau_x, bytearray())

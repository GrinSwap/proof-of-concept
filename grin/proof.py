from hashlib import blake2b
from secp256k1.key import SecretKey, PublicKey
from secp256k1.pedersen import Secp256k1, Commitment, RangeProof
from grin.extkey import ChainCode, ExtendedSecretKey
from grin.keychain import ChildKey


def create_nonce(secp: Secp256k1, chain_code: ChainCode, commit: Commitment) -> SecretKey:
    return SecretKey.from_bytearray(secp, bytearray(
        blake2b(bytes(chain_code.chain_code), digest_size=32, key=bytes(commit.to_bytearray(secp))).digest()
    ))


def create_common_nonce(secp: Secp256k1, secret_key: SecretKey, public_key: PublicKey, commit: Commitment) -> SecretKey:
    common_key = public_key.mul(secp, secret_key)
    return SecretKey.from_bytearray(secp, bytearray(
        blake2b(bytes(common_key.to_bytearray(secp)), digest_size=32, key=bytes(commit.to_bytearray(secp))).digest()
    ))


def create(secp: Secp256k1, ext_key: ExtendedSecretKey, amount: int,
           commit: Commitment, extra_data: bytearray) -> RangeProof:
    nonce = create_nonce(secp, ext_key.chain_code, commit)
    return secp.bullet_proof(amount, ext_key.secret_key, nonce, extra_data)


def verify(secp: Secp256k1, commit: Commitment, proof: RangeProof, extra_data: bytearray) -> bool:
    return secp.verify_bullet_proof(commit, proof, extra_data)


class MultiPartyBulletProof:
    def __init__(self, secp: Secp256k1, ext_key: ExtendedSecretKey, amount: int,
                 commit: Commitment, common_nonce: SecretKey):
        self.secp = secp
        self.key = ext_key.secret_key
        self.amount = amount
        self.commit = commit
        self.nonce = create_nonce(secp, ext_key.chain_code, commit)
        self.common_nonce = common_nonce
        self.t_1 = None
        self.t_2 = None
        self.tau_x = None

    def round_1(self) -> (PublicKey, PublicKey):
        self.t_1, self.t_2 = self.secp.bullet_proof_multisig_1(self.amount, self.key, self.commit,
                                                               self.common_nonce, self.nonce, bytearray())
        return self.t_1.clone(self.secp), self.t_2.clone(self.secp)

    def fill_round_1(self, t_1: PublicKey, t_2: PublicKey):
        if self.t_1 is None:
            self.t_1 = t_1.clone(self.secp)
        else:
            self.t_1.add_assign(self.secp, t_1)

        if self.t_2 is None:
            self.t_2 = t_2.clone(self.secp)
        else:
            self.t_2.add_assign(self.secp, t_2)

    def round_2(self) -> SecretKey:
        self.tau_x = self.secp.bullet_proof_multisig_2(self.amount, self.key, self.commit, self.common_nonce,
                                                       self.nonce, self.t_1, self.t_2, bytearray())
        return self.tau_x.clone()

    def fill_round_2(self, tau_x: SecretKey):
        if self.tau_x is None:
            self.tau_x = tau_x
        else:
            self.tau_x.add_assign(self.secp, tau_x)

    def finalize(self) -> RangeProof:
        return self.secp.bullet_proof_multisig_3(self.amount, self.key, self.commit, self.common_nonce,
                                                 self.nonce, self.t_1, self.t_2, self.tau_x, bytearray())


class TwoPartyBulletProof(MultiPartyBulletProof):
    def __init__(self, secp: Secp256k1, ext_key: ExtendedSecretKey, public_key: PublicKey,
                 amount: int, commit: Commitment):
        common_nonce = create_common_nonce(secp, ext_key.secret_key, public_key, commit)
        super().__init__(secp, ext_key, amount, commit, common_nonce)

from typing import List, Optional
from enum import Enum
from binascii import hexlify
from grin.util import hasher, sort_by_hash, MILLI_GRIN_UNIT
from grin.keychain import Keychain, BlindingFactor, ChildKey
from grin.proof import create as create_proof, verify as verify_proof
import grin.aggsig as aggsig
from secp256k1.key import SecretKey, Signature, PUBLIC_KEY_SIZE_COMPRESSED
from secp256k1.pedersen import Secp256k1, Commitment, RangeProof


def tx_fee(n_input: int, n_output: int, base_fee: Optional[int]):
    if base_fee is None:
        base_fee = MILLI_GRIN_UNIT
    weight = max(1, 1+4*n_output-n_input)
    return weight*base_fee


class OutputFeatures(Enum):
    DEFAULT_OUTPUT = 0
    COINBASE_OUTPUT = 1


class Input:
    def __init__(self, features: OutputFeatures, commit: Commitment):
        self.features = features
        self.commit = commit

    def __repr__(self):
        return "Input<f={}, {}>".format(self.features.value, self.commit)

    def to_bytearray(self, secp: Secp256k1) -> bytearray:
        data = bytearray()
        data.extend(bytearray(int(self.features.value).to_bytes(1, "big")))
        data.extend(self.commit.to_bytearray(secp))
        return data

    def to_dict(self, secp: Secp256k1, short=False) -> dict:
        return {
            "features": self.features.value if short else {"bits": self.features.value},
            "commit": self.commit.to_hex(secp).decode() if short else list(self.commit.to_bytearray(secp))
        }

    def hash(self, secp: Secp256k1) -> bytes:
        return hasher(self.to_bytearray(secp))

    @staticmethod
    def from_dict(secp: Secp256k1, dct: dict, short=False):
        features = OutputFeatures(dct['features']) if short else OutputFeatures(dct['features']['bits'])
        commit = Commitment.from_hex(secp, dct['commit'].encode()) if short else \
            Commitment.from_bytearray(secp, bytearray(dct['commit']))
        return Input(features, commit)


class Output:
    def __init__(self, features: OutputFeatures, commit: Commitment, range_proof: RangeProof):
        self.features = features
        self.commit = commit
        self.range_proof = range_proof

    def __repr__(self):
        return "Output<f={}, {}, {}>".format(self.features.value, self.commit, self.range_proof)

    def to_bytearray(self, secp: Secp256k1, for_hash=False) -> bytearray:
        data = bytearray()
        data.extend(bytearray(int(self.features.value).to_bytes(1, "big")))
        data.extend(self.commit.to_bytearray(secp))
        if not for_hash:
            proof = self.range_proof.to_bytearray()
            data.extend(bytearray(len(proof).to_bytes(8, "big")))
            data.extend(proof)
        return data

    def to_dict(self, secp, short=False) -> dict:
        return {
            "features": self.features.value if short else {"bits": self.features.value},
            "commit": self.commit.to_hex(secp).decode() if short else list(self.commit.to_bytearray(secp)),
            "proof": self.range_proof.to_hex().decode() if short else list(self.range_proof.to_bytearray())
        }

    def hash(self, secp: Secp256k1) -> bytes:
        return hasher(self.to_bytearray(secp, True))

    def verify(self, secp: Secp256k1) -> bool:
        return verify_proof(secp, self.commit, self.range_proof, bytearray())

    @staticmethod
    def from_dict(secp: Secp256k1, dct: dict, short=False):
        features = OutputFeatures(dct['features']) if short else OutputFeatures(dct['features']['bits'])
        commit = Commitment.from_hex(secp, dct['commit'].encode()) if short else \
            Commitment.from_bytearray(secp, bytearray(dct['commit']))
        proof = RangeProof.from_hex(dct['proof'].encode()) if short else \
            RangeProof.from_bytearray(bytearray(dct['proof']))
        return Output(features, commit, proof)

    @staticmethod
    def create(chain: Keychain, features: OutputFeatures, child_key: ChildKey, amount: int):
        commit = chain.commit(amount, child_key)
        proof = create_proof(chain.secp, child_key.key, amount, commit, bytearray())
        return Output(features, commit, proof)


class Kernel:
    def __init__(self, features: int, fee: int, lock_height: int, excess: Optional[Commitment],
                 excess_signature: Optional[Signature]):
        self.features = features
        self.fee = fee
        self.lock_height = lock_height
        self.excess = excess
        self.excess_signature = excess_signature

    def to_bytearray(self, secp: Secp256k1) -> bytearray:
        data = bytearray()
        data.extend(bytearray(self.features.to_bytes(1, "big")))
        data.extend(bytearray(self.fee.to_bytes(8, "big")))
        data.extend(bytearray(self.lock_height.to_bytes(8, "big")))
        data.extend(
            bytearray([0] * PUBLIC_KEY_SIZE_COMPRESSED) if self.excess is None else self.excess.to_bytearray(secp)
        )
        data.extend(
            bytearray([0] * 64) if self.excess_signature is None else self.excess_signature.to_bytearray(secp, False)
        )
        return data

    def hash(self, secp: Secp256k1) -> bytes:
        return hasher(self.to_bytearray(secp))

    def to_dict(self, secp: Secp256k1, short=False) -> dict:
        excess = bytearray([0] * PUBLIC_KEY_SIZE_COMPRESSED) if self.excess is None else self.excess.to_bytearray(secp)
        excess_sig = bytearray([0] * 64) if self.excess_signature is None \
            else self.excess_signature.to_bytearray(secp, True)

        return {
            "features": self.features if short else {"bits": self.features},
            "fee": self.fee,
            "lock_height": self.lock_height,
            "excess": hexlify(excess).decode() if short else list(excess),
            "excess_sig": hexlify(excess_sig).decode() if short else list(excess_sig)
        }

    def verify(self, secp: Secp256k1) -> bool:
        return aggsig.verify(secp, self.excess_signature, self.excess.to_public_key(secp), self.fee, self.lock_height)

    @staticmethod
    def from_dict(secp: Secp256k1, dct: dict):
        return Kernel(
            dct['features']['bits'],
            dct['fee'],
            dct['lock_height'],
            None if sum(dct['excess']) == 0 else Commitment.from_bytearray(secp, bytearray(dct['excess'])),
            None if sum(dct['excess_sig']) == 0 else Signature.from_bytearray(secp, bytearray(dct['excess_sig']), True)
        )


class Transaction:
    def __init__(self, inputs: List[Input], outputs: List[Output], kernels: List[Kernel], offset: BlindingFactor):
        self.inputs = inputs
        self.outputs = outputs
        self.kernels = kernels
        self.offset = offset

    def to_dict(self, secp: Secp256k1, short=False) -> dict:
        return {
            "offset": self.offset.to_hex().decode() if short else list(self.offset.to_bytearray()),
            "body": {
                "inputs": [x.to_dict(secp, short) for x in self.inputs],
                "outputs": [x.to_dict(secp, short) for x in self.outputs],
                "kernels": [x.to_dict(secp, short) for x in self.kernels]
            }
        }

    def to_bytearray(self, secp: Secp256k1) -> bytearray:
        data = bytearray()
        data.extend(self.offset.to_bytearray())
        data.extend(bytearray(len(self.inputs).to_bytes(8, "big")))
        data.extend(bytearray(len(self.outputs).to_bytes(8, "big")))
        data.extend(bytearray(len(self.kernels).to_bytes(8, "big")))

        inputs = sort_by_hash(self.inputs, secp)
        for input in inputs:
            data.extend(input.to_bytearray(secp))
        outputs = sort_by_hash(self.outputs, secp)
        for output in outputs:
            data.extend(output.to_bytearray(secp))
        kernels = sort_by_hash(self.kernels, secp)
        for kernel in kernels:
            data.extend(kernel.to_bytearray(secp))
        return data

    def to_hex(self, secp: Secp256k1):
        return hexlify(self.to_bytearray(secp))

    def add_input(self, secp: Secp256k1, input: Input):
        self.inputs.append(input)
        self.inputs = sort_by_hash(self.inputs, secp)

    def add_output(self, secp: Secp256k1, output: Output):
        self.outputs.append(output)
        self.outputs = sort_by_hash(self.outputs, secp)

    def add_kernel(self, secp: Secp256k1, kernel: Kernel):
        self.kernels.append(kernel)
        self.kernels = sort_by_hash(self.kernels, secp)

    def sum_commitments(self, secp: Secp256k1) -> Commitment:
        overage = sum([x.fee for x in self.kernels])
        inputs = [x.commit for x in self.inputs]
        outputs = [x.commit for x in self.outputs]
        if overage > 0:
            outputs.append(secp.commit_value(overage))
        inputs.append(secp.commit(0, self.offset.to_secret_key(secp)))
        return secp.commit_sum(outputs, inputs)

    def verify_kernels(self, secp: Secp256k1) -> bool:
        for kernel in self.kernels:
            if not kernel.verify(secp):
                return False
        return True

    @staticmethod
    def empty(secp: Secp256k1, features: int, fee: int, lock_height: int):
        kernel = Kernel(features, fee, lock_height, None, None)
        return Transaction([], [], [kernel], BlindingFactor.from_secret_key(SecretKey.random(secp)))

    @staticmethod
    def from_dict(secp: Secp256k1, dct: dict):
        inputs = []
        for input in dct['body']['inputs']:
            inputs.append(Input.from_dict(secp, input))
        outputs = []
        for output in dct['body']['outputs']:
            outputs.append(Output.from_dict(secp, output))
        kernels = []
        for kernel in dct['body']['kernels']:
            kernels.append(Kernel.from_dict(secp, kernel))
        offset = BlindingFactor.from_bytearray(bytearray(dct['offset']))
        return Transaction(inputs, outputs, kernels, offset)

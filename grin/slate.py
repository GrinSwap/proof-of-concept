from typing import List, Optional
from grin.transaction import Transaction
from grin.util import UUID
import grin.aggsig as aggsig
from secp256k1.pedersen import Secp256k1
from secp256k1.key import SecretKey, PublicKey
from secp256k1.aggsig import Signature


class ParticipantData:
    def __init__(self, id: int, public_blind_excess: PublicKey, public_nonce: PublicKey,
                 partial_signature: Optional[Signature]):
        self.id = id
        self.public_blind_excess = public_blind_excess
        self.public_nonce = public_nonce
        self.partial_signature = partial_signature

    def to_dict(self, secp: Secp256k1, short=False) -> dict:
        return {
            "id": self.id,
            "public_blind_excess": self.public_blind_excess.to_hex(secp).decode() if short else
            list(self.public_blind_excess.to_bytearray(secp)),
            "public_nonce": self.public_nonce.to_hex(secp).decode() if short else
            list(self.public_nonce.to_bytearray(secp)),
            "part_sig": None if self.partial_signature is None else (
                self.partial_signature.to_hex().decode() if short else
                list(self.partial_signature.to_bytearray(secp, True))
            )
        }

    def is_complete(self) -> bool:
        return self.partial_signature is not None

    @staticmethod
    def from_dict(secp: Secp256k1, dct: dict):
        sig = dct['part_sig']
        return ParticipantData(
            dct['id'],
            PublicKey.from_bytearray(secp, bytearray(dct['public_blind_excess'])),
            PublicKey.from_bytearray(secp, bytearray(dct['public_nonce'])),
            None if sig is None else Signature.from_bytearray(secp, bytearray(sig), True)
        )


class InvalidSignatureException(Exception):
    pass


class Slate:
    def __init__(self, num_participants: int, id: UUID, tx: Transaction, amount: int, fee: int, height: int,
                 lock_height: int, participant_data: List[ParticipantData]):
        self.num_participants = num_participants
        self.id = id
        self.tx = tx
        self.amount = amount
        self.fee = fee
        self.height = height
        self.lock_height = lock_height
        self.participant_data = participant_data

    def to_dict(self, secp: Secp256k1, short=False) -> dict:
        return {
            "num_participants": self.num_participants,
            "id": str(self.id),
            "tx": self.tx.to_dict(secp, short),
            "amount": self.amount,
            "fee": self.fee,
            "height": self.height,
            "lock_height": self.lock_height,
            "participant_data": [x.to_dict(secp, short) for x in self.participant_data]
        }

    def add_participant(self, participant_data: ParticipantData):
        self.participant_data.append(participant_data)

    def get_participant(self, id: int) -> Optional[ParticipantData]:
        for participant in self.participant_data:
            if participant.id == id:
                return participant
        return None

    def public_blind_excess_sum(self, secp: Secp256k1) -> PublicKey:
        return PublicKey.from_combination(secp, [x.public_blind_excess for x in self.participant_data])

    def public_nonce_sum(self, secp: Secp256k1) -> PublicKey:
        return PublicKey.from_combination(secp, [x.public_nonce for x in self.participant_data])

    def partial_signature(self, secp: Secp256k1, participant: ParticipantData, secret_key: SecretKey,
                          secret_nonce: SecretKey):
        participant.partial_signature = aggsig.calculate_partial(
            secp, secret_key, secret_nonce, self.public_blind_excess_sum(secp), self.public_nonce_sum(secp),
            self.fee, self.lock_height
        )

    def verify_partial_signatures(self, secp: Secp256k1):
        for participant in self.participant_data:
            if participant.is_complete():
                res = aggsig.verify_partial(
                    secp,
                    participant.partial_signature,
                    self.public_nonce_sum(secp),
                    participant.public_blind_excess,
                    self.fee,
                    self.lock_height
                )
                if not res:
                    raise InvalidSignatureException()

    def finalize(self, secp: Secp256k1):
        signature = self.finalize_signature(secp)
        self.finalize_transaction(secp, signature)

    def finalize_signature(self, secp: Secp256k1) -> Signature:
        self.verify_partial_signatures(secp)
        partial_signatures = [x.partial_signature for x in self.participant_data]
        public_nonce_sum = self.public_nonce_sum(secp)
        public_key_sum = self.public_blind_excess_sum(secp)
        signature = aggsig.add_partials(secp, partial_signatures, public_nonce_sum)
        if not aggsig.verify(secp, signature, public_key_sum, self.fee, self.lock_height):
            raise InvalidSignatureException()

        return signature

    def finalize_transaction(self, secp: Secp256k1, signature: Signature):
        excess = self.tx.sum_commitments(secp)
        self.tx.kernels[0].excess = excess
        self.tx.kernels[0].excess_signature = signature
        if not self.tx.kernels[0].verify(secp):
            raise InvalidSignatureException()
        # TODO: verify all parts of tx

    @staticmethod
    def blank(secp: Secp256k1, num_participants: int, amount: int, height: int, features: int,
              fee: int, lock_height: int):
        slate = Slate(
            num_participants, UUID.random(), Transaction.empty(secp, features, fee, lock_height), amount,
            fee, height, lock_height, []
        )
        return slate

    @staticmethod
    def from_dict(secp: Secp256k1, dct: dict):
        return Slate(
            dct['num_participants'],
            UUID.from_str(dct['id']),
            Transaction.from_dict(secp, dct['tx']),
            dct['amount'],
            dct['fee'],
            dct['height'],
            dct['lock_height'],
            [ParticipantData.from_dict(secp, x) for x in dct['participant_data']]
        )

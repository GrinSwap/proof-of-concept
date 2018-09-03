from typing import List
from secp256k1 import Secp256k1, Message
from secp256k1.key import SecretKey, PublicKey, Signature
import secp256k1.aggsig as aggsig
from grin.util import kernel_sig_msg


def calculate_partial(secp: Secp256k1, excess: SecretKey, nonce: SecretKey, public_nonce_sum: PublicKey,
                      fee: int, lock_height: int) -> Signature:
    message = Message.from_bytearray(kernel_sig_msg(fee, lock_height))
    return aggsig.sign_single(secp, message, excess, nonce, public_nonce_sum, public_nonce_sum)


def verify_partial(secp: Secp256k1, signature: Signature, nonce_sum: PublicKey, public_excess: PublicKey,
                   fee: int, lock_height: int) -> bool:
    message = Message.from_bytearray(kernel_sig_msg(fee, lock_height))
    return aggsig.verify_single(secp, signature, message, nonce_sum, public_excess, True)


def add_partials(secp: Secp256k1, partials: List[Signature], nonce_sum: PublicKey) -> Signature:
    return aggsig.add_single(secp, partials, nonce_sum)


def verify(secp: Secp256k1, signature: Signature, public_key: PublicKey, fee: int, lock_height: int) -> bool:
    message = Message.from_bytearray(kernel_sig_msg(fee, lock_height))
    return aggsig.verify_single(secp, signature, message, None, public_key, False)


def calculate_partial_extra(secp: Secp256k1, excess: SecretKey, secret_nonce: SecretKey, extra: SecretKey,
                            public_nonce_sum: PublicKey, fee: int, lock_height: int) -> Signature:
    message = Message.from_bytearray(kernel_sig_msg(fee, lock_height))
    return aggsig.sign_single_extra(secp, message, excess, secret_nonce, extra, public_nonce_sum, public_nonce_sum)


def verify_partial_extra(secp: Secp256k1, signature: Signature, nonce_sum: PublicKey, public_excess: PublicKey,
                         extra_key: PublicKey, fee: int, lock_height: int) -> bool:
    message = Message.from_bytearray(kernel_sig_msg(fee, lock_height))
    return aggsig.verify_single_extra(secp, signature, message, nonce_sum, public_excess, extra_key, True)

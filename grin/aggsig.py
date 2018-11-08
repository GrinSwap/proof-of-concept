from typing import List
from secp256k1 import Secp256k1, Message
from secp256k1.key import SecretKey, PublicKey, Signature
import secp256k1.aggsig as aggsig
from grin.util import kernel_sig_msg


def calculate_partial(secp: Secp256k1, excess: SecretKey, nonce: SecretKey, public_excess_sum: PublicKey,
                      public_nonce_sum: PublicKey, fee: int, lock_height: int) -> Signature:
    message = Message.from_bytearray(kernel_sig_msg(fee, lock_height))
    return aggsig.sign_single(
        secp, message, excess, nonce, public_nonce_sum, public_excess_sum, public_nonce_sum, None
    )


def verify_partial(secp: Secp256k1, signature: Signature, public_excess: PublicKey, public_excess_sum: PublicKey,
                   public_nonce_sum: PublicKey, fee: int, lock_height: int) -> bool:
    message = Message.from_bytearray(kernel_sig_msg(fee, lock_height))
    return aggsig.verify_single(
        secp, signature, message, public_excess, public_excess_sum, public_nonce_sum, None, True
    )


def add_partials(secp: Secp256k1, partials: List[Signature], public_nonce_sum: PublicKey) -> Signature:
    return aggsig.add_single(secp, partials, public_nonce_sum)


def verify(secp: Secp256k1, signature: Signature, public_excess_sum: PublicKey, fee: int, lock_height: int) -> bool:
    message = Message.from_bytearray(kernel_sig_msg(fee, lock_height))
    return aggsig.verify_single(
        secp, signature, message, public_excess_sum, public_excess_sum, None, None, False
    )


def calculate_partial_adaptor(secp: Secp256k1, excess: SecretKey, nonce: SecretKey, extra: SecretKey,
                              public_excess_sum: PublicKey, public_nonce_sum: PublicKey, fee: int,
                              lock_height: int) -> Signature:
    message = Message.from_bytearray(kernel_sig_msg(fee, lock_height))
    return aggsig.sign_single(
        secp, message, excess, nonce, public_nonce_sum, public_excess_sum, public_nonce_sum, extra
    )


def verify_partial_adaptor(secp: Secp256k1, signature: Signature, public_excess: PublicKey, extra: PublicKey,
                           public_excess_sum: PublicKey, public_nonce_sum: PublicKey, fee: int,
                           lock_height: int) -> bool:
    message = Message.from_bytearray(kernel_sig_msg(fee, lock_height))
    return aggsig.verify_single(
        secp, signature, message, public_excess, public_excess_sum, public_nonce_sum, extra, True
    )

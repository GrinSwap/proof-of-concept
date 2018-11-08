from os import urandom
from typing import List, Optional
from secp256k1 import Secp256k1, Message
from secp256k1.key import SecretKey, PublicKey, Signature
from ._libsecp256k1 import ffi, lib


def sign_single(secp: Secp256k1, message: Message, secret_key: SecretKey, secret_nonce: Optional[SecretKey],
                public_nonce: Optional[PublicKey], public_key_sum: Optional[PublicKey],
                public_nonce_sum: Optional[PublicKey], extra_secret_key: Optional[SecretKey]) -> Signature:
    signature_out = ffi.new("char [64]")
    res = lib.secp256k1_aggsig_sign_single(
        secp.ctx, signature_out, bytes(message.message), bytes(secret_key.key), ffi.NULL if secret_nonce is None
        else bytes(secret_nonce.key), ffi.NULL if extra_secret_key is None else bytes(extra_secret_key.key),
        ffi.NULL if public_nonce is None else public_nonce.key, ffi.NULL if public_nonce_sum is None
        else public_nonce_sum.key, ffi.NULL if public_key_sum is None else public_key_sum.key, urandom(32)
    )
    assert res, "Unable to sign message"
    return Signature.from_bytearray(secp, bytearray(ffi.buffer(signature_out, 64)))


def verify_single(secp: Secp256k1, signature: Signature, message: Message, public_key: PublicKey,
                  public_key_sum: Optional[PublicKey], public_nonce_sum: Optional[PublicKey],
                  extra_public_key: Optional[PublicKey], partial=True) -> bool:
    res = lib.secp256k1_aggsig_verify_single(
        secp.ctx, bytes(signature.signature), bytes(message.message), ffi.NULL if public_nonce_sum is None
        else public_nonce_sum.key, public_key.key, ffi.NULL if public_key_sum is None else public_key_sum.key,
        ffi.NULL if extra_public_key is None else extra_public_key.key, 1 if partial else 0
    )
    return True if res else False


def add_single(secp: Secp256k1, signatures: List[Signature], public_nonce_sum: PublicKey) -> Signature:
    signature_out = ffi.new("char [64]")
    signature_ptrs = []
    for signature in signatures:
        signature_ptr = ffi.new("char []", bytes(signature.signature))
        signature_ptrs.append(signature_ptr)

    res = lib.secp256k1_aggsig_add_signatures_single(
        secp.ctx, signature_out, signature_ptrs, len(signatures), public_nonce_sum.key
    )
    assert res, "Unable to add signatures"
    return Signature.from_bytearray(secp, bytearray(ffi.buffer(signature_out, 64)))

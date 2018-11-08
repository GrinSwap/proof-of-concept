from os import urandom
from random import randint
from secp256k1 import FLAG_ALL
from secp256k1.key import SecretKey, PublicKey, Signature
from secp256k1.pedersen import Secp256k1
from grin import aggsig


def test_partial_sig():
    secp = Secp256k1(None, FLAG_ALL)
    excess = SecretKey.random(secp)
    public_excess = excess.to_public_key(secp)
    nonce = SecretKey.random(secp)
    public_key_sum = SecretKey.random(secp).to_public_key(secp)
    public_nonce_sum = SecretKey.random(secp).to_public_key(secp)
    fee = randint(1, 999999)
    lock_height = randint(1, 999999)
    sig = aggsig.calculate_partial(secp, excess, nonce, public_key_sum, public_nonce_sum, fee, lock_height)

    assert aggsig.verify_partial(secp, sig, public_excess, public_key_sum, public_nonce_sum, fee, lock_height)
    rnd_sig = Signature(bytearray(urandom(64)))
    assert not aggsig.verify_partial(secp, rnd_sig, public_excess, public_key_sum, public_nonce_sum, fee, lock_height)
    public_rnd = SecretKey.random(secp).to_public_key(secp)
    assert not aggsig.verify_partial(secp, sig, public_rnd, public_key_sum, public_nonce_sum, fee, lock_height)
    assert not aggsig.verify_partial(secp, sig, public_excess, public_rnd, public_nonce_sum, fee, lock_height)
    assert not aggsig.verify_partial(secp, sig, public_excess, public_key_sum, public_rnd, fee, lock_height)
    assert not aggsig.verify_partial(secp, sig, public_excess, public_key_sum, public_nonce_sum, 0, lock_height)
    assert not aggsig.verify_partial(secp, sig, public_excess, public_key_sum, public_nonce_sum, fee, 0)


def test_sig():
    # Test Grin-like signature scheme
    secp = Secp256k1(None, FLAG_ALL)
    nonce_a = SecretKey.random(secp)
    public_nonce_a = nonce_a.to_public_key(secp)
    nonce_b = SecretKey.random(secp)
    public_nonce_b = nonce_b.to_public_key(secp)
    public_nonce_sum = PublicKey.from_combination(secp, [public_nonce_a, public_nonce_b])
    excess_a = SecretKey.random(secp)
    public_excess_a = excess_a.to_public_key(secp)
    excess_b = SecretKey.random(secp)
    public_excess_b = excess_b.to_public_key(secp)
    public_excess_sum = PublicKey.from_combination(secp, [public_excess_a, public_excess_b])
    fee = randint(1, 999999)
    lock_height = randint(1, 999999)

    # Partial signature for A
    sig_a = aggsig.calculate_partial(secp, excess_a, nonce_a, public_excess_sum, public_nonce_sum, fee, lock_height)
    assert aggsig.verify_partial(secp, sig_a, public_excess_a, public_excess_sum, public_nonce_sum, fee, lock_height)

    # Partial signature for B
    sig_b = aggsig.calculate_partial(secp, excess_b, nonce_b, public_excess_sum, public_nonce_sum, fee, lock_height)
    assert aggsig.verify_partial(secp, sig_b, public_excess_b, public_excess_sum, public_nonce_sum, fee, lock_height)

    # Total signature
    sig = aggsig.add_partials(secp, [sig_a, sig_b], public_nonce_sum)
    assert aggsig.verify(secp, sig, public_excess_sum, fee, lock_height)
    rnd_sig = Signature(bytearray(urandom(64)))
    assert not aggsig.verify(secp, rnd_sig, public_excess_sum, fee, lock_height)
    public_rnd = SecretKey.random(secp).to_public_key(secp)
    assert not aggsig.verify(secp, sig, public_rnd, fee, lock_height)
    assert not aggsig.verify(secp, sig, public_excess_sum, 0, lock_height)
    assert not aggsig.verify(secp, sig, public_excess_sum, fee, 0)

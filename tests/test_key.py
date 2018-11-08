from pytest import raises
from secp256k1 import Secp256k1, FLAG_ALL, SECRET_KEY_SIZE
from secp256k1.key import SecretKey, PublicKey


def test_secret_key():
    secp = Secp256k1(None, FLAG_ALL)

    # (de)serialization
    key_a = SecretKey.random(secp)
    key_b = SecretKey.from_bytearray(secp, key_a.to_bytearray())
    assert key_a == key_b

    # Too short
    with raises(Exception):
        SecretKey.from_bytearray(secp, bytearray([0x01] * (SECRET_KEY_SIZE-1)))

    # Too long
    with raises(Exception):
        SecretKey.from_bytearray(secp, bytearray([0x01] * (SECRET_KEY_SIZE+1)))

    # Zero
    with raises(Exception):
        SecretKey.from_bytearray(secp, bytearray([0] * SECRET_KEY_SIZE))

    # Overflow
    with raises(Exception):
        SecretKey.from_bytearray(secp, bytearray([0xFF] * SECRET_KEY_SIZE))

    # Top of range
    SecretKey.from_bytearray(secp, bytearray([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                              0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                              0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40]))

    # One past top of range
    with raises(Exception):
        SecretKey.from_bytearray(secp, bytearray([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                                  0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                                  0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41]))

    # a=a
    key_a = SecretKey.from_bytearray(secp, bytearray([0xCB] * SECRET_KEY_SIZE))
    key_b = SecretKey.from_bytearray(secp, bytearray([0xCB] * SECRET_KEY_SIZE))
    assert key_a == key_b

    # a!=b
    key_b = SecretKey.from_bytearray(secp, bytearray([0xCC] * SECRET_KEY_SIZE))
    assert key_a != key_b

    # a+b
    key_a = SecretKey.from_bytearray(secp, bytearray([0xDD] * SECRET_KEY_SIZE))
    key_b = SecretKey.from_bytearray(secp, bytearray([0x02] * SECRET_KEY_SIZE))
    key_a.add_assign(secp, key_b)
    key_c = SecretKey.from_bytearray(secp, bytearray([0xDF] * SECRET_KEY_SIZE))
    assert key_a == key_c

    # a+b = b+a
    key_a = SecretKey.random(secp)
    key_b = SecretKey.random(secp)
    key_a_b = key_a.add(secp, key_b)
    key_b_a = key_b.add(secp, key_a)
    assert key_a_b == key_b_a

    # Key addition where sum > order (N-1+N-2=N-3)
    key_a = SecretKey.from_bytearray(secp, bytearray([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                                      0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                                      0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40]))
    key_b = SecretKey.from_bytearray(secp, bytearray([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                                      0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                                      0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x3F]))
    key_a.add_assign(secp, key_b)
    key_c = SecretKey.from_bytearray(secp, bytearray([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                                      0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                                      0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x3E]))
    assert key_a == key_c

    # ab = ba
    key_a = SecretKey.random(secp)
    key_b = SecretKey.random(secp)
    key_ab = key_a.mul(secp, key_b)
    key_ba = key_b.mul(secp, key_a)
    assert key_ab == key_ba

    # c(a+b) = ca + cb
    key_a = SecretKey.random(secp)
    key_b = SecretKey.random(secp)
    key_c = SecretKey.random(secp)
    key_ca = key_a.mul(secp, key_c)
    key_cb = key_b.mul(secp, key_c)
    key_ca_b = key_a.add(secp, key_b)
    key_ca_b.mul_assign(secp, key_c)
    key_ca_cb = key_ca.add(secp, key_cb)
    assert key_ca_b == key_ca_cb


def test_public_key():
    secp = Secp256k1(None, FLAG_ALL)

    # (de)serialization
    secret_key = SecretKey.random(secp)
    public_key = secret_key.to_public_key(secp)
    public_key_2 = PublicKey.from_bytearray(secp, public_key.to_bytearray(secp))
    assert public_key == public_key_2

    # (a+b)*G = a*G + b*G
    secret_key_a = SecretKey.random(secp)
    secret_key_b = SecretKey.random(secp)
    secret_key_a_b = secret_key_a.add(secp, secret_key_b)
    public_key_a = secret_key_a.to_public_key(secp)
    public_key_b = secret_key_b.to_public_key(secp)
    public_key_a_b = secret_key_a_b.to_public_key(secp)
    public_key_a_b_2 = PublicKey.from_combination(secp, [public_key_a, public_key_b])
    public_key_a_b_3 = public_key_a.add_scalar(secp, secret_key_b)
    assert public_key_a_b == public_key_a_b_2
    assert public_key_a_b == public_key_a_b_3

    # (ab)*G = a(b*G) = b(a*G)
    secret_key_a = SecretKey.random(secp)
    secret_key_b = SecretKey.random(secp)
    secret_key_ab = secret_key_a.mul(secp, secret_key_b)
    public_key_ab = secret_key_ab.to_public_key(secp)
    public_key_ab_2 = secret_key_a.to_public_key(secp)
    public_key_ab_2.mul_assign(secp, secret_key_b)
    public_key_ab_3 = secret_key_b.to_public_key(secp)
    public_key_ab_3.mul_assign(secp, secret_key_a)
    assert public_key_ab == public_key_ab_2
    assert public_key_ab == public_key_ab_3

    # (c(a+b))*G = c(a*G) + c(b*G)
    secret_key_a = SecretKey.random(secp)
    secret_key_b = SecretKey.random(secp)
    secret_key_c = SecretKey.random(secp)
    secret_key_ca_b = secret_key_a.add(secp, secret_key_b)
    secret_key_ca_b.mul_assign(secp, secret_key_c)
    public_key_ca_b = secret_key_ca_b.to_public_key(secp)
    public_key_ca = secret_key_a.to_public_key(secp)
    public_key_ca.mul_assign(secp, secret_key_c)
    public_key_cb = secret_key_b.to_public_key(secp)
    public_key_cb.mul_assign(secp, secret_key_c)
    public_key_ca_cb = public_key_ca.add(secp, public_key_cb)
    assert public_key_ca_b == public_key_ca_cb

    # (a+b+c)*G = a*G + b*G + c*G
    secret_key_a = SecretKey.random(secp)
    secret_key_b = SecretKey.random(secp)
    secret_key_c = SecretKey.random(secp)
    secret_key_a_b_c = secret_key_a.add(secp, secret_key_b)
    secret_key_a_b_c.add_assign(secp, secret_key_c)
    public_key_a_b_c = secret_key_a_b_c.to_public_key(secp)
    public_key_a = secret_key_a.to_public_key(secp)
    public_key_b = secret_key_b.to_public_key(secp)
    public_key_c = secret_key_c.to_public_key(secp)
    public_key_a_b_c_2 = PublicKey.from_combination(secp, [public_key_a, public_key_b, public_key_c])
    assert public_key_a_b_c == public_key_a_b_c_2


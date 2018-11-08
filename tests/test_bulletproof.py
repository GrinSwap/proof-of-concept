import json
from random import randint
from secp256k1 import FLAG_ALL
from secp256k1.key import SecretKey
from secp256k1.pedersen import Secp256k1, RangeProof
from grin.keychain import ChildKey, Identifier
from grin.proof import MultiPartyBulletProof, TwoPartyBulletProof


def test_proofs(create=False):
    secp = Secp256k1(None, FLAG_ALL)

    if create:
        dct = []
        for i in range(100):
            secret = SecretKey.random(secp)
            nonce = SecretKey.random(secp)
            amount = randint(1, 10000000000)
            proof = secp.bullet_proof(amount, secret, nonce, bytearray())
            dct.append({
                "secret": secret.to_hex().decode(),
                "nonce": nonce.to_hex().decode(),
                "amount": amount,
                "proof": proof.to_hex().decode()
            })
        f = open("proofs_new.json", "w")
        f.write(json.dumps(dct, indent=2))
        f.close()
        return

    f = open("tests/proofs.json", "r")
    dct = json.loads(f.read())
    f.close()

    test_count = 0
    test_equal_count = 0
    for test in dct:
        test_count += 1
        secret = SecretKey.from_hex(secp, test['secret'].encode())
        nonce = SecretKey.from_hex(secp, test['nonce'].encode())
        amount = test['amount']
        proof_target = RangeProof.from_hex(test['proof'].encode())
        proof = secp.bullet_proof(amount, secret, nonce, bytearray())
        commit = secp.commit(amount, secret)
        assert secp.verify_bullet_proof(commit, proof, bytearray()), "Proof {} fails to verify".format(test_count)
        if proof == proof_target:
            test_equal_count += 1

    assert test_count == test_equal_count, \
        "All proofs verify, but only {} out of {} proofs are the same".format(test_equal_count, test_count)


def multi_party_proof(n):
    assert n > 1
    secp = Secp256k1(None, FLAG_ALL)
    mpps = []
    child_keys = []
    amount = randint(1, 999999)
    commit_sum = [secp.commit_value(amount)]
    common_nonce = SecretKey.random(secp)
    for i in range(n):
        child_keys.append(ChildKey(i, Identifier.random(), Identifier.random(), SecretKey.random(secp)))
        child_key = child_keys[i]
        commit_sum.append(secp.commit(0, child_key.key))
    # Total commitment: sum xi*G + v*H
    commitment = secp.commit_sum(commit_sum, [])
    t_1s = []
    t_2s = []
    # Each party exports their T1 and T2
    for i in range(n):
        mpps.append(MultiPartyBulletProof(secp, child_keys[i], amount, commitment, common_nonce))
        t_1, t_2 = mpps[i].round_1()
        t_1s.append(t_1)
        t_2s.append(t_2)
    # Each party receives the other T1 and T2 values and adds it to their own
    for i in range(n):
        for j in range(n):
            if i != j:
                mpps[i].fill_round_1(t_1s[j], t_2s[j])
    tau_xs = []
    # Each party exports their tau_x
    for i in range(n):
        tau_xs.append(mpps[i].round_2())
    # One party receives the other tau_x values and adds it to their own
    # In this test we simulate each party calculating the proof
    for i in range(n):
        for j in range(n):
            if i != j:
                mpps[i].fill_round_2(tau_xs[j])
    proofs = []
    for i in range(n):
        proofs.append(mpps[i].finalize())
        assert secp.verify_bullet_proof(commitment, proofs[i], bytearray())
    for i in range(n-1):
        assert proofs[i+1] == proofs[0]


def test_multi_party_proofs():
    for i in range(2, 9):
        multi_party_proof(i)


def test_two_party_proof():
    secp = Secp256k1(None, FLAG_ALL)
    secret_key_a = SecretKey.random(secp)
    public_key_a = secret_key_a.to_public_key(secp)
    child_key_a = ChildKey(0, Identifier.random(), Identifier.random(), secret_key_a)
    secret_key_b = SecretKey.random(secp)
    public_key_b = secret_key_b.to_public_key(secp)
    child_key_b = ChildKey(0, Identifier.random(), Identifier.random(), secret_key_b)
    amount = randint(1, 999999)
    commit = secp.commit_sum([secp.commit(amount, secret_key_a), secp.commit(0, secret_key_b)], [])
    tpp_a = TwoPartyBulletProof(secp, child_key_a, public_key_b, amount, commit)
    tpp_b = TwoPartyBulletProof(secp, child_key_b, public_key_a, amount, commit)
    t_1_a, t_2_a = tpp_a.round_1()
    t_1_b, t_2_b = tpp_b.round_1()
    tpp_a.fill_round_1(t_1_b, t_2_b)
    tpp_b.fill_round_1(t_1_a, t_2_a)
    tau_x_a = tpp_a.round_2()
    tau_x_b = tpp_b.round_2()
    tpp_a.fill_round_2(tau_x_b)
    tpp_b.fill_round_2(tau_x_a)
    proof_a = tpp_a.finalize()
    assert secp.verify_bullet_proof(commit, proof_a, bytearray())
    proof_b = tpp_b.finalize()
    assert proof_a == proof_b

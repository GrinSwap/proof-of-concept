from binascii import hexlify, unhexlify
from http.server import HTTPServer
import json
from time import time
from urllib.request import urlopen
from secp256k1 import FLAG_ALL
from secp256k1.key import PublicKey, Signature
from secp256k1.pedersen import Secp256k1, Commitment, RangeProof
import grin.aggsig as aggsig
from grin.keychain import BlindSum, SecretKey
from grin.proof import MultiPartyBulletProof
from grin.transaction import tx_fee, Transaction, Input, Output, OutputFeatures
from grin.util import MILLI_GRIN_UNIT, GRIN_UNIT, HTTPServerHandler, set_callback_post
from grin.wallet import Wallet

secp = None
wallet = None
server = None
proof_builder = None


def send(node_url: str):
    global secp, wallet, proof_builder

    now = int(time())

    send_amount = GRIN_UNIT
    lock_height = 1
    refund_lock_height = lock_height + 1440  # ~24 hours
    dest_url = "http://127.0.0.1:18185"
    fluff = True

    secp = Secp256k1(None, FLAG_ALL)
    wallet = Wallet.open(secp, "wallet_a")

    print("Preparing to create multisig with {}".format(dest_url))

    input_entries = wallet.select_outputs(send_amount + tx_fee(1, 2, MILLI_GRIN_UNIT))
    fee_amount = tx_fee(len(input_entries), 2, MILLI_GRIN_UNIT)
    input_amount = sum(x.value for x in input_entries)
    change_amount = input_amount - send_amount - fee_amount
    refund_fee_amount = tx_fee(1, 1, MILLI_GRIN_UNIT)

    print("Selected {} inputs".format(len(input_entries)))

    tx = Transaction.empty(secp, 0, fee_amount, lock_height)
    refund_tx = Transaction.empty(secp, 0, refund_fee_amount, refund_lock_height)

    blind_sum = BlindSum()

    # Inputs
    inputs = []
    for entry in input_entries:
        entry.mark_locked()
        blind_sum.sub_child_key(wallet.derive_from_entry(entry))
        input = wallet.entry_to_input(entry)
        tx.add_input(secp, input)
        inputs.append(input)

    # Change output
    change_child, change_entry = wallet.create_output(change_amount)
    blind_sum.add_child_key(change_child)
    change_output = wallet.entry_to_output(change_entry)
    tx.add_output(secp, change_output)

    # Multisig output
    partial_child, partial_entry = wallet.create_output(send_amount)
    partial_entry.mark_locked()
    blind_sum.add_child_key(partial_child)
    public_partial_commit = wallet.commit_with_child_key(0, partial_child)

    # Refund output
    refund_amount = send_amount-refund_fee_amount
    refund_child, refund_entry = wallet.create_output(refund_amount)
    refund_output = wallet.entry_to_output(refund_entry)
    refund_tx.add_output(secp, refund_output)

    # Offset
    blind_sum.sub_blinding_factor(tx.offset)

    # Excess
    excess = wallet.chain.blind_sum(blind_sum).to_secret_key(secp)
    public_excess = excess.to_public_key(secp)

    # Nonce
    nonce = SecretKey.random(secp)
    public_nonce = nonce.to_public_key(secp)

    # Refund nonce
    refund_nonce = SecretKey.random(secp)
    refund_public_nonce = refund_nonce.to_public_key(secp)

    dct = {
        "amount": send_amount,
        "fee": fee_amount,
        "refund_fee": refund_fee_amount,
        "lock_height": lock_height,
        "refund_lock_height": refund_lock_height,
        "public_partial_commit": public_partial_commit.to_hex(secp).decode(),
        "public_nonce": public_nonce.to_hex(secp).decode(),
        "refund_public_nonce": refund_public_nonce.to_hex(secp).decode()
    }

    f = open("logs/{}_multisig_1.json".format(now), "w")
    f.write(json.dumps(dct, indent=2))
    f.close()

    print("Sending to receiver..")

    req = urlopen(dest_url, json.dumps(dct).encode(), 60)
    dct2 = json.loads(req.read().decode())

    f = open("logs/{}_multisig_2.json".format(now), "w")
    f.write(json.dumps(dct2, indent=2))
    f.close()

    print("Received response, processing..")

    public_partial_commit_recv = Commitment.from_hex(secp, dct2['public_partial_commit'].encode())
    public_partial_recv = public_partial_commit_recv.to_public_key(secp)
    public_nonce_recv = PublicKey.from_hex(secp, dct2['public_nonce'].encode())
    public_excess_recv = public_partial_commit_recv.to_public_key(secp)
    partial_signature_recv = Signature.from_hex(dct2['partial_signature'].encode())
    refund_public_nonce_recv = PublicKey.from_hex(secp, dct2['refund_public_nonce'].encode())
    refund_public_excess_recv = PublicKey.from_hex(secp, dct2['refund_public_excess'].encode())
    refund_partial_signature_recv = Signature.from_hex(dct2['refund_partial_signature'].encode())

    # Commitment
    commit = secp.commit_sum([public_partial_commit_recv, wallet.commit(partial_entry)], [])
    print("Total commit: {}".format(commit))

    # Nonce sums
    public_nonce_sum = PublicKey.from_combination(secp, [public_nonce_recv, public_nonce])
    refund_public_nonce_sum = PublicKey.from_combination(secp, [refund_public_nonce_recv, refund_public_nonce])

    # Step 2 of bulletproof
    proof_builder = MultiPartyBulletProof(secp, partial_child, public_partial_recv, send_amount, commit)
    t_1_recv = PublicKey.from_hex(secp, dct2['t_1'].encode())
    t_2_recv = PublicKey.from_hex(secp, dct2['t_2'].encode())
    t_1, t_2 = proof_builder.step_1()
    proof_builder.fill_step_1(t_1_recv, t_2_recv)
    tau_x = proof_builder.step_2()

    dct3 = {
        "t_1": t_1.to_hex(secp).decode(),
        "t_2": t_2.to_hex(secp).decode(),
        "tau_x": tau_x.to_hex().decode()
    }

    f = open("logs/{}_multisig_3.json".format(now), "w")
    f.write(json.dumps(dct3, indent=2))
    f.close()

    print("Sending bulletproof component..")

    req2 = urlopen(dest_url, json.dumps(dct3).encode(), 60)
    dct4 = json.loads(req2.read().decode())

    print("Received response")

    f = open("logs/{}_multisig_4.json".format(now), "w")
    f.write(json.dumps(dct4, indent=2))
    f.close()

    # Bulletproof
    proof = RangeProof.from_bytearray(bytearray(unhexlify(dct4['proof'].encode())))
    output = Output(OutputFeatures.DEFAULT_OUTPUT, commit, proof)
    assert output.verify(secp), "Invalid bulletproof"
    tx.add_output(secp, output)
    print("Created bulletproof")

    # First we finalize the refund tx, and check its validity
    refund_input = Input(OutputFeatures.DEFAULT_OUTPUT, commit)
    refund_tx.add_input(secp, refund_input)

    # Refund excess
    refund_blind_sum = BlindSum()
    refund_blind_sum.sub_child_key(partial_child)
    refund_blind_sum.add_child_key(refund_child)
    refund_blind_sum.sub_blinding_factor(refund_tx.offset)
    refund_excess = wallet.chain.blind_sum(refund_blind_sum).to_secret_key(secp)
    refund_public_excess = refund_excess.to_public_key(secp)

    # Refund partial signature
    refund_partial_signature = aggsig.calculate_partial(
        secp, refund_excess, refund_nonce, refund_public_nonce_sum, refund_fee_amount, refund_lock_height
    )

    # Refund final signature
    refund_public_excess_sum = PublicKey.from_combination(secp, [refund_public_excess_recv, refund_public_excess])
    refund_signature = aggsig.add_partials(secp, [refund_partial_signature_recv, refund_partial_signature],
                                           refund_public_nonce_sum)
    assert aggsig.verify(secp, refund_signature, refund_public_excess_sum, refund_fee_amount, refund_lock_height), \
        "Unable to verify refund signature"
    refund_kernel = refund_tx.kernels[0]
    refund_kernel.excess = refund_tx.sum_commitments(secp)
    refund_kernel.excess_signature = refund_signature
    assert refund_tx.verify_kernels(secp), "Unable to verify refund kernel"

    print("Refund tx is valid")

    f = open("logs/{}_refund.json".format(now), "w")
    f.write(json.dumps(refund_tx.to_dict(secp), indent=2))
    f.close()

    refund_tx_wrapper = {
        "tx_hex": refund_tx.to_hex(secp).decode()
    }

    f = open("logs/{}_refund_hex.json".format(now), "w")
    f.write(json.dumps(refund_tx_wrapper, indent=2))
    f.close()

    print("Finalizing multisig tx..")

    # Partial signature
    partial_signature = aggsig.calculate_partial(secp, excess, nonce, public_nonce_sum, fee_amount, lock_height)

    # Final signature
    public_excess_sum = PublicKey.from_combination(secp, [public_excess_recv, public_excess])
    signature = aggsig.add_partials(secp, [partial_signature_recv, partial_signature], public_nonce_sum)
    assert aggsig.verify(secp, signature, public_excess_sum, fee_amount, lock_height), "Unable to verify signature"
    kernel = tx.kernels[0]
    kernel.excess = tx.sum_commitments(secp)
    kernel.excess_signature = signature
    assert tx.verify_kernels(secp), "Unable to verify kernel"

    f = open("logs/{}_tx.json".format(now), "w")
    f.write(json.dumps(tx.to_dict(secp), indent=2))
    f.close()

    tx_wrapper = {
        "tx_hex": tx.to_hex(secp).decode()
    }

    f = open("logs/{}_tx_hex.json".format(now), "w")
    f.write(json.dumps(tx_wrapper, indent=2))
    f.close()

    print("Submitting to node..")

    urlopen("{}/v1/pool/push".format(node_url) + ("?fluff" if fluff else ""), json.dumps(tx_wrapper).encode(), 600)

    wallet.save()

    print("Transaction complete!")


def post(handler: HTTPServerHandler):
    global secp, wallet, server, proof_builder

    if secp is None:
        secp = Secp256k1(None, FLAG_ALL)
        wallet = Wallet.open(secp, "wallet_b")

    try:
        length = handler.headers['Content-Length']
        length = 0 if length is None else int(length)
        if length == 0:
            raise Exception("Invalid length")
        dct = json.loads(handler.rfile.read(length).decode())

        if proof_builder is not None:
            print("Creating bulletproof components")

            t_1_sender = PublicKey.from_hex(secp, dct['t_1'].encode())
            t_2_sender = PublicKey.from_hex(secp, dct['t_2'].encode())
            proof_builder.fill_step_1(t_1_sender, t_2_sender)
            tau_x_sender = SecretKey.from_hex(secp, dct['tau_x'].encode())
            proof_builder.fill_step_2(tau_x_sender)
            proof = proof_builder.finalize()

            wallet.save()

            dct2 = {
                "proof": hexlify(bytes(proof.proof)).decode()
            }

            handler.json_response((json.dumps(dct2) + "\r\n").encode())

            print("Sent response")

            return

        send_amount = dct['amount']
        fee_amount = dct['fee']
        refund_fee_amount = dct['refund_fee']
        lock_height = dct['lock_height']
        refund_lock_height = dct['refund_lock_height']

        print("Receive {} grin in multisig".format(send_amount / GRIN_UNIT))

        public_partial_commit_sender = Commitment.from_hex(secp, dct['public_partial_commit'].encode())
        public_partial_sender = public_partial_commit_sender.to_public_key(secp)
        public_nonce_sender = PublicKey.from_hex(secp, dct['public_nonce'].encode())
        refund_public_nonce_sender = PublicKey.from_hex(secp, dct['refund_public_nonce'].encode())

        # Multisig output
        partial_child, partial_entry = wallet.create_output(send_amount)
        partial_entry.mark_locked()
        public_partial_commit = wallet.commit_with_child_key(0, partial_child)

        # Commitment
        commit = secp.commit_sum([public_partial_commit_sender, wallet.commit(partial_entry)], [])
        print("Total commit: {}".format(commit))

        # Nonce
        nonce = SecretKey.random(secp)
        public_nonce = nonce.to_public_key(secp)
        public_nonce_sum = PublicKey.from_combination(secp, [public_nonce_sender, public_nonce])

        # Refund excess
        refund_blind_sum = BlindSum()
        refund_blind_sum.sub_child_key(partial_child)
        refund_excess = wallet.chain.blind_sum(refund_blind_sum).to_secret_key(secp)
        refund_public_excess = refund_excess.to_public_key(secp)

        # Refund nonce
        refund_nonce = SecretKey.random(secp)
        refund_public_nonce = refund_nonce.to_public_key(secp)
        refund_public_nonce_sum = PublicKey.from_combination(secp, [refund_public_nonce_sender, refund_public_nonce])

        # Start building the bulletproof for the multisig output
        proof_builder = MultiPartyBulletProof(secp, partial_child, public_partial_sender, send_amount, commit)
        t_1, t_2 = proof_builder.step_1()

        # Partial signature
        partial_signature = aggsig.calculate_partial(
            secp, partial_child.key, nonce, public_nonce_sum, fee_amount, lock_height
        )

        # Refund partial signature
        refund_partial_signature = aggsig.calculate_partial(
            secp, refund_excess, refund_nonce, refund_public_nonce_sum, refund_fee_amount, refund_lock_height
        )

        dct2 = {
            "public_partial_commit": public_partial_commit.to_hex(secp).decode(),
            "refund_public_excess": refund_public_excess.to_hex(secp).decode(),
            "public_nonce": public_nonce.to_hex(secp).decode(),
            "refund_public_nonce": refund_public_nonce.to_hex(secp).decode(),
            "partial_signature": partial_signature.to_hex().decode(),
            "refund_partial_signature": refund_partial_signature.to_hex().decode(),
            "t_1": t_1.to_hex(secp).decode(),
            "t_2": t_2.to_hex(secp).decode()
        }

        handler.json_response((json.dumps(dct2) + "\r\n").encode())

        print("Sent response")

    except Exception as e:
        print("Unable to parse input: {}".format(e))
        handler.error_response()


def receive():
    global secp, wallet, server
    secp = Secp256k1(None, FLAG_ALL)
    wallet = Wallet.open(secp, "wallet_2")

    set_callback_post(post)

    print("Listening on port 18185..")
    server = HTTPServer(("", 18185), HTTPServerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.socket.close()

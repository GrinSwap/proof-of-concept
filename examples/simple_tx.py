import json
from urllib.request import urlopen
from http.server import HTTPServer
from secp256k1 import FLAG_ALL
from secp256k1.pedersen import Secp256k1
from secp256k1.key import SecretKey
from grin.transaction import tx_fee
from grin.wallet import Wallet
from grin.keychain import BlindSum
from grin.slate import Slate, ParticipantData
from grin.util import MILLI_GRIN_UNIT, GRIN_UNIT, HTTPServerHandler, set_callback_post

secp = None
wallet = None
server = None


def send(node_url: str):
    global secp, wallet
    send_amount = 1
    height = 33333
    lock_height = 33333
    features = 0
    dest_url = "http://127.0.0.1:17175"
    fluff = True
    n_outputs = 2

    secp = Secp256k1(None, FLAG_ALL)

    wallet = Wallet.open(secp, "wallet_1")

    print("Preparing to send {} grin to {}".format(send_amount / GRIN_UNIT, dest_url))

    input_entries = wallet.select_outputs(send_amount + tx_fee(1, n_outputs, MILLI_GRIN_UNIT))
    fee_amount = tx_fee(len(input_entries), n_outputs, MILLI_GRIN_UNIT)
    input_amount = sum(x.value for x in input_entries)
    change_amount = input_amount - send_amount - fee_amount

    print("Selected {} inputs".format(len(input_entries)))

    blind_sum = BlindSum()

    slate = Slate.blank(secp, 2, send_amount, height, features, fee_amount, lock_height)

    # Inputs
    for entry in input_entries:
        entry.mark_locked()
        blind_sum.sub_child_key(wallet.derive_from_entry(entry))
        slate.tx.add_input(secp, wallet.entry_to_input(entry))

    # Change output
    change_key, change_entry = wallet.create_output(change_amount)
    blind_sum.add_child_key(change_key)
    slate.tx.add_output(secp, wallet.entry_to_output(change_entry))

    # Excess
    blind_sum.sub_blinding_factor(slate.tx.offset)
    excess = wallet.chain.blind_sum(blind_sum).to_secret_key(secp)
    public_excess = excess.to_public_key(secp)

    # Nonce
    nonce = SecretKey.random(secp)
    public_nonce = nonce.to_public_key(secp)

    # Participant
    participant = ParticipantData(0, public_excess, public_nonce, None)
    slate.add_participant(participant)

    print("Sending slate to receiver..")

    req = urlopen(dest_url, json.dumps(slate.to_dict(secp)).encode(), 600)
    slate = Slate.from_dict(secp, json.loads(req.read().decode()))

    print("Received response, finishing transaction..")

    participant = slate.get_participant(0)
    slate.partial_signature(secp, participant, excess, nonce)
    slate.finalize(secp)

    tx_wrapper = {
        "tx_hex": slate.tx.to_hex(secp).decode()
    }

    print("Submitting to node..")

    urlopen("{}/v1/pool/push".format(node_url) + ("?fluff" if fluff else ""), json.dumps(tx_wrapper).encode(), 600)

    wallet.save()

    print("Transaction complete!")


def post(handler: HTTPServerHandler):
    global secp, wallet, server
    try:
        length = handler.headers['Content-Length']
        length = 0 if length is None else int(length)
        raw = ""
        if length > 0:
            raw = handler.rfile.read(length).decode()
        f = open("simple_tx_receive.json", "w")
        f.write(raw)
        f.close()
        slate = Slate.from_dict(secp, json.loads(raw))

        print("Receive {} grin".format(slate.amount / GRIN_UNIT))

        # Output
        # n_outputs = min(100, slate.amount)
        n_outputs = 1
        blind_sum = BlindSum()
        output_child_key, output_entry = wallet.create_output(slate.amount-n_outputs+1)
        print("Generate output 0: {}".format(wallet.commit(output_entry)))
        print()
        blind_sum.add_child_key(output_child_key)
        slate.tx.add_output(secp, wallet.entry_to_output(output_entry))
        if n_outputs > 1:
            for i in range(n_outputs-1):
                output_child_key_loop, output_entry_loop = wallet.create_output(1)
                print("Generate output {}: {}".format(i + 1, wallet.commit(output_entry_loop)))
                blind_sum.add_child_key(output_child_key_loop)
                slate.tx.add_output(secp, wallet.entry_to_output(output_entry_loop))

        # Excess
        excess = wallet.chain.blind_sum(blind_sum).to_secret_key(secp)
        public_excess = excess.to_public_key(secp)
        print("Generated excess")

        # Nonce
        nonce = SecretKey.random(secp)
        public_nonce = nonce.to_public_key(secp)

        # Add participant data
        participant = ParticipantData(1, public_excess, public_nonce, None)
        slate.add_participant(participant)

        # After all participants published their nonce, calculate partial signature
        slate.partial_signature(secp, participant, excess, nonce)

        resp = json.dumps(slate.to_dict(secp))

        wallet.save()

        handler.json_response((resp + "\r\n").encode())

        print("Sent response")
    except Exception as e:
        print("Unable to parse slate: {}".format(e))
        handler.error_response()


def receive():
    global secp, wallet, server
    secp = Secp256k1(None, FLAG_ALL)
    wallet = Wallet.open(secp, "wallet")

    set_callback_post(post)

    print("Listening on port 17175..")
    server = HTTPServer(("", 17175), HTTPServerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.socket.close()


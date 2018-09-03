from secp256k1 import FLAG_ALL
from secp256k1.pedersen import Secp256k1
from grin.util import GRIN_UNIT
from grin.wallet import Wallet


def outputs():
    secp = Secp256k1(None, FLAG_ALL)
    wallet = Wallet.open(secp, "wallet_a")
    for entry in wallet.outputs.values():
        print("n={}  key={}  value={}  commit={}".format(entry.n_child, entry.key_id,
                                                         entry.value / GRIN_UNIT, wallet.commit(entry)))
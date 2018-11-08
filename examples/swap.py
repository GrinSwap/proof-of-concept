import json
import math
import os
from time import time
from secp256k1 import FLAG_ALL
from secp256k1.pedersen import Secp256k1, ethereum_signature
from grin.btc import TXID, OutputPoint, Address as BitcoinAddress
from grin.swap import AtomicSwap, Role, Stage, is_eth_address, is_btc_address, is_btc_txid
from grin.util import GRIN_UNIT, UUID, absolute
from grin.wallet import Wallet, NotEnoughFundsException

ETHER_UNIT = 1000000000000000000
BITCOIN_UNIT = 100000000

if not os.path.isdir(absolute("swap_data")):
    os.mkdir(absolute("swap_data"))
    f = open(absolute("swap_data", "_DONT_PUBLISH_THESE_FILES_"), "w")
    f.write("Seriously, dont")
    f.close()
if not os.path.isdir(absolute("swap_data", "sell")):
    os.mkdir(absolute("swap_data", "sell"))
if not os.path.isdir(absolute("swap_data", "buy")):
    os.mkdir(absolute("swap_data", "buy"))


def sell(file=None):
    assert file is None or isinstance(file, str), "Invalid argument"

    secp = Secp256k1(None, FLAG_ALL)

    print("################################")

    swap = None
    if file is None:
        print("# Grin -> BTC/ETH atomic swap\n# ")

        id = UUID.random()
        swap = AtomicSwap(secp, Role.SELLER, id)

        print("# This script is used for selling grin coins for Bitcoin or Ether through an atomic swap\n"
              "# ")

        wallet_dir = input("# What is the name of the wallet you want to use? ")
        if not os.path.isdir(wallet_dir):
            print("# Wallet directory not found")
            return
        swap.wallet = Wallet.open(secp, wallet_dir)

        grin_amount = float(input("# How much grin do you want to sell? "))
        assert grin_amount > 0 and math.isfinite(grin_amount), "Invalid input"
        swap.grin_amount = int(grin_amount*GRIN_UNIT)

        currency = input("# Which currency would you like to receive? [BTC/ETH]: ")
        if currency != "BTC" and currency != "ETH":
            print("# Unknown currency, please enter BTC or ETH")
            return
        swap.swap_currency = currency

        swap_amount = float(input("# How much {} do you want to receive? ".format(currency)))
        assert swap_amount > 0 and math.isfinite(swap_amount), "Invalid input"
        if swap.is_bitcoin_swap():
            swap.swap_amount = int(swap_amount * BITCOIN_UNIT)
            swap_receive_address = input("# At which Bitcoin address would you like to receive this? ")
            assert is_btc_address(swap_receive_address, False), "Invalid input"
        elif swap.is_ether_swap():
            swap.swap_amount = int(swap_amount * ETHER_UNIT)
            swap_receive_address = input("# At which Ethereum address would you like to receive this? ")
            assert is_eth_address(swap_receive_address), "Invalid input"
        else:
            print("# Unknown swap currency")
            return

        swap.swap_receive_address = swap_receive_address

        last_block = float(input("# What is the height of the last Grin T4 block? "))
        assert last_block > 0 and math.isfinite(last_block), "Invalid input"
        swap.lock_height = int(last_block)
        swap.refund_lock_height = swap.lock_height+720  # ~12h

        try:
            swap.select_inputs()
        except NotEnoughFundsException:
            print("# Not enough funds available!")
            return
    else:
        f = open(absolute(file), "r")
        dct = json.loads(f.read())
        f.close()

        if dct['target'] != "seller":
            print("# This file is not meant for me")
            return

        id = UUID.from_str(dct['id'])
        swap_file = absolute("swap_data", "sell", "{}.json".format(str(id)))
        if not os.path.exists(swap_file):
            print("# Swap file not found")
            return
        swap = AtomicSwap(secp, Role.SELLER, id)

        print("# Grin -> {} atomic swap\n# ".format(swap.swap_currency))

        if dct['stage'] != swap.stage.value:
            print("# Unexpected stage")
            return

        diff = int((time() - swap.time_start) / 60)
        diff_hour = int(abs(diff) / 60)
        diff_min = int(abs(diff) % 60)
        if diff_hour >= 6:
            print("# WARNING: this swap was initiated {}h{}m ago".format(diff_hour, diff_min))
            if input("# Do you want to continue? [Y/n]: ") not in ["", "Y", "y"]:
                return
            print("# ")

        swap.receive(dct)

        if swap.stage == Stage.SIGN:
            if swap.is_bitcoin_swap():
                print("# Check that the balance of address {} is at least {} tBTC, with enough confirmations".format(
                    swap.btc_lock_address.to_base58check().decode(), swap.swap_amount / BITCOIN_UNIT
                ))

                if input("# Is this the case? [Y/n]: ") not in ["", "Y", "y"]:
                    print("# Please rerun this script when the address has enough balance")
                    return

                utxo_count = int(input("# How many UTXOs does the address have? "))
                assert utxo_count > 0 and math.isfinite(utxo_count), "Invalid input"
                print("# Output point format: TXID:index")
                swap.btc_output_points = []
                for i in range(utxo_count):
                    output_point = input("#   Insert output point for UTXO #{}: ".format(i))
                    split = output_point.split(":")
                    assert len(split) == 2, "Invalid input"
                    output_txid = split[0]
                    assert is_btc_txid(output_txid), "Invalid output point TXID"
                    output_index = int(split[1])
                    assert output_index >= 0 and math.isfinite(output_index), "Invalid output point index"
                    swap.btc_output_points.append(OutputPoint(TXID.from_hex(output_txid.encode()), output_index))

            if swap.is_ether_swap():
                print("# Check the ETH Ropsten contract at {} for\n"
                      "#   balance of at least {} ETH\n"
                      "#   sign_address = {}\n"
                      "#   receive_address = {}\n"
                      "#   unlock_time far enough in the future (>18h)"
                      "#   enough confirmations".format(swap.eth_contract_address, swap.swap_amount / ETHER_UNIT,
                                                        swap.eth_address_lock, swap.swap_receive_address))

                if input("# Does the contract fulfil these requirements? [Y/n]: ") not in ["", "Y", "y"]:
                    print("# The buyer tried to scam you, but we caught it in time!")
                    return

            swap.fill_signatures()
        elif swap.stage == Stage.LOCK:
            swap.build_transactions()

            name = "{}_multisig_tx.json".format(swap.short_id())
            tx_wrapper = {
                "tx_hex": swap.tx.to_hex(secp).decode()
            }
            f = open(name, "w")
            f.write(json.dumps(tx_wrapper, indent=2))
            f.close()

            print("# Transaction written to {}, please submit it to a node".format(name))

            tx_height = float(input("# Enter the height of the block containing the transaction: "))
            assert tx_height > 0 and math.isfinite(tx_height), "Invalid input"
            swap.tx_height = int(tx_height)

            refund_name = "{}_refund_tx_lock{}.json".format(swap.short_id(), swap.refund_lock_height)
            refund_tx_wrapper = {
                "tx_hex": swap.refund_tx.to_hex(secp).decode()
            }
            f = open(refund_name, "w")
            f.write(json.dumps(refund_tx_wrapper, indent=2))
            f.close()

            print("# Refund transaction written to {}, can be submitted at height {}".format(refund_name,
                                                                                             swap.refund_lock_height))
        elif swap.stage == Stage.SWAP:
            swap.fill_swap_signatures()
        elif swap.stage == Stage.DONE:
            swap.finalize_swap()

            if swap.is_bitcoin_swap():
                btc_swap_name = "{}_btc_swap_tx.hex".format(swap.short_id())
                f = open(btc_swap_name, "w")
                f.write(swap.claim.decode())
                f.close()

                print("# The buyer has claimed their Grin!\n"
                      "# \n"
                      "# Bitcoin transaction written to {}, submit it to a node\n"
                      "# This will give you the testnet BTC and complete the swap. Congratulations!\n"
                      "################################".format(btc_swap_name))

            if swap.is_ether_swap():
                r, s, v = ethereum_signature(swap.claim)
                print("# The buyer has claimed their Grin!\n"
                      "# \n"
                      "# Submit a transaction to contract {}, 'claim' method, with the following arguments:\n"
                      "#   r = {}\n"
                      "#   s = {}\n"
                      "#   v = {}\n"
                      "# This will give you the Ropsten ETH and complete the swap. Congratulations!\n"
                      "################################".format(swap.eth_contract_address, r.decode(), s.decode(), v))

            return

    swap.save()

    out_name = "{}_seller_{}.json".format(swap.short_id(), swap.stage.value)
    f = open(absolute(out_name), "x")
    f.write(json.dumps(swap.send(), indent=2))
    f.close()

    print("# \n"
          "# Created file '{}', please send it to the buyer\n"
          "################################".format(out_name))


def buy(file=None):
    assert file is None or isinstance(file, str), "Invalid argument"

    secp = Secp256k1(None, FLAG_ALL)

    print("################################")

    if file is None:
        print("# BTC/ETH -> grin atomic swap\n# ")
        print("# This script is used for buying grin coins with Bitcoin or Ether through an atomic swap\n"
              "# The seller initiates the process, wait for them to send you a file and run './swap buy <file.json>")
        return

    f = open(absolute(file), "r")
    dct = json.loads(f.read())
    f.close()

    if dct['target'] != "buyer":
        print("# This file is not meant for me")
        return

    id = UUID.from_str(dct['id'])
    swap_file = absolute("swap_data", "buy", "{}.json".format(str(id)))

    swap = AtomicSwap(secp, Role.BUYER, id)

    if not os.path.exists(swap_file):
        if dct['stage'] != Stage.INIT.value:
            print("# Unexpected transaction stage")
            return

        if dct['swap_currency'] != "BTC" and dct['swap_currency'] != "ETH":
            print("# Unsupported currency {}".format(dct['swap_currency']))
            return

        print("# {} -> grin atomic swap\n# ".format(dct['swap_currency']))

        normalize_unit = BITCOIN_UNIT if dct['swap_currency'] == "BTC" else ETHER_UNIT

        print("# You are about to start the process of buying {} grin for {} {}".format(
            dct['grin_amount'] / GRIN_UNIT, dct['swap_amount'] / normalize_unit, dct['swap_currency']))

        if input("# Are you sure? [Y/n]: ") not in ["", "Y", "y"]:
            print("# You declined the offer")
            return

        wallet_dir = input("# What is the name of the wallet you want to use? ")
        if not os.path.isdir(wallet_dir):
            print("# Wallet directory not found")
            return
        dct['wallet'] = wallet_dir

        swap.receive(dct)

        last_block = float(input("# What is the height of the last Grin T4 block? "))
        assert last_block > 0 and math.isfinite(last_block), "Invalid input"

        print("# ")
        diff = swap.lock_height-last_block
        diff_hour = int(abs(diff) / 60)
        diff_min = int(abs(diff) % 60)
        if diff >= 10 or diff <= -60:
            print("#\n"
                  "# WARNING: transaction unlocks ~{}h{}m minutes in the {} (height {})\n"
                  "# ".format(diff_hour, diff_min, "future" if diff > 0 else "past", swap.lock_height))

        diff_refund = swap.refund_lock_height-last_block
        diff_refund_hour = int(diff_refund / 60)
        diff_refund_min = int(diff_refund % 60)
        if diff_refund < 360:
            print("# Refund unlocks less than 6 hours from now (~{}h{}m, height {})".format(
                diff_refund_hour, diff_refund_min, swap.refund_lock_height))
            return

        print("# Refund unlocks in ~{}h{}m (height {})\n"
              "# ".format(diff_refund_hour, diff_refund_min, swap.refund_lock_height))

        if swap.is_bitcoin_swap():
            print("# Please send (at least) {} tBTC to {}".format(swap.swap_amount / BITCOIN_UNIT,
                                                                  swap.btc_lock_address.to_base58check().decode()))
            input("# When you are done, press Enter: ")

        if swap.is_ether_swap():
            print(
                "# Please deploy the GrinSwap.sol contract on the Ethereum Ropsten testnet"
                "with the following arguments:\n"
                "#   _sign_address = {}\n"
                "#   _receive_address = {}\n"
                "# and deposit (at least) {} ETH in it".format(swap.eth_address_lock, swap.swap_receive_address,
                                                               swap.swap_amount / ETHER_UNIT))

            eth_contract_address = input("# When you are done, enter the contract address: ")
            assert is_eth_address(eth_contract_address), "Invalid input"
            swap.eth_contract_address = eth_contract_address

        swap.fill_signatures()
    else:
        print("# {} -> grin atomic swap\n# ".format(swap.swap_currency))

        if dct['stage'] != swap.stage.value+1:
            print("# Unexpected stage")
            return

        diff = int((time() - swap.time_start) / 60)
        diff_hour = int(abs(diff) / 60)
        diff_min = int(abs(diff) % 60)
        if diff_hour >= 6:
            print("# WARNING: this swap was initiated {}h{}m ago".format(diff_hour, diff_min))
            if input("# Do you want to continue? [Y/n]: ") not in ["", "Y", "y"]:
                return
            print("# ")

        swap.receive(dct)

        if swap.stage == Stage.SIGN:
            swap.finalize_range_proof()
        elif swap.stage == Stage.LOCK:
            print("# The seller claims the multisig output {} was mined in block {}".format(
                swap.commit.to_hex(secp).decode(), swap.tx_height))
            if input("# Does this block (or another) contain the output? [Y/n]: ") not in ["", "Y", "y"]:
                print("# You can rerun this command when the output has been mined")
                return
            swap.prepare_swap()
        elif swap.stage == Stage.SWAP:
            swap.finalize_swap()

            swap_name = "{}_swap_tx.json".format(swap.short_id())
            swap_tx_wrapper = {
                "tx_hex": swap.swap_tx.to_hex(secp).decode()
            }
            f = open(swap_name, "w")
            f.write(json.dumps(swap_tx_wrapper, indent=2))
            f.close()

            print("# Transaction written to {}, please submit it to a node to claim your Grin".format(swap_name))
            input("# Press [Enter] when the transaction has been mined: ")
            print("# \n"
                  "# Congratulations, you completed the swap!")
        else:
            print("# Not sure what to do")
            return

    swap.save()

    out_name = "{}_buyer_{}.json".format(swap.short_id(), swap.stage.value)
    f = open(absolute(out_name), "x")
    f.write(json.dumps(swap.send(), indent=2))
    f.close()

    print("# \n"
          "# Created file '{}', please send it to the seller\n"
          "################################".format(out_name))

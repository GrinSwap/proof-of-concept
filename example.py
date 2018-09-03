from examples import simple_tx, multisig_tx, submit, swap, wallet
from sys import argv


def main():
    if len(argv) < 2:
        print("################################\n"
              "# GrinSwap examples\n"
              "#\n"
              "# Usage: run './py example.py <name>' to find out more. Choices for <name> are\n"
              "#  - simple_tx, create and submit a grin transaction\n"
              "#  - multisig_tx, create a 2-of-2 multi-signature output\n"
              "#  - submit, submit a finished transaction to a node\n"
              "################################")
        return

    if argv[1] == "simple_tx":
        if len(argv) < 3:
            print("################################\n"
                  "# Sending and receiving a simple transaction\n"
                  "#\n"
                  "# Requirements:\n"
                  "#   - Wallet folder 'wallet_1' with at least 1 unspent output\n"
                  "#   - Wallet folder 'wallet_2', receiving wallet\n"
                  "#   - A node to submit the final tx to\n"
                  "#\n"
                  "# Usage:\n"
                  "#  - Run './example simple_tx receive' to start the receive server\n"
                  "#  - With the server running, execute './example simple_tx send <http://node_url:13413>'\n"
                  "################################")
            return

        if argv[2] == "receive":
            simple_tx.receive()
        elif argv[2] == "send":
            if len(argv) < 4:
                node = "http://127.0.0.1:13413"
                print("Missing node URL, assuming '{}'".format(node))
            else:
                node = argv[3]
            simple_tx.send(node)
    elif argv[1] == "multisig_tx":
        if len(argv) < 3:
            print("################################\n"
                  "# Building a multi-signature transaction with timelocked refund\n"
                  "#\n"
                  "# Requirements:\n"
                  "#   - Wallet folder 'wallet_1' with at least 1 unspent output\n"
                  "#   - Wallet folder 'wallet_2', receiving wallet\n"
                  "#   - A node to submit the final tx to\n"
                  "#\n"
                  "# Usage:\n"
                  "#  - Run './example multisig_tx receive' to start the receive server\n"
                  "#  - With the server running, execute './example multisig_tx send <http://node_url:13413>'\n"
                  "################################")
            return

        if argv[2] == "receive":
            multisig_tx.receive()
        elif argv[2] == "send":
            if len(argv) < 4:
                node = "http://127.0.0.1:13413"
                print("Missing node URL, assuming '{}'".format(node))
            else:
                node = argv[3]
            multisig_tx.send(node)
        else:
            print("Unknown argument")
    elif argv[1] == "submit":
        if len(argv) < 3:
            print("################################\n"
                  "# Building a multi-signature transaction with timelocked refund\n"
                  "#\n"
                  "# Requirements:\n"
                  "#   - A tx_wrapper json file\n"
                  "#\n"
                  "# Usage:\n"
                  "#  - Run './py example.py submit <file.json> <http://node_url:13413>' to submit a transaction\n"
                  "################################")
            return
        if len(argv) < 4:
            node = "http://127.0.0.1:13413"
            print("Missing node URL, assuming '{}'".format(node))
        else:
            node = argv[3]
        submit.submit(argv[2], node)
    elif argv[1] == "swap":
        if len(argv) < 3:
            print("################################\n"
                  "# Atomic swap\n"
                  "#\n"
                  "# Run './swap sell' to sell grin for ETH\n"
                  "# Run './swap buy' to buy grin for ETH\n"
                  "################################")
            return

        if argv[2] == "sell":
            if len(argv) >= 4:
                swap.sell(argv[3])
            else:
                swap.sell()
        elif argv[2] == "buy":
            if len(argv) >= 4:
                swap.buy(argv[3])
            else:
                swap.buy()
        else:
            print("Unknown argument")
    elif argv[1] == "wallet":
        wallet.outputs()
    else:
        print("Unknown example")

if __name__ == "__main__":
    main()

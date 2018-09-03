from urllib.request import urlopen


def submit(file: str, node_url: str):
    fluff = True

    f = open(file, "r")
    raw = f.read()
    f.close()

    print("Submitting to node..")

    urlopen("{}/v1/pool/push".format(node_url) + ("?fluff" if fluff else ""), raw.encode(), 60)

    print("Transaction complete!")

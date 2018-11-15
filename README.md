# GrinSwap proof of concept
This code provides a proof of concept for executing Grin-BTC/ETH atomic swaps. It was used to perform the first swaps on Grin testnet (as far as we know), read more about it [here](https://medium.com/grinswap/first-grin-atomic-swap-a16b4cc19196).
Note that this code is definitely not production-ready and usage is at your own risk.

## Building
Getting this code to run is a bit involved, it has not been optimized for user friendliness. The steps to take are:
  1. Download a copy of this repository
  2. Clone [the Grin fork](https://github.com/mimblewimble/secp256k1-zkp) of secp256k1-zkp
  3. Copy `build_secp256k1-zkp.sh` to the secp25k1-zkp directory
  4. Excute it to build the library
  5. Copy the `build/include` and `build/lib` directories to the grinswap directory
  6. Create and start a venv with python 3.6, and install `cffi eth-hash pysha3` with pip
  7. Execute `./build` to build the python cffi library

## Usage
Executing a swap is for now a very manual process, requiring sending files between the seller and buyer multiple times.
  1. Start the venv
  2. Create a wallet directory and add a `wallet.seed` file with a random seed
  3. If you are selling Grin, you need to have some in your wallet. Run `./example simple_tx receive` and send some Grin to it, on port 17175
  4. To get started with the swap, run `./swap sell` and follow the directions
Any Grin transactions can be submitted with `./example <filename> <optional node url>`

## License
This code is released under the Apache License 2.0

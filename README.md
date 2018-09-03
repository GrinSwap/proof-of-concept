# GrinSwap proof of concept
This code provides a proof of concept for executing Grin-ETH atomic swaps. It was used to perform the first swap on Grin testnet3 (as far as we know), read more about it [here]().

## Building
Getting this code to run is a bit involved, it has not been optimized for user friendliness. The steps to take are:
  1. Download a copy of this repository
  2. Check out [this fork](https://github.com/jaspervdm/secp256k1-zkp/tree/bp_multisig) (bp_multisig branch) of secp256k1-zkp
  3. Copy `build_secp256k1-zkp.sh` to the secp25k1-zkp directory
  4. Excute it to build the library
  5. Copy the `build/include` and `build/lib` directories to the grinswap directory
  6. Create and start a venv with python 3.6, and install `cffi eth-hash pysha3` with pip
  7. Execute `./build` to build the python cffi library

## Usage
Executing a swap is for now a very manual process, requiring sending files between the seller and buyer multiple times.
To get started, start the venv, run `./swap sell` and follow the directions.
It requires a directory containing `wallet.seed`, `wallet.det` and `wallet.dat` that has an unspent output.
Transactions can be submitted to a node using `./example submit`.

## License
This code is released under the Apache License 2.0

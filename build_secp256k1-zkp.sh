#!/bin/sh
./autogen.sh
./configure --prefix=$PWD/build --with-bignum=no --enable-benchmark=no --enable-endomorphism --enable-experimental \
  --enable-module-ecdh --enable-module-generator --enable-module-recovery --enable-module-commitment \
  --enable-module-aggsig --enable-module-rangeproof --enable-module-bulletproof
make
make install

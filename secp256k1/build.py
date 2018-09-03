import os
from collections import namedtuple
from cffi import FFI


def absolute(*paths):
    op = os.path
    return op.realpath(op.abspath(op.join(op.dirname(__file__), "..", *paths)))

Source = namedtuple("Source", ("h", "include"))

_modules = [
    "secp256k1",
    "secp256k1_recovery",
    "secp256k1_aggsig",
    "secp256k1_generator",
    "secp256k1_commitment",
    "secp256k1_rangeproof",
    "secp256k1_bulletproofs"
]

ffi = FFI()
code = []
for mod in _modules:
    with open(absolute("_cffi_build/{}.h".format(mod)), "rt") as h:
        ffi.cdef(h.read())
    code.append("#include <{}.h>".format(mod))
ffi.set_source('_libsecp256k1', "\n".join(code), libraries=["secp256k1"], library_dirs=[absolute("lib")],
               include_dirs=[absolute("include")])
ffi.compile(verbose=True)

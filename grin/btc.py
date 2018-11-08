from binascii import hexlify, unhexlify
from typing import Optional, List
from secp256k1.key import SecretKey, PublicKey
from secp256k1.pedersen import Secp256k1
from grin.util import hash160, hash256, base58check_encode, base58check_decode, var_int_encode, script_write_bytes

PREFIX_TN_PUBKEY_HASH = 0x6F
PREFIX_TN_SCRIPT_HASH = 0xC4
PREFIX_PUBKEY_HASH = 0x00
PREFIX_SCRIPT_HASH = 0x05

OP_FALSE = 0x00
OP_0 = OP_FALSE
OP_PUSH_4 = 0x04
OP_PUSH_20 = 0x14
OP_PUSH_33 = 0x21
OP_TRUE = 0x51
OP_1 = OP_TRUE
OP_2 = 0x52
OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_DROP = 0x75
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xa9
OP_CHECKSIG = 0xac
OP_CHECKMULTISIG = 0xae
OP_CHECKLOCKTIMEVERIFY = 0xb1


class TXID:
    def __init__(self, hashed: bytearray):
        assert len(hashed) == 32
        self.hashed = hashed

    def __str__(self):
        return "TXID<{}>".format(self.to_hex().decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self, reverse=False) -> bytearray:
        data = self.hashed[:]
        if reverse:
            data.reverse()
        return data

    def to_hex(self, reverse=True) -> bytes:
        return hexlify(self.to_bytearray(reverse))

    @staticmethod
    def from_bytearray(data: bytearray, reverse=False):
        hashed = data[:]
        if reverse:
            hashed.reverse()
        return TXID(hashed)

    @staticmethod
    def from_hex(data: bytes, reverse=True):
        return TXID.from_bytearray(bytearray(unhexlify(data)), reverse)


class OutputPoint:
    def __init__(self, txid: TXID, index: int):
        self.txid = txid
        self.index = index

    def to_bytearray(self) -> bytearray:
        data = bytearray()
        data.extend(self.txid.to_bytearray())
        data.extend(self.index.to_bytes(4, "big"))
        return data

    def to_hex(self) -> bytes:
        return hexlify(self.to_bytearray())

    @staticmethod
    def from_bytearray(data: bytearray):
        return OutputPoint(TXID.from_bytearray(data[:32]), int.from_bytes(data[32:36], "big"))

    @staticmethod
    def from_hex(data: bytes):
        return OutputPoint.from_bytearray(bytearray(unhexlify(data)))


class Address:
    def __init__(self, hashed: bytearray, pubkey=True, mainnet=True):
        assert len(hashed) == 20
        self.pubkey = pubkey
        self.mainnet = mainnet
        self.hashed = hashed

    def __str__(self):
        return "Address<{}>".format(self.to_base58check().decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self, prefix=True) -> bytearray:
        data = self.hashed[:]
        if prefix:
            data.insert(0, self.prefix())
        return data

    def to_base58check(self) -> bytes:
        return base58check_encode(self.to_bytearray())

    def prefix(self) -> int:
        if self.mainnet:
            return PREFIX_PUBKEY_HASH if self.pubkey else PREFIX_SCRIPT_HASH
        return PREFIX_TN_PUBKEY_HASH if self.pubkey else PREFIX_TN_SCRIPT_HASH

    def is_mainnet(self) -> bool:
        return self.mainnet

    def is_testnet(self) -> bool:
        return not self.mainnet

    def is_pubkey_hash(self) -> bool:
        return self.pubkey

    def is_script_hash(self) -> bool:
        return not self.pubkey

    @staticmethod
    def from_bytearray(data: bytearray):
        prefixes = {
            PREFIX_TN_PUBKEY_HASH: [True, False],
            PREFIX_TN_SCRIPT_HASH: [False, False],
            PREFIX_PUBKEY_HASH: [True, True],
            PREFIX_SCRIPT_HASH: [False, True]
        }
        assert data[0] in prefixes
        flags = prefixes[data[0]]
        return Address(data[1:], flags[0], flags[1])

    @staticmethod
    def from_base58check(data: bytes):
        return Address.from_bytearray(base58check_decode(data))

    @staticmethod
    def from_public_key(secp: Secp256k1, key: PublicKey, mainnet=True):
        return Address(hash160(key.to_bytearray(secp)), True, mainnet)

    @staticmethod
    def from_script(script: bytearray, mainnet=True):
        return Address(hash160(script), False, mainnet)


class Script:
    @staticmethod
    def is_p2pkh(script: bytearray) -> bool:
        return len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and \
               script[23] == 0x88 and script[24] == 0xac

    @staticmethod
    def p2(address: Address):
        if address.is_script_hash():
            return Script.p2sh(address)
        return Script.p2pkh(address)

    @staticmethod
    def p2pkh(pubkey_hash: Address) -> bytearray:
        data = bytearray()
        data.append(OP_DUP)
        data.append(OP_HASH160)
        data.append(OP_PUSH_20)
        data.extend(pubkey_hash.to_bytearray(False))
        data.append(OP_EQUALVERIFY)
        data.append(OP_CHECKSIG)
        return data

    @staticmethod
    def p2sh(script_hash: Address) -> bytearray:
        data = bytearray()
        data.append(OP_HASH160)
        data.append(OP_PUSH_20)
        data.extend(script_hash.to_bytearray(False))
        data.append(OP_EQUAL)
        return data

    @staticmethod
    def multisig_refund(secp: Secp256k1, key_a: PublicKey, key_b: PublicKey,
                        refund_key: PublicKey, timelock: int) -> bytearray:
        data = bytearray()
        data.append(OP_IF)
        data.append(OP_PUSH_4)
        data.extend(timelock.to_bytes(4, "little"))
        data.append(OP_CHECKLOCKTIMEVERIFY)
        data.append(OP_DROP)
        data.append(OP_PUSH_33)
        data.extend(refund_key.to_bytearray(secp))
        data.append(OP_CHECKSIG)
        data.append(OP_ELSE)
        data.append(OP_2)
        data.append(OP_PUSH_33)
        data.extend(key_a.to_bytearray(secp))
        data.append(OP_PUSH_33)
        data.extend(key_b.to_bytearray(secp))
        data.append(OP_2)
        data.append(OP_CHECKMULTISIG)
        data.append(OP_ENDIF)
        return data


class Input:
    def __init__(self, prev_tx_hash: TXID, prev_tx_index: int,
                 prev_script_pubkey: bytearray, script_sig: bytearray, sequence: Optional[int]):
        self.prev_tx_hash = prev_tx_hash
        self.prev_tx_index = prev_tx_index
        self.prev_script_pubkey = prev_script_pubkey
        self.script_sig = script_sig
        self.sequence = 0xFFFFFFFF if sequence is None else sequence

    def to_bytearray(self, for_signature=None) -> bytearray:
        data = bytearray()
        data.extend(self.prev_tx_hash.to_bytearray())
        data.extend(self.prev_tx_index.to_bytes(4, "little"))
        if for_signature is None:
            data.extend(var_int_encode(len(self.script_sig)))
            data.extend(self.script_sig)
        else:
            if for_signature:
                data.extend(var_int_encode(len(self.prev_script_pubkey)))
                data.extend(self.prev_script_pubkey)
            else:
                data.append(0x00)
        data.extend(self.sequence.to_bytes(4, "little"))
        return data


class Output:
    def __init__(self, value: int, script_pubkey: bytearray):
        self.value = value
        self.script = script_pubkey

    def to_bytearray(self) -> bytearray:
        data = bytearray()
        data.extend(self.value.to_bytes(8, "little"))
        data.extend(var_int_encode(len(self.script)))
        data.extend(self.script)
        return data


class Transaction:
    def __init__(self, version: int, inputs: List[Input], outputs: List[Output], lock_time: int):
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.lock_time = lock_time

    def to_bytearray(self, sign_input=None) -> bytearray:
        data = bytearray()
        data.extend(self.version.to_bytes(4, "little"))
        data.extend(var_int_encode(len(self.inputs)))
        for i in range(len(self.inputs)):
            input = self.inputs[i]
            data.extend(input.to_bytearray(None if sign_input is None else (True if sign_input == i else False)))
        data.extend(var_int_encode(len(self.outputs)))
        for output in self.outputs:
            data.extend(output.to_bytearray())
        data.extend(self.lock_time.to_bytes(4, "little"))
        return data

    def to_hex(self) -> bytes:
        return hexlify(self.to_bytearray())

    def txid(self) -> TXID:
        return TXID.from_bytearray(hash256(self.to_bytearray()))

    def add_input(self, input: Input):
        self.inputs.append(input)

    def add_output(self, output: Output):
        self.outputs.append(output)

    def raw_signature(self, secp: Secp256k1, i: int, secret_key: SecretKey) -> bytearray:
        data = self.to_bytearray(i)
        data.extend(bytearray([1, 0, 0, 0]))
        signature = secp.sign(secret_key, hash256(data))
        signature.append(0x01)
        return signature

    def sign(self, secp: Secp256k1, i: int, secret_key: SecretKey):
        script_sig = bytearray()
        signature = self.raw_signature(secp, i, secret_key)
        script_sig.extend(script_write_bytes(len(signature)))
        script_sig.extend(signature)
        public_key = secret_key.to_public_key(secp).to_bytearray(secp)
        script_sig.extend(script_write_bytes(len(public_key)))
        script_sig.extend(public_key)
        self.inputs[i].script_sig = script_sig

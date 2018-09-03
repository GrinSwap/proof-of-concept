import os
import json
from binascii import hexlify, unhexlify
from typing import List
from enum import Enum
from grin.keychain import Keychain, Identifier, ChildKey
from grin.util import absolute
from grin.transaction import Input, Output, OutputFeatures
from secp256k1.pedersen import Secp256k1, Commitment


class OutputStatus(Enum):
    Unconfirmed = 1,
    Unspent = 2,
    Locked = 3,
    Spent = 4


class OutputEntry:
    def __init__(self, root_key_id: Identifier, key_id: Identifier, n_child: int, value: int, status: OutputStatus,
                 height: int, lock_height: int, is_coinbase: bool):
        self.root_key_id = root_key_id
        self.key_id = key_id
        self.n_child = n_child
        self.value = value
        self.status = status
        self.height = height
        self.lock_height = lock_height
        self.is_coinbase = is_coinbase

    def __repr__(self):
        return "OutputEntry<n={}, value={}, status={}>".format(self.n_child, self.value, self.status.name)

    def to_dict(self) -> dict:
        return {
            "root_key_id": self.root_key_id.to_hex().decode(),
            "key_id": self.key_id.to_hex().decode(),
            "n_child": self.n_child,
            "value": self.value,
            "status": self.status.name,
            "height": self.height,
            "lock_height": self.lock_height,
            "is_coinbase": self.is_coinbase
        }

    def update_from_dict(self, dct: dict):
        self.value = dct['value']
        self.status = OutputStatus[dct['status']]
        self.height = dct['height']
        self.lock_height = dct['lock_height']
        self.is_coinbase = dct['is_coinbase']

    def mark_locked(self):
        self.status = OutputStatus.Locked

    def mark_unspent(self):
        if self.status in (OutputStatus.Unconfirmed, OutputStatus.Locked):
            self.status = OutputStatus.Unspent

    def mark_spent(self):
        if self.status in (OutputStatus.Unspent, OutputStatus.Locked):
            self.status = OutputStatus.Spent

    @staticmethod
    def from_dict(dct: dict):
        root_key_id = Identifier.from_hex(dct['root_key_id'].encode())
        key_id = Identifier.from_hex(dct['key_id'].encode())
        status = OutputStatus[dct['status']]
        return OutputEntry(root_key_id, key_id, dct['n_child'], dct['value'], status, dct['height'],
                           dct['lock_height'], dct['is_coinbase'])

    @staticmethod
    def from_child(child: ChildKey, value: int, is_coinbase: bool):
        return OutputEntry(child.root_key_id, child.key_id, child.n_child, value,
                           OutputStatus.Unconfirmed, 0, 0, is_coinbase)


class WalletDetails:
    def __init__(self, location: str):
        self.location = location
        self.last_confirmed_height = 0
        self.last_child_index = 0
        if not os.path.exists(location):
            self.save()
        else:
            self.load()

    def to_dict(self) -> dict:
        return {
            "last_confirmed_height": self.last_confirmed_height,
            "last_child_index": self.last_child_index
        }

    def load(self):
        f = open(self.location, "r")
        dct = json.loads(f.read())
        f.close()
        self.last_confirmed_height = dct['last_confirmed_height']
        self.last_child_index = dct['last_child_index']

    def save(self):
        f = open(self.location, "w")
        f.write(json.dumps(self.to_dict(), indent=2))
        f.close()

    def next(self) -> int:
        self.last_child_index += 1
        return self.last_child_index


class NotEnoughFundsException(Exception):
    pass


# File wallet
# TODO: locking, output selection strategies
class Wallet:
    def __init__(self, secp: Secp256k1, location: str, seed: bytes):
        self.dir_in = location
        self.dir = absolute(location)
        assert os.path.isdir(self.dir)
        self.chain = Keychain.from_seed(secp, seed)
        self.details = WalletDetails(absolute(self.dir, "wallet.det"))
        self.cache = {}
        self.outputs = {}
        if not os.path.exists(absolute(self.dir, "wallet.dat")):
            self.save()
        else:
            self.load()

    def load(self):
        self.details.load()
        f = open(absolute(self.dir, "wallet.dat"), "r")
        entries = json.loads(f.read())
        f.close()
        outputs = {}
        for entry in entries:
            key_id = entry['key_id']
            if key_id in self.outputs:
                output = self.outputs[key_id]
                output.update_from_dict(entry)
                outputs[key_id] = output
            outputs[key_id] = OutputEntry.from_dict(entry)
        self.outputs = outputs

    def save(self):
        self.details.save()
        lst = [y.to_dict() for x, y in self.outputs.items()]
        lst = sorted(lst, key=lambda x: x['n_child'])
        f = open(absolute(self.dir, "wallet.dat"), "w")
        f.write(json.dumps(lst, indent=2))
        f.close()

    def get_output(self, key: str) -> OutputEntry:
        return self.outputs[key] if key in self.outputs else None

    def get_output_by_n(self, n: int) -> OutputEntry:
        return self.get_output(self.chain.derive(n).key_id.to_hex().decode())

    def select_outputs(self, amount: int) -> List[OutputEntry]:
        total_amount = 0
        outputs = []
        for n, output in self.outputs.items():
            if output.status != OutputStatus.Unspent:
                continue
            total_amount += output.value
            outputs.append(output)
            if total_amount > amount:
                break
        if total_amount <= amount:
            raise NotEnoughFundsException()
        return outputs

    def create_output(self, value: int, is_coinbase=False) -> (ChildKey, OutputEntry):
        assert isinstance(is_coinbase, bool)
        # TODO: lock
        child = self.chain.derive(self.details.next())
        self.cache[child.key_id.to_hex().decode()] = child
        output = OutputEntry.from_child(child, value, is_coinbase)
        self.outputs[output.key_id.to_hex().decode()] = output
        # self.save()
        return child, output

    def derive_from_entry(self, entry: OutputEntry) -> ChildKey:
        key_id = entry.key_id.to_hex().decode()
        if key_id not in self.cache:
            self.cache[key_id] = self.chain.derive(entry.n_child)
        return self.cache[key_id]

    def commit_with_child_key(self, value: int, child: ChildKey) -> Commitment:
        return self.chain.commit(value, child)

    def commit(self, entry: OutputEntry) -> Commitment:
        return self.chain.commit(entry.value, self.derive_from_entry(entry))

    def entry_to_input(self, entry: OutputEntry) -> Input:
        commitment = self.commit(entry)
        return Input(
            OutputFeatures.COINBASE_OUTPUT if entry.is_coinbase else OutputFeatures.DEFAULT_OUTPUT,
            commitment
        )

    def entry_to_output(self, entry: OutputEntry) -> Output:
        return Output.create(
            self.chain,
            OutputFeatures.COINBASE_OUTPUT if entry.is_coinbase else OutputFeatures.DEFAULT_OUTPUT,
            self.derive_from_entry(entry),
            entry.value
        )

    @staticmethod
    def open(secp: Secp256k1, location: str):
        abs_dir = absolute(location)
        assert os.path.isdir(abs_dir)
        seed_file = absolute(abs_dir, "wallet.seed")
        assert os.path.exists(seed_file)
        f = open(seed_file, "r")
        wallet = Wallet(secp, location, unhexlify(f.readline().encode()))
        wallet.load()
        return wallet

    @staticmethod
    def create(secp: Secp256k1, location: str, seed: bytes):
        assert len(seed) == 32, "Invalid seed length"
        abs_dir = absolute(location)
        if not os.path.exists(abs_dir):
            os.makedirs(abs_dir)
        else:
            assert os.path.isdir(abs_dir), "Wallet location not a directory"
        seed_file = absolute(abs_dir, "wallet.seed")
        assert not os.path.exists(seed_file), "Wallet already exists"
        f = open(seed_file, "x")
        f.write(hexlify(seed).decode())
        f.close()
        return Wallet(secp, location, seed)

    @staticmethod
    def create_random(secp: Secp256k1, location: str):
        return Wallet.create(secp, location, os.urandom(32))

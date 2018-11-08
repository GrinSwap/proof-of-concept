from binascii import hexlify
from enum import Enum
import json
import os
import string
from time import time
from secp256k1.key import SecretKey, PublicKey, Signature, ethereum_address
from secp256k1.pedersen import Secp256k1, Commitment, RangeProof
from grin import aggsig
from grin.btc import Address, Script, OutputPoint, Transaction as BitcoinTransaction, Input as BitcoinInput, \
    Output as BitcoinOutput, OP_FALSE
from grin.keychain import BlindingFactor, BlindSum
from grin.proof import TwoPartyBulletProof
from grin.transaction import tx_fee, Input, Output, OutputFeatures, Kernel, Transaction
from grin.util import UUID, absolute, MILLI_GRIN_UNIT, OrderedEnum, script_write_bytes
from grin.wallet import Wallet


def is_hex(s: str) -> bool:
    hex_digits = set(string.hexdigits)
    return all(c in hex_digits for c in s)


def is_eth_address(s: str) -> bool:
    return len(s) == 42 and s[:2] == "0x" and is_hex(s[2:])


def is_base58(s: str) -> bool:
    base58_digits = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    return all(c in base58_digits for c in s)


def is_btc_address(s: str, mainnet=None) -> bool:
    if not is_base58(s):
        return False
    try:
        address = Address.from_base58check(s.encode())
        return mainnet is None or (mainnet and address.is_mainnet()) or (not mainnet and address.is_testnet())
    except AssertionError:
        return False


def is_btc_txid(s: str) -> bool:
    return len(s) == 64 and is_hex(s)


class Role(Enum):
    SELLER = 1
    BUYER = 2


class Stage(OrderedEnum):
    INIT = 1
    SIGN = 2
    LOCK = 3
    SWAP = 4
    DONE = 5

    def num(self) -> int:
        return self.value


class AtomicSwap:
    def __init__(self, secp: Secp256k1, role: Role, id: UUID):
        self.secp = secp
        self.role = role
        self.id = id
        self.swap_file = absolute("swap_data", "sell" if self.role is Role.SELLER else "buy", "{}.json".format(str(id)))

        # Default values
        self.stage = self.wallet = self.grin_amount = self.swap_currency = self.swap_amount \
            = self.swap_receive_address = self.swap_cosign = self.public_swap_cosign = self.lock_height \
            = self.refund_lock_height = self.input_entries = self.inputs = self.fee_amount = self.refund_fee_amount \
            = self.input_amount = self.change_amount = self.change_entry = self.change_child = self.change_output \
            = self.partial_entry = self.partial_child = self.partial_commit = self.offset = self.public_excess \
            = self.refund_entry = self.refund_child = self.refund_output = self.refund_offset = self.nonce \
            = self.public_nonce = self.refund_nonce = self.public_refund_nonce = self.foreign_partial_commit \
            = self.foreign_public_nonce = self.foreign_public_refund_nonce = self.secret_lock \
            = self.public_lock = self.eth_address_lock = self.eth_contract_address = self.btc_lock_time \
            = self.btc_refund_key = self.public_btc_refund_key = self.btc_lock_address = self.commit \
            = self.public_refund_excess = self.partial_signature = self.partial_refund_signature = self.t_1 = self.t_2 \
            = self.foreign_partial_signature = self.foreign_partial_refund_signature = self.foreign_t_1 \
            = self.foreign_t_2 = self.tau_x = self.foreign_tau_x = self.range_proof = self.refund_tx = self.tx \
            = self.tx_height = self.btc_output_points = self.swap_nonce = self.public_swap_nonce \
            = self.foreign_public_swap_nonce = self.swap_entry = self.swap_child = self.swap_fee_amount \
            = self.swap_lock_height = self.swap_output = self.swap_offset = self.public_swap_excess \
            = self.partial_swap_signature = self.partial_swap_adaptor \
            = self.foreign_partial_swap_adaptor = self.foreign_partial_swap_signature = self.swap_tx \
            = self.claim = None
        self.time_start = int(time())

        if os.path.exists(self.swap_file):
            self.load()

    def is_bitcoin_swap(self) -> bool:
        return self.swap_currency == "BTC"

    def is_ether_swap(self) -> bool:
        return self.swap_currency == "ETH"

    def select_inputs(self):
        assert self.stage is None, "Incorrect stage"
        assert self.role == Role.SELLER, "Incorrect role"

        self.stage = Stage.INIT

        if self.is_bitcoin_swap():
            # Generate a key that will co-sign the BTC multisig
            self.swap_cosign = SecretKey.random(self.secp)
            self.public_swap_cosign = self.swap_cosign.to_public_key(self.secp)

        # Inputs
        self.input_entries = self.wallet.select_outputs(self.grin_amount + tx_fee(1, 2, MILLI_GRIN_UNIT) + 1)
        self.inputs = []
        for entry in self.input_entries:
            entry.mark_locked()
            input = self.wallet.entry_to_input(entry)
            self.inputs.append(input)
        self.fee_amount = tx_fee(len(self.input_entries), 2, MILLI_GRIN_UNIT)
        self.refund_fee_amount = tx_fee(1, 1, MILLI_GRIN_UNIT)
        self.input_amount = sum(x.value for x in self.input_entries)
        self.change_amount = self.input_amount - self.grin_amount - self.fee_amount

        # Change output
        self.change_child, self.change_entry = self.wallet.create_output(self.change_amount)
        self.change_entry.mark_locked()
        self.change_output = self.wallet.entry_to_output(self.change_entry)

        # Partial multisig output
        self.partial_child, self.partial_entry = self.wallet.create_output(self.grin_amount)
        self.partial_entry.mark_locked()
        self.partial_commit = self.wallet.commit_with_child_key(0, self.partial_child)

        # Offset
        self.offset = BlindingFactor.from_secret_key(SecretKey.random(self.secp))

        # Refund output
        refund_amount = self.grin_amount - self.refund_fee_amount
        self.refund_child, self.refund_entry = self.wallet.create_output(refund_amount)
        self.refund_output = self.wallet.entry_to_output(self.refund_entry)

        # Refund offset
        self.refund_offset = BlindingFactor.from_secret_key(SecretKey.random(self.secp))

        # Nonces
        self.nonce = SecretKey.random(self.secp)
        self.public_nonce = self.nonce.to_public_key(self.secp)
        self.refund_nonce = SecretKey.random(self.secp)
        self.public_refund_nonce = self.refund_nonce.to_public_key(self.secp)

        self.wallet.save()

    def fill_signatures(self):
        seller = self.role == Role.SELLER
        assert (not seller and self.stage == Stage.INIT) or (seller and self.stage == Stage.SIGN), "Incorrect stage"

        # Public (total) excess
        pos = [self.commit, self.change_output.commit, self.secp.commit_value(self.fee_amount)]
        neg = [x.commit for x in self.inputs]
        neg.append(self.secp.commit(0, self.offset))
        self.public_excess = self.secp.commit_sum(pos, neg).to_public_key(self.secp)

        # Partial excess
        blind_sum = BlindSum()
        blind_sum.add_child_key(self.partial_child)
        if seller:
            blind_sum.add_child_key(self.change_child)
            for entry in self.input_entries:
                blind_sum.sub_child_key(self.wallet.derive_from_entry(entry))
            blind_sum.sub_blinding_factor(self.offset)
        excess = self.wallet.chain.blind_sum(blind_sum).to_secret_key(self.secp)

        # Partial signature
        public_nonce_sum = PublicKey.from_combination(self.secp, [self.public_nonce, self.foreign_public_nonce])
        self.partial_signature = aggsig.calculate_partial(
            self.secp, excess, self.nonce, self.public_excess, public_nonce_sum, self.fee_amount, self.lock_height
        )

        # First step of multi party bullet proof
        proof_builder = TwoPartyBulletProof(self.secp, self.partial_child.key,
                                            self.foreign_partial_commit.to_public_key(self.secp),
                                            self.grin_amount, self.commit)
        self.t_1, self.t_2 = proof_builder.round_1()

        if seller:
            proof_builder.fill_round_1(self.foreign_t_1, self.foreign_t_2)
            self.tau_x = proof_builder.round_2()

        # Public (total) refund excess
        pos = [self.refund_output.commit, self.secp.commit_value(self.refund_fee_amount)]
        neg = [self.commit, self.secp.commit(0, self.refund_offset)]
        self.public_refund_excess = self.secp.commit_sum(pos, neg).to_public_key(self.secp)

        # Partial refund excess
        refund_blind_sum = BlindSum()
        refund_blind_sum.sub_child_key(self.partial_child)
        if seller:
            refund_blind_sum.add_child_key(self.refund_child)
            refund_blind_sum.sub_blinding_factor(self.refund_offset)
        refund_excess = self.wallet.chain.blind_sum(refund_blind_sum).to_secret_key(self.secp)

        # Partial refund signature
        public_refund_nonce_sum = PublicKey.from_combination(self.secp, [self.public_refund_nonce,
                                                                         self.foreign_public_refund_nonce])
        self.partial_refund_signature = aggsig.calculate_partial(
            self.secp, refund_excess, self.refund_nonce, self.public_refund_excess, public_refund_nonce_sum,
            self.refund_fee_amount, self.refund_lock_height
        )

    def finalize_range_proof(self):
        assert self.role == Role.BUYER and self.stage == Stage.SIGN, "Incorrect stage"

        proof_builder = TwoPartyBulletProof(self.secp, self.partial_child.key,
                                            self.foreign_partial_commit.to_public_key(self.secp),
                                            self.grin_amount, self.commit)
        proof_builder.fill_round_1(self.t_1, self.t_2)
        proof_builder.fill_round_1(self.foreign_t_1, self.foreign_t_2)
        proof_builder.round_2()
        proof_builder.fill_round_2(self.foreign_tau_x)
        self.range_proof = proof_builder.finalize()

    def build_transactions(self):
        assert self.role == Role.SELLER and self.stage == Stage.LOCK, "Incorrect stage"

        # Check output range proof
        output = Output(OutputFeatures.DEFAULT_OUTPUT, self.commit, self.range_proof)
        assert output.verify(self.secp), "Invalid bulletproof"

        # Build refund tx
        refund_input = Input(OutputFeatures.DEFAULT_OUTPUT, self.commit)

        public_refund_nonce_sum = PublicKey.from_combination(self.secp, [self.public_refund_nonce,
                                                                         self.foreign_public_refund_nonce])

        refund_signature = aggsig.add_partials(
            self.secp, [self.partial_refund_signature, self.foreign_partial_refund_signature], public_refund_nonce_sum
        )
        assert aggsig.verify(self.secp, refund_signature, self.public_refund_excess, self.refund_fee_amount,
                             self.refund_lock_height), "Unable to verify refund signature"

        refund_kernel = Kernel(0, self.refund_fee_amount, self.refund_lock_height, None, None)
        self.refund_tx = Transaction([refund_input], [self.refund_output], [refund_kernel], self.refund_offset)
        refund_kernel.excess = self.refund_tx.sum_commitments(self.secp)
        refund_kernel.excess_signature = refund_signature
        assert self.refund_tx.verify_kernels(self.secp), "Unable to verify refund kernel"

        # Build multisig tx
        public_nonce_sum = PublicKey.from_combination(self.secp, [self.public_nonce, self.foreign_public_nonce])

        signature = aggsig.add_partials(
            self.secp, [self.partial_signature, self.foreign_partial_signature], public_nonce_sum
        )
        assert aggsig.verify(self.secp, signature, self.public_excess, self.fee_amount, self.lock_height), \
            "Unable to verify signature"

        kernel = Kernel(0, self.fee_amount, self.lock_height, None, None)
        self.tx = Transaction(self.inputs, [self.change_output, output], [kernel], self.offset)
        kernel.excess = self.tx.sum_commitments(self.secp)
        kernel.excess_signature = signature
        assert self.tx.verify_kernels(self.secp), "Unable to verify kernel"

        self.swap_nonce = SecretKey.random(self.secp)
        self.public_swap_nonce = self.swap_nonce.to_public_key(self.secp)

    def fill_swap_signatures(self):
        buyer = self.role == Role.BUYER
        assert (buyer and self.stage == Stage.LOCK) or (not buyer and self.stage == Stage.SWAP), "Incorrect stage"

        # Public (total) swap excess
        pos = [self.swap_output.commit, self.secp.commit_value(self.swap_fee_amount)]
        neg = [self.commit, self.secp.commit(0, self.swap_offset)]
        self.public_swap_excess = self.secp.commit_sum(pos, neg).to_public_key(self.secp)

        # Partial swap excess
        swap_blind_sum = BlindSum()
        swap_blind_sum.sub_child_key(self.partial_child)
        if buyer:
            swap_blind_sum.add_child_key(self.swap_child)
            swap_blind_sum.sub_blinding_factor(self.swap_offset)
        swap_excess = self.wallet.chain.blind_sum(swap_blind_sum).to_secret_key(self.secp)

        # Nonce sum
        public_swap_nonce_sum = PublicKey.from_combination(self.secp, [self.public_swap_nonce,
                                                                       self.foreign_public_swap_nonce])

        if not buyer:
            # Verify that partial signature is valid with swap secret
            pos = [self.swap_output.commit]
            neg = [self.foreign_partial_commit, self.secp.commit(0, self.swap_offset),
                   self.secp.commit_value(self.grin_amount-self.swap_fee_amount)]
            foreign_public_partial_swap_excess = self.secp.commit_sum(pos, neg).to_public_key(self.secp)

            assert aggsig.verify_partial_adaptor(
                self.secp, self.foreign_partial_swap_adaptor, foreign_public_partial_swap_excess, self.public_lock,
                self.public_swap_excess, public_swap_nonce_sum, self.swap_fee_amount, self.swap_lock_height
            ), "Partial swap signature not valid"

        # Partial swap signature
        self.partial_swap_signature = aggsig.calculate_partial(
            self.secp, swap_excess, self.swap_nonce, self.public_swap_excess, public_swap_nonce_sum,
            self.swap_fee_amount, self.swap_lock_height
        )

        if buyer:
            self.partial_swap_adaptor = aggsig.calculate_partial_adaptor(
                self.secp, swap_excess, self.swap_nonce, self.secret_lock, self.public_swap_excess,
                public_swap_nonce_sum, self.swap_fee_amount, self.swap_lock_height
            )

    def prepare_swap(self):
        assert self.role == Role.BUYER and self.stage == Stage.LOCK, "Incorrect stage"

        self.swap_nonce = SecretKey.random(self.secp)
        self.public_swap_nonce = self.swap_nonce.to_public_key(self.secp)
        self.swap_fee_amount = tx_fee(1, 1, MILLI_GRIN_UNIT)
        self.swap_lock_height = self.lock_height+1
        self.swap_child, self.swap_entry = self.wallet.create_output(self.grin_amount-self.swap_fee_amount)
        self.wallet.save()
        self.swap_offset = BlindingFactor.from_secret_key(SecretKey.random(self.secp))
        self.swap_output = self.wallet.entry_to_output(self.swap_entry)

        self.fill_swap_signatures()

    def finalize_swap(self):
        seller = self.role == Role.SELLER
        assert (seller and self.stage == Stage.DONE) or (not seller and self.stage == Stage.SWAP), "Incorrect stage"

        if seller:
            self.secret_lock = self.foreign_partial_swap_adaptor.scalar(self.secp).add(
                self.secp, self.foreign_partial_swap_signature.scalar(self.secp).negate(self.secp)
            )

            public_lock = self.secret_lock.to_public_key(self.secp)
            assert self.public_lock == public_lock, "Invalid secret lock, this should never happen"

            if self.is_bitcoin_swap():
                tx = BitcoinTransaction(2, [], [], int(time()))
                input_script = self.generate_btc_script()
                for output_point in self.btc_output_points:
                    tx.add_input(BitcoinInput(output_point.txid, output_point.index, input_script, bytearray(), None))
                output = BitcoinOutput(1, Script.p2(Address.from_base58check(self.swap_receive_address.encode())))
                tx.add_output(output)
                tx_size = len(tx.to_bytearray()) + 270 * len(self.btc_output_points)  # estimate total tx size
                fee = 2 * tx_size  # 2 sat/B
                output.value = self.swap_amount - fee
                for i in range(len(tx.inputs)):
                    signature_a = tx.raw_signature(self.secp, i, self.swap_cosign)
                    signature_b = tx.raw_signature(self.secp, i, self.secret_lock)
                    prev_script = self.generate_btc_script()

                    script_sig = bytearray()
                    script_sig.append(OP_FALSE)
                    script_sig.extend(script_write_bytes(len(signature_a)))
                    script_sig.extend(signature_a)
                    script_sig.extend(script_write_bytes(len(signature_b)))
                    script_sig.extend(signature_b)
                    script_sig.append(OP_FALSE)
                    script_sig.extend(script_write_bytes(len(prev_script)))
                    script_sig.extend(prev_script)
                    tx.inputs[i].script_sig = script_sig
                self.claim = hexlify(tx.to_bytearray())

            if self.is_ether_swap():
                self.claim = self.secp.sign_recoverable(self.secret_lock, bytearray([0] * 32))
        else:
            swap_input = Input(OutputFeatures.DEFAULT_OUTPUT, self.commit)
            public_swap_nonce_sum = PublicKey.from_combination(self.secp, [self.public_swap_nonce,
                                                                           self.foreign_public_swap_nonce])

            swap_signature = aggsig.add_partials(
                self.secp, [self.partial_swap_signature, self.foreign_partial_swap_signature], public_swap_nonce_sum
            )

            assert aggsig.verify(self.secp, swap_signature, self.public_swap_excess, self.swap_fee_amount,
                                 self.swap_lock_height), "Unable to verify swap signature"

            swap_kernel = Kernel(0, self.swap_fee_amount, self.swap_lock_height, None, None)
            self.swap_tx = Transaction([swap_input], [self.swap_output], [swap_kernel], self.swap_offset)
            swap_kernel.excess = self.swap_tx.sum_commitments(self.secp)
            swap_kernel.excess_signature = swap_signature
            assert self.swap_tx.verify_kernels(self.secp), "Unable to verify swap kernel"

    def load(self, dct=None):
        seller = self.role == Role.SELLER
        buyer = not seller

        from_file = dct is None
        if from_file:
            f = open(absolute(self.swap_file), "r")
            dct = json.loads(f.read())
            f.close()

        self.stage = Stage(dct['stage'])
        if self.wallet is None:
            self.wallet = Wallet.open(self.secp, dct['wallet'])
        self.time_start = int(dct['time_start'])
        self.grin_amount = int(dct['grin_amount'])
        self.swap_currency = dct['swap_currency']
        self.swap_amount = int(dct['swap_amount'])
        if seller or self.is_ether_swap():
            self.swap_receive_address = dct['swap_receive_address']
        self.lock_height = int(dct['lock_height'])
        self.refund_lock_height = int(dct['refund_lock_height'])
        self.inputs = [Input.from_dict(self.secp, x, True) for x in dct['inputs']]
        self.fee_amount = int(dct['fee_amount'])
        self.refund_fee_amount = int(dct['refund_fee_amount'])
        self.change_output = Output.from_dict(self.secp, dct['change_output'], True)
        if from_file:
            self.partial_entry = self.wallet.get_output(dct['partial_entry'])
            self.partial_child = self.wallet.derive_from_entry(self.partial_entry)
        self.partial_commit = self.wallet.commit_with_child_key(0, self.partial_child)
        self.offset = BlindingFactor.from_hex(dct['offset'].encode())
        self.refund_output = Output.from_dict(self.secp, dct['refund_output'], True)
        self.refund_offset = BlindingFactor.from_hex(dct['refund_offset'].encode())
        if from_file:
            self.nonce = SecretKey.from_hex(self.secp, dct['nonce'].encode())
            self.refund_nonce = SecretKey.from_hex(self.secp, dct['refund_nonce'].encode())
        self.public_nonce = self.nonce.to_public_key(self.secp)
        self.public_refund_nonce = self.refund_nonce.to_public_key(self.secp)

        if seller:
            if self.is_bitcoin_swap():
                self.swap_cosign = SecretKey.from_hex(self.secp, dct['swap_cosign'].encode())
            self.input_entries = [self.wallet.get_output(x) for x in dct['input_entries']]
            self.input_amount = sum(x.value for x in self.input_entries)
            self.change_amount = self.input_amount - self.grin_amount - self.fee_amount
            self.change_entry = self.wallet.get_output(dct['change_entry'])
            self.change_child = self.wallet.derive_from_entry(self.change_entry)
            self.refund_entry = self.wallet.get_output(dct['refund_entry'])
            self.refund_child = self.wallet.derive_from_entry(self.refund_entry)
        else:
            if from_file:
                self.secret_lock = SecretKey.from_hex(self.secp, dct['secret_lock'].encode())
                if self.is_bitcoin_swap():
                    self.btc_refund_key = SecretKey.from_hex(self.secp, dct['btc_refund_key'].encode())

        if self.is_bitcoin_swap():
            self.public_swap_cosign = self.swap_cosign.to_public_key(self.secp) if seller else \
                PublicKey.from_hex(self.secp, dct['public_swap_cosign'].encode())

        if self.stage >= Stage.SIGN or buyer:
            self.foreign_partial_commit = Commitment.from_hex(self.secp, dct['foreign_partial_commit'].encode())
            self.foreign_public_nonce = PublicKey.from_hex(self.secp, dct['foreign_public_nonce'].encode())
            self.foreign_public_refund_nonce = PublicKey.from_hex(self.secp,
                                                                  dct['foreign_public_refund_nonce'].encode())
            if from_file:
                self.public_lock = PublicKey.from_hex(self.secp, dct['public_lock'].encode())
                if self.is_bitcoin_swap():
                    self.public_btc_refund_key = self.btc_refund_key.to_public_key(self.secp) if buyer else \
                        PublicKey.from_hex(self.secp, dct['public_btc_refund_key'].encode())

            if self.is_ether_swap():
                self.eth_address_lock = ethereum_address(self.secp, self.public_lock).decode()

            self.commit = self.secp.commit_sum([self.foreign_partial_commit,
                                                self.wallet.commit(self.partial_entry)], []) if not from_file else \
                Commitment.from_hex(self.secp, dct['commit'].encode())

        if self.stage >= Stage.SIGN or (buyer and from_file):
            self.public_excess = PublicKey.from_hex(self.secp, dct['public_excess'].encode())
            self.public_refund_excess = PublicKey.from_hex(self.secp, dct['public_refund_excess'].encode())
            if self.is_bitcoin_swap():
                self.btc_lock_time = int(dct['btc_lock_time'])
                self.btc_lock_address = Address.from_base58check(dct['btc_lock_address'].encode())
            if self.is_ether_swap():
                self.eth_contract_address = dct['eth_contract_address']
            self.partial_signature = Signature.from_hex(dct['partial_signature'].encode())
            self.partial_refund_signature = Signature.from_hex(dct['partial_refund_signature'].encode())
            self.t_1 = PublicKey.from_hex(self.secp, dct['t_1'].encode())
            self.t_2 = PublicKey.from_hex(self.secp, dct['t_2'].encode())

        if self.stage >= Stage.SIGN:
            self.foreign_t_1 = PublicKey.from_hex(self.secp, dct['foreign_t_1'].encode())
            self.foreign_t_2 = PublicKey.from_hex(self.secp, dct['foreign_t_2'].encode())
            if seller:
                self.tau_x = SecretKey.from_hex(self.secp, dct['tau_x'].encode())
                self.foreign_partial_signature = Signature.from_hex(dct['foreign_partial_signature'].encode())
                self.foreign_partial_refund_signature = Signature.from_hex(
                    dct['foreign_partial_refund_signature'].encode())
                if self.is_bitcoin_swap():
                    self.btc_output_points = [OutputPoint.from_hex(x.encode()) for x in dct['btc_output_points']]
            else:
                self.foreign_tau_x = SecretKey.from_hex(self.secp, dct['foreign_tau_x'].encode())

        if self.stage >= Stage.LOCK or (self.stage == Stage.SIGN and buyer):
            self.range_proof = RangeProof.from_hex(dct['range_proof'].encode())

        if self.stage >= Stage.LOCK:
            self.tx_height = dct['tx_height']
            self.swap_nonce = SecretKey.from_hex(self.secp, dct['swap_nonce'].encode())
            self.public_swap_nonce = self.swap_nonce.to_public_key(self.secp)
            if buyer:
                self.swap_entry = self.wallet.get_output(dct['swap_entry'])
                self.swap_child = self.wallet.derive_from_entry(self.swap_entry)
                self.partial_swap_adaptor = Signature.from_hex(dct['partial_swap_adaptor'].encode())

        if (buyer and self.stage >= Stage.LOCK) or (seller and self.stage >= Stage.SWAP):
            self.foreign_public_swap_nonce = PublicKey.from_hex(self.secp, dct['foreign_public_swap_nonce'].encode())
            self.swap_fee_amount = int(dct['swap_fee_amount'])
            self.swap_lock_height = int(dct['swap_lock_height'])
            self.swap_output = Output.from_dict(self.secp, dct['swap_output'], True)
            self.swap_offset = BlindingFactor.from_hex(dct['swap_offset'].encode())
            self.public_swap_excess = PublicKey.from_hex(self.secp, dct['public_swap_excess'].encode())
            self.partial_swap_signature = Signature.from_hex(dct['partial_swap_signature'].encode())

        if seller and self.stage >= Stage.SWAP:
            self.foreign_partial_swap_adaptor = Signature.from_hex(
                dct['foreign_partial_swap_adaptor'].encode()
            )

    def save(self):
        f = open(absolute(self.swap_file), "w")
        dct = self.to_dict(True)
        f.write(json.dumps(dct, indent=2))
        f.close()

    def to_dict(self, all: bool):
        seller = self.role == Role.SELLER
        buyer = not seller

        dct = {
            "id": str(self.id),
            "stage": self.stage.value
        }

        if all:
            dct.update({
                "wallet": self.wallet.dir_in,
                "time_start": self.time_start
            })
        else:
            dct.update({"target": "buyer" if self.role == Role.SELLER else "seller"})

        if all or (self.stage == Stage.INIT and seller):
            dct.update({
                "grin_amount": self.grin_amount,
                "swap_currency": self.swap_currency,
                "swap_amount": self.swap_amount,
                "lock_height": self.lock_height,
                "refund_lock_height": self.refund_lock_height,
                "inputs": [x.to_dict(self.secp, True) for x in self.inputs],
                "fee_amount": self.fee_amount,
                "refund_fee_amount": self.refund_fee_amount,
                "change_output": self.change_output.to_dict(self.secp, True),
                "offset": self.offset.to_hex().decode(),
                "refund_output": self.refund_output.to_dict(self.secp, True),
                "refund_offset": self.refund_offset.to_hex().decode()
            })

            if (all and seller) or self.is_ether_swap():
                dct.update({
                    "swap_receive_address": self.swap_receive_address,
                })

        if not all and self.stage == Stage.INIT:
            dct.update({
                "partial_commit": self.partial_commit.to_hex(self.secp).decode(),
                "public_nonce": self.public_nonce.to_hex(self.secp).decode(),
                "public_refund_nonce": self.public_refund_nonce.to_hex(self.secp).decode()
            })

        if all:
            dct.update({
                "partial_entry": self.partial_entry.key_id.to_hex().decode(),
                "nonce": self.nonce.to_hex().decode(),
                "refund_nonce": self.refund_nonce.to_hex().decode()
            })
            if seller:
                dct.update({
                    "input_entries": [x.key_id.to_hex().decode() for x in self.input_entries],
                    "change_entry": self.change_entry.key_id.to_hex().decode(),
                    "refund_entry": self.refund_entry.key_id.to_hex().decode()
                })
                if self.is_bitcoin_swap():
                    dct.update({
                        "swap_cosign": self.swap_cosign.to_hex().decode()
                    })
            else:
                dct.update({
                    "secret_lock": self.secret_lock.to_hex().decode()
                })
                if self.is_bitcoin_swap():
                    dct.update({
                        "btc_refund_key": self.btc_refund_key.to_hex().decode()
                    })

            if self.stage >= Stage.SIGN or buyer:
                dct.update({
                    "public_excess": self.public_excess.to_hex(self.secp).decode(),
                    "public_refund_excess": self.public_refund_excess.to_hex(self.secp).decode(),
                    "commit": self.commit.to_hex(self.secp).decode(),
                    "foreign_partial_commit": self.foreign_partial_commit.to_hex(self.secp).decode(),
                    "foreign_public_nonce": self.foreign_public_nonce.to_hex(self.secp).decode(),
                    "foreign_public_refund_nonce": self.foreign_public_refund_nonce.to_hex(self.secp).decode()
                })
                if self.is_bitcoin_swap():
                    dct.update({
                        "btc_lock_address": self.btc_lock_address.to_base58check().decode()
                    })

            if self.stage >= Stage.SIGN:
                if seller:
                    dct.update({
                        "foreign_partial_signature": self.foreign_partial_signature.to_hex().decode(),
                        "foreign_partial_refund_signature": self.foreign_partial_refund_signature.to_hex().decode()
                    })
                    if self.is_bitcoin_swap():
                        dct.update({
                            "btc_output_points": [x.to_hex().decode() for x in self.btc_output_points]
                        })
                else:
                    dct.update({
                        "foreign_tau_x": self.foreign_tau_x.to_hex().decode()
                    })
                dct.update({
                    "foreign_t_1": self.foreign_t_1.to_hex(self.secp).decode(),
                    "foreign_t_2": self.foreign_t_2.to_hex(self.secp).decode()
                })

        if self.is_bitcoin_swap():
            if (all and buyer) or (not all and self.stage == Stage.INIT and seller):
                dct.update({
                    "public_swap_cosign": self.public_swap_cosign.to_hex(self.secp).decode()
                })

            if (all and self.stage >= Stage.SIGN and seller) or (not all and self.stage == Stage.INIT and buyer):
                dct.update({
                    "public_btc_refund_key": self.public_btc_refund_key.to_hex(self.secp).decode(),
                })

        if (all and (self.stage >= Stage.SIGN or buyer)) or (self.stage == Stage.INIT and buyer):
            dct.update({
                "public_lock": self.public_lock.to_hex(self.secp).decode(),
                "partial_signature": self.partial_signature.to_hex().decode(),
                "partial_refund_signature": self.partial_refund_signature.to_hex().decode()
            })

            if self.is_bitcoin_swap():
                dct.update({
                    "btc_lock_time": self.btc_lock_time
                })
            if self.is_ether_swap():
                dct.update({
                    "eth_contract_address": self.eth_contract_address
                })

        if (all and (self.stage >= Stage.SIGN or buyer)) or (self.stage == Stage.INIT and buyer) or \
                (self.stage == Stage.SIGN and seller):
            dct.update({
                "t_1": self.t_1.to_hex(self.secp).decode(),
                "t_2": self.t_2.to_hex(self.secp).decode()
            })

        if seller and ((all and self.stage >= Stage.SIGN) or self.stage == Stage.SIGN):
            dct.update({
                "tau_x": self.tau_x.to_hex().decode()
            })

        if (all and ((self.stage >= Stage.SIGN and buyer) or (self.stage >= Stage.LOCK and seller))) or \
                (self.stage == Stage.SIGN and buyer):
            dct.update({
                "range_proof": self.range_proof.to_hex().decode()
            })

        if (all and self.stage >= Stage.LOCK) or (self.stage == Stage.LOCK and seller):
            dct.update({
                "tx_height": self.tx_height
            })

        if all and self.stage >= Stage.LOCK:
            dct.update({
                "swap_nonce": self.swap_nonce.to_hex().decode()
            })

        if (all and self.stage >= Stage.LOCK) or self.stage == Stage.LOCK:
            dct.update({
                "public_swap_nonce": self.public_swap_nonce.to_hex(self.secp).decode()
            })

        if all and ((self.stage >= Stage.LOCK and buyer) or (self.stage >= Stage.SWAP and seller)):
            dct.update({
                "foreign_public_swap_nonce": self.foreign_public_swap_nonce.to_hex(self.secp).decode(),
                "public_swap_excess": self.public_swap_excess.to_hex(self.secp).decode(),
            })

        if all and self.stage >= Stage.LOCK and buyer:
            dct.update({
                "swap_entry": self.swap_entry.key_id.to_hex().decode()
            })

        if (all and ((self.stage >= Stage.LOCK and buyer) or (self.stage >= Stage.SWAP and seller))) or \
                (self.stage == Stage.LOCK and buyer):
            dct.update({
                "swap_fee_amount": self.swap_fee_amount,
                "swap_lock_height": self.swap_lock_height,
                "swap_output": self.swap_output.to_dict(self.secp, True),
                "swap_offset": self.swap_offset.to_hex().decode()
            })

        if buyer and ((all and self.stage >= Stage.LOCK) or self.stage == Stage.LOCK):
            dct.update({
                "partial_swap_adaptor": self.partial_swap_adaptor.to_hex().decode()
            })

        if all and self.stage >= Stage.SWAP and seller:
            dct.update({
                "foreign_partial_swap_adaptor": self.foreign_partial_swap_adaptor.to_hex().decode()
            })

        if (all and ((self.stage >= Stage.LOCK and buyer) or (self.stage >= Stage.SWAP and seller))) or \
                self.stage == Stage.SWAP:
            dct.update({
                "partial_swap_signature": self.partial_swap_signature.to_hex().decode()
            })

        if all and ((self.stage >= Stage.SWAP and buyer) or (self.stage >= Stage.DONE and seller)):
            dct.update({
                "foreign_partial_swap_signature": self.foreign_partial_swap_signature.to_hex().decode()
            })

        return dct

    def receive(self, dct: dict):
        if self.stage is None:
            if self.role == Role.BUYER:
                dct['time_start'] = int(time())

                self.wallet = Wallet.open(self.secp, dct['wallet'])

                # Add 'foreign_' prefix to some keys
                dct.update({
                    "foreign_partial_commit": dct['partial_commit'],
                    "foreign_public_nonce": dct['public_nonce'],
                    "foreign_public_refund_nonce": dct['public_refund_nonce']
                })

                dct.pop("partial_commit", None)
                dct.pop("public_nonce", None)
                dct.pop("public_refund_nonce", None)

                # Partial multisig output
                self.partial_child, self.partial_entry = self.wallet.create_output(dct['grin_amount'])
                self.partial_entry.mark_locked()

                self.nonce = SecretKey.random(self.secp)
                self.refund_nonce = SecretKey.random(self.secp)

                self.secret_lock = SecretKey.random(self.secp)
                self.public_lock = self.secret_lock.to_public_key(self.secp)

                if dct['swap_currency'] == "BTC":
                    self.btc_lock_time = int(time() + 24 * 60 * 60)
                    self.btc_refund_key = SecretKey.random(self.secp)
                    self.public_btc_refund_key = self.btc_refund_key.to_public_key(self.secp)

                self.load(dct)
                if self.is_bitcoin_swap():
                    self.btc_lock_address = self.calculate_btc_lock_address()
                self.wallet.save()
            else:
                raise Exception("This stage doesn't expect an input file")
        elif self.stage == Stage.INIT:
            self.stage = Stage.SIGN
            self.foreign_t_1 = PublicKey.from_hex(self.secp, dct['t_1'].encode())
            self.foreign_t_2 = PublicKey.from_hex(self.secp, dct['t_2'].encode())
            if self.role == Role.SELLER:
                self.foreign_partial_commit = Commitment.from_hex(self.secp, dct['partial_commit'].encode())
                self.foreign_public_nonce = PublicKey.from_hex(self.secp, dct['public_nonce'].encode())
                self.foreign_public_refund_nonce = PublicKey.from_hex(self.secp, dct['public_refund_nonce'].encode())
                self.public_lock = PublicKey.from_hex(self.secp, dct['public_lock'].encode())
                if self.is_bitcoin_swap():
                    self.btc_lock_time = int(dct['btc_lock_time'])
                    self.public_btc_refund_key = PublicKey.from_hex(self.secp, dct['public_btc_refund_key'])
                    self.btc_lock_address = self.calculate_btc_lock_address()
                if self.is_ether_swap():
                    self.eth_address_lock = ethereum_address(self.secp, self.public_lock).decode()
                    self.eth_contract_address = dct['eth_contract_address']
                self.commit = self.secp.commit_sum([self.foreign_partial_commit,
                                                    self.wallet.commit(self.partial_entry)], [])
                self.foreign_partial_signature = Signature.from_hex(dct['partial_signature'].encode())
                self.foreign_partial_refund_signature = Signature.from_hex(dct['partial_refund_signature'].encode())
            else:
                self.foreign_tau_x = SecretKey.from_hex(self.secp, dct['tau_x'].encode())
        elif self.stage == Stage.SIGN:
            self.stage = Stage.LOCK
            if self.role == Role.SELLER:
                self.range_proof = RangeProof.from_hex(dct['range_proof'].encode())
            else:
                self.tx_height = dct['tx_height']
                self.foreign_public_swap_nonce = PublicKey.from_hex(self.secp, dct['public_swap_nonce'].encode())
        elif self.stage == Stage.LOCK:
            self.stage = Stage.SWAP
            if self.role == Role.SELLER:
                self.foreign_public_swap_nonce = PublicKey.from_hex(self.secp, dct['public_swap_nonce'].encode())
                self.swap_fee_amount = int(dct['swap_fee_amount'])
                self.swap_lock_height = int(dct['swap_lock_height'])
                self.swap_output = Output.from_dict(self.secp, dct['swap_output'], True)
                self.swap_offset = BlindingFactor.from_hex(dct['swap_offset'].encode())
                self.foreign_partial_swap_adaptor = Signature.from_hex(dct['partial_swap_adaptor'])
            else:
                self.foreign_partial_swap_signature = Signature.from_hex(dct['partial_swap_signature'])
        elif self.stage == Stage.SWAP:
            self.stage = Stage.DONE
            if self.role == Role.SELLER:
                self.foreign_partial_swap_signature = Signature.from_hex(dct['partial_swap_signature'])
        else:
            raise Exception("Invalid stage")

    def send(self) -> dict:
        return self.to_dict(False)

    def short_id(self) -> str:
        return str(self.id)[:8]

    def generate_btc_script(self) -> bytearray:
        assert self.is_bitcoin_swap()
        return Script.multisig_refund(
            self.secp, self.public_swap_cosign, self.public_lock, self.public_btc_refund_key, self.btc_lock_time
        )

    def calculate_btc_lock_address(self) -> Address:
        return Address.from_script(self.generate_btc_script(), False)

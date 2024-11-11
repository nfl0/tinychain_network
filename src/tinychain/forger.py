import asyncio
import logging
import blake3
import json
import time
from aiohttp import web
from block import BlockHeader, Block, Signature
from transaction import Transaction
from validation_engine import ValidationEngine
from vm import TinyVMEngine
from wallet import Wallet
from parameters import ROUND_TIMEOUT
from peer_communication import broadcast_block_header, broadcast_transaction

class Forger:
    def __init__(self, transactionpool, storage_engine, validation_engine, wallet):
        self.transactionpool = transactionpool
        self.storage_engine = storage_engine
        self.validation_engine = validation_engine

        self.wallet = wallet
        self.validator = self.proposer = self.wallet.get_address()
        self.sign = self.wallet.sign_message

        self.in_memory_blocks = {}
        self.in_memory_block_headers = {}
        self.current_proposer_index = 0

        self.lock = asyncio.Lock()

    @staticmethod
    def generate_block_hash(merkle_root, timestamp, state_root, previous_block_hash, chain_id):
        values = [merkle_root, str(timestamp), str(state_root), previous_block_hash, chain_id]
        concatenated_string = f"{''.join(values)}".encode()
        return blake3.blake3(concatenated_string).hexdigest()

    @staticmethod
    def compute_merkle_root(transaction_hashes):
        if len(transaction_hashes) == 0:
            return blake3.blake3(b'').hexdigest()

        while len(transaction_hashes) > 1:
            if len(transaction_hashes) % 2 != 0:
                transaction_hashes.append(transaction_hashes[-1])

            if isinstance(transaction_hashes[0], bytes):
                transaction_hashes = [blake3.blake3(transaction_hashes[i] + transaction_hashes[i + 1]).digest() for i in range(0, len(transaction_hashes), 2)]
            elif isinstance(transaction_hashes[0], str):
                transaction_hashes = [blake3.blake3(transaction_hashes[i].encode() + transaction_hashes[i + 1].encode()).digest() for i in range(0, len(transaction_hashes), 2)]
            else:
                raise TypeError("Unsupported data type in transaction_hashes")
            
        if isinstance(transaction_hashes[0], str):
            transaction_hashes[0] = transaction_hashes[0].encode('utf-8')

        return blake3.blake3(transaction_hashes[0]).hexdigest()

    def fetch_current_validator_set(self):
        staking_contract_state = self.storage_engine.fetch_contract_state("7374616b696e67")
        if staking_contract_state:
            return sorted(staking_contract_state.keys(), key=lambda k: staking_contract_state[k]['index'])
        return []

    def select_proposer(self):
        validator_set = self.fetch_current_validator_set()
        if validator_set:
            proposer = validator_set[self.current_proposer_index]
            logging.info(f"Selected proposer: {proposer} (index: {self.current_proposer_index})")
            self.current_proposer_index = (self.current_proposer_index + 1) % len(validator_set)
            return proposer
        logging.error("No validators found in the current validator set")
        return None

    def validate_block(self, block_header):
        if not self.validation_engine.validate_block_header_signatures(block_header):
            return False
        if not self.validation_engine.validate_enough_signatures(block_header, required_signatures=2/3 * len(self.fetch_current_validator_set())):
            return False
        return True

    async def forge_new_block(self):
        logging.info("Starting to forge a new block")
        async with self.lock:
            transactions_to_forge = self.get_transactions_to_forge()

            valid_transactions_to_forge = [t for t in transactions_to_forge if self.validation_engine.validate_transaction(t)]

            previous_block_header = self.storage_engine.fetch_last_block_header()
            previous_block_hash = previous_block_header.block_hash
            height = previous_block_header.height + 1
            current_state = self.storage_engine.fetch_state(previous_block_header.state_root)

            tvm_engine = TinyVMEngine(current_state)

            self.proposer = self.wallet.get_address()
            timestamp = int(time.time())
            state_root, new_state = tvm_engine.exec(valid_transactions_to_forge, self.proposer)
            transaction_hashes = [t.to_dict()['transaction_hash'] for t in valid_transactions_to_forge]
            merkle_root = self.compute_merkle_root(transaction_hashes)
            chain_id = "tinychain"
            block_hash = self.generate_block_hash(merkle_root, timestamp, state_root, previous_block_hash, chain_id)
            signature = self.sign(block_hash)
            validator_index = self.get_validator_index(self.proposer)
            signatures = [Signature(self.proposer, timestamp, signature, validator_index)]

            block_header = self.create_block_header(block_hash, height, timestamp, previous_block_hash, merkle_root, state_root, self.proposer, chain_id, signatures, transaction_hashes)

            block = Block(block_header, valid_transactions_to_forge)

            self.in_memory_blocks[block.header.block_hash] = block
            self.in_memory_block_headers[block.header.block_hash] = block_header

            integrity_check = self.generate_integrity_check(block_header)
            broadcast_block_header(block_header, integrity_check)


    async def replay_block(self, block_header):
        logging.info("Starting to replay a block")
        async with self.lock:
            transactions_to_forge = self.get_transactions_to_forge(block_header)

            valid_transactions_to_forge = [t for t in transactions_to_forge if self.validation_engine.validate_transaction(t)]

            previous_block_header = self.storage_engine.fetch_last_block_header()
            current_state = self.storage_engine.fetch_state(previous_block_header.state_root)

            tvm_engine = TinyVMEngine(current_state)

            state_root, new_state = tvm_engine.exec(valid_transactions_to_forge, block_header.proposer)
            if state_root == block_header.state_root:
                transaction_hashes = [t.to_dict()['transaction_hash'] for t in block_header.transactions]
                computed_merkle_root = self.compute_merkle_root(transaction_hashes)
                if computed_merkle_root == block_header.merkle_root:
                    signature = self.wallet.sign_message(block_header.block_hash)
                    validator_index = self.get_validator_index(self.validator)
                    signatures = block_header.signatures
                    logging.info("Block signatures: %s", signatures)

                    if isinstance(signatures, list) and all(isinstance(sig, Signature) for sig in signatures):
                        signatures.append(Signature(self.validator, int(time.time()), signature, validator_index))
                    else:
                        signatures = [Signature.from_dict(sig) for sig in signatures]
                        signatures.append(Signature(self.validator, int(time.time()), signature, validator_index))

                    block_header = self.create_block_header(block_header.block_hash, block_header.height, block_header.timestamp, block_header.previous_block_hash, block_header.merkle_root, block_header.state_root, block_header.proposer, block_header.chain_id, signatures, block_header.transaction_hashes)
                    logging.info("Replay successful for block %s", block_header.block_hash)
                else:
                    logging.error("Replay failed for block %s (Merkle root mismatch)", block_header.block_hash)
                    return False
            else:
                logging.error("Replay failed for block %s (State root mismatch)", block_header.block_hash)
                return False

            block = Block(block_header, valid_transactions_to_forge)

            self.in_memory_blocks[block.header.block_hash] = block
            self.in_memory_block_headers[block.header.block_hash] = block_header

            integrity_check = self.generate_integrity_check(block_header)
            broadcast_block_header(block_header, integrity_check)

            if block.header.has_enough_signatures(required_signatures=2/3 * len(self.fetch_current_validator_set())):
                self.store_block_procedure(block, new_state)
                return True
            else:
                del self.in_memory_blocks[block.header.block_hash]
                del self.in_memory_block_headers[block.header.block_hash]
                return False

    def commit_genesis_block(self):
        with open('genesis.json', 'r') as f:
            genesis_data = json.load(f)

        genesis_addresses = genesis_data['genesis_addresses']
        staking_contract_address = genesis_data['staking_contract_address']
        genesis_timestamp = genesis_data['genesis_timestamp']

        current_time = int(time.time())
        if current_time > genesis_timestamp + 3:
            logging.error("Node has missed the network launch")
            exit(1)
        elif current_time < genesis_timestamp - 3:
            while current_time < genesis_timestamp - 3:
                remaining_time = genesis_timestamp - current_time
                logging.info(f"Waiting for the genesis timestamp... {remaining_time} seconds remaining")
                time.sleep(2)
                current_time = int(time.time())

        genesis_transactions = [
            Transaction("genesis", genesis_addresses[0], 10000*TINYCOIN, 120, 0, "consensus", ""),
            Transaction(genesis_addresses[0], staking_contract_address, 1000*TINYCOIN, 110, 0, "genesis_signature_0", "stake"),
            Transaction("genesis", genesis_addresses[1], 10000*TINYCOIN, 100, 1, "consensus", ""),
            Transaction(genesis_addresses[1], staking_contract_address, 1000*TINYCOIN, 90, 0, "genesis_signature_1", "stake"),
            Transaction("genesis", genesis_addresses[2], 10000*TINYCOIN, 80, 2, "consensus", ""),
            Transaction(genesis_addresses[2], staking_contract_address, 1000*TINYCOIN, 70, 0, "genesis_signature_2", "stake"),
            Transaction("genesis", genesis_addresses[3], 10000*TINYCOIN, 60, 3, "consensus", ""),
            Transaction(genesis_addresses[3], staking_contract_address, 1000*TINYCOIN, 50, 0, "genesis_signature_3", "stake"),
            Transaction("genesis", genesis_addresses[4], 10000*TINYCOIN, 40, 4, "consensus", ""),
            Transaction(genesis_addresses[4], staking_contract_address, 1000*TINYCOIN, 30, 0, "genesis_signature_4", "stake"),
            Transaction("genesis", genesis_addresses[5], 10000*TINYCOIN, 20, 5, "consensus", ""),
            Transaction(genesis_addresses[5], staking_contract_address, 1000*TINYCOIN, 10, 0, "genesis_signature_5", "stake")
        ]
        for transaction in genesis_transactions:
            self.transactionpool.add_transaction(transaction)

        logging.info("Starting to forge the genesis block")
        transactions_to_forge = self.get_transactions_to_forge()

        height = 0
        current_state = {}

        tvm_engine = TinyVMEngine(current_state)

        self.proposer = "genesis"
        timestamp = genesis_timestamp
        state_root, new_state = tvm_engine.exec(transactions_to_forge, self.proposer)
        transaction_hashes = [t.to_dict()['transaction_hash'] for t in transactions_to_forge]
        merkle_root = self.compute_merkle_root(transaction_hashes)
        previous_block_hash = "00000000"
        chain_id = "tinychain"
        block_hash = self.generate_block_hash(merkle_root, timestamp, state_root, previous_block_hash, chain_id)
        signature = "genesis_signature"
        validator_index = -1
        signatures = [Signature(self.proposer, timestamp, signature, validator_index)]

        block_header = self.create_block_header(block_hash, height, timestamp, previous_block_hash, merkle_root, state_root, self.proposer, chain_id, signatures, transaction_hashes)

        block = Block(block_header, transactions_to_forge)

        self.store_block_procedure(block, new_state)
        return True

    def get_transactions_to_forge(self, block_header=None):
        transactions_to_forge = []
        if block_header:
            for transaction_hash in block_header.transaction_hashes:
                transaction = self.transactionpool.get_transaction_by_hash(transaction_hash)
                if transaction is not None:
                    transactions_to_forge.append(transaction)
                else:
                    logging.info(f"Transaction {transaction_hash} not found in pool, requesting transaction from peers...")
        else:
            transactions_to_forge = self.transactionpool.get_transactions()
        return transactions_to_forge

    def create_block_header(self, block_hash, height, timestamp, previous_block_hash, merkle_root, state_root, proposer, chain_id, signatures, transaction_hashes):
        return BlockHeader(
            block_hash,
            height,
            timestamp,
            previous_block_hash,
            merkle_root,
            state_root,
            proposer,
            chain_id,
            signatures,
            transaction_hashes
        )

    def store_block_procedure(self, block, new_state):
        logging.info("Storing block with hash: %s", block.header.block_hash)
        self.storage_engine.store_block(block)
        self.storage_engine.store_block_header(block.header)
        self.storage_engine.store_state(block.header.state_root, new_state)

    def has_enough_signatures(self, block_header):
        required_signatures = 2/3 * len(self.fetch_current_validator_set())
        return block_header.has_enough_signatures(required_signatures)

    def get_validator_index(self, validator_address):
        staking_contract_state = self.storage_engine.fetch_contract_state("7374616b696e67")
        if staking_contract_state and validator_address in staking_contract_state:
            return staking_contract_state[validator_address]['index']
        return -1

    async def check_round_robin_result(self):
        while True:
            logging.info("******************")
            logging.info("CHECKING ROUND ROBIN RESULT")
            logging.info("******************")
            await asyncio.sleep(ROUND_TIMEOUT)
            previous_block_header = self.storage_engine.fetch_last_block_header()
            if previous_block_header:
                current_time = int(time.time())
                if current_time >= previous_block_header.timestamp + ROUND_TIMEOUT:
                    proposer = self.select_proposer()
                    logging.info("******************")
                    logging.info("PROPOSER RESULT: " + proposer)
                    logging.info("******************")
                    if proposer == self.wallet.get_address():
                        logging.info("******************")
                        logging.info("forge_new_block")
                        logging.info("******************")
                        await self.forge_new_block()
                    else:
                        await self.wait_for_new_block_headers()

    async def wait_for_new_block_headers(self):
        while True:
            await asyncio.sleep(1)
            previous_block_header = self.storage_engine.fetch_last_block_header()
            if previous_block_header:
                current_time = int(time.time())
                if current_time >= previous_block_header.timestamp + ROUND_TIMEOUT:
                    if self.wallet.get_address() == self.select_proposer():
                        await self.forge_new_block()
                    break

    def generate_integrity_check(self, block_header):
        values = [
            block_header.block_hash,
            str(block_header.height),
            str(block_header.timestamp),
            block_header.previous_block_hash,
            block_header.merkle_root,
            block_header.state_root,
            block_header.proposer,
            block_header.chain_id,
            ''.join(block_header.transaction_hashes)
        ]
        concatenated_string = ''.join(values).encode()
        return blake3.blake3(concatenated_string).hexdigest()

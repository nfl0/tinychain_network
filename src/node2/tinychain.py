import asyncio
import logging
import plyvel
import json
from jsonschema import validate
from jsonschema.exceptions import ValidationError
import blake3
import time
from aiohttp import web
from block import BlockHeader, Block, Signature
from transaction import Transaction, transaction_schema
from validation_engine import ValidationEngine
from vm import TinyVMEngine
from wallet import Wallet
from parameters import HTTP_PORT, MAX_TX_POOL, ROUND_TIMEOUT, PEER_DISCOVERY_METHOD, PEER_DISCOVERY_FILE, PEER_DISCOVERY_API
from peer_communication import broadcast_block_header, receive_block_header, broadcast_transaction

TINYCOIN = 1000000000000000000
TINYCHAIN_UNIT = 'tatoshi'

app = web.Application()
    
class TransactionPool:
    def __init__(self, max_size):
        self.transactions = {}
        self.max_size = max_size

    def add_transaction(self, transaction):
        if len(self.transactions) >= self.max_size:
            raise ValueError("Transaction pool is full")
        if len(self.transactions) < self.max_size:
            self.transactions[transaction.transaction_hash] = transaction
    def remove_transaction(self, transaction):
        self.transactions.pop(transaction.transaction_hash, None)
    def get_transactions(self):
        return sorted(self.transactions.values(), key=lambda tx: tx.fee, reverse=True)
    def get_transaction_by_hash(self, hash):
        return self.transactions[hash]
    def is_empty(self):
        return not self.transactions


class Forger:
    def __init__(self, transactionpool, storage_engine, validation_engine, wallet):
        self.transactionpool = transactionpool
        self.storage_engine = storage_engine
        self.validation_engine = validation_engine

        self.wallet = wallet
        self.validator = self.proposer = self.wallet.get_address()
        self.sign = self.wallet.sign_message

        self.in_memory_blocks = {}  # P7e15
        self.in_memory_block_headers = {}  # P7e15
        self.current_proposer_index = 0  # Initialize the current proposer index

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

    def forge_new_block(self):
        logging.info("Starting to forge a new block")
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

        broadcast_block_header(block_header)


    def replay_block(self, block_header):
        logging.info("Starting to replay a block")
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

        broadcast_block_header(block_header)

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
            logging.info("ROUND RESULT CHECK")
            logging.info("******************")
            await asyncio.sleep(ROUND_TIMEOUT)
            previous_block_header = self.storage_engine.fetch_last_block_header()
            if previous_block_header:
                logging.info("******************")
                logging.info("previous_block_header is TRUE")
                logging.info("******************")
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
                        self.forge_new_block()
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
                        self.forge_new_block()
                    break

class StorageEngine:
    def __init__(self, transactionpool):
        self.transactionpool = transactionpool
        self.db_headers = None
        self.db_blocks = None
        self.db_transactions = None
        self.db_states = None
        self.state = []

    def open_databases(self):
        try:
            self.db_headers = plyvel.DB('headers.db', create_if_missing=True)
            self.db_blocks = plyvel.DB('blocks.db', create_if_missing=True)
            self.db_transactions = plyvel.DB('transactions.db', create_if_missing=True)
            self.db_states = plyvel.DB('states.db', create_if_missing=True)
            headers = self.db_headers.iterator()
            if not any(headers):
                forger.commit_genesis_block()
            else:
                logging.info("Databases already initialized")

        except Exception as err:
            logging.error("Failed to open databases: %s", err)
            raise

    def close_databases(self):
        try:
            if self.db_headers:
                self.db_headers.close()
            if self.db_blocks:
                self.db_blocks.close()
            if self.db_transactions:
                self.db_transactions.close()
            if self.db_states:
                self.db_states.close()
        except Exception as err:
            logging.error("Failed to close databases: %s", err)
            raise

    def store_block(self, block):
        try:
            if block.header.state_root is None:
                logging.error("Block storage skipped: 'NoneType' object has no attribute 'state_root'")
                return
            
            for transaction in block.transactions:
                transaction.confirmed = block.header.height
                self.store_transaction(transaction)
                self.transactionpool.remove_transaction(transaction)
                self.set_nonce_for_account(transaction.sender, transaction.nonce + 1)

            block_data = {
                'block_hash': block.header.block_hash,
                'height': block.header.height,
                'timestamp': block.header.timestamp,
                'merkle_root': block.header.merkle_root,
                'state_root': block.header.state_root,
                'previous_block_hash': block.header.previous_block_hash,
                'proposer': block.header.proposer,
                'chain_id': block.header.chain_id,
                'signatures': [sig.to_dict() for sig in block.header.signatures],
                'transactions': [transaction.to_dict() for transaction in block.transactions]
            }

            self.db_blocks.put(block.header.block_hash.encode(), json.dumps(block_data).encode())

            logging.info("Stored block: %s at height %s", block.header.block_hash, block.header.height)
        except Exception as err:
            logging.error("Failed to store block: %s", err)

    def store_block_header(self, block_header):
        try:
            block_header_data = {
                'block_hash': block_header.block_hash,
                'height': block_header.height,
                'timestamp': block_header.timestamp,
                'merkle_root': block_header.merkle_root,
                'state_root': block_header.state_root,
                'previous_block_hash': block_header.previous_block_hash,
                'proposer': block_header.proposer,
                'chain_id': block_header.chain_id,
                'signatures': [sig.to_dict() for sig in block_header.signatures],
                'transaction_hashes': block_header.transaction_hashes
            }

            self.db_headers.put(str(block_header.height).encode(), json.dumps(block_header_data).encode())

            logging.info("Stored block header: %s at height %s", block_header.block_hash, block_header.height)
        except Exception as err:
            logging.error("Failed to store block header: %s", err)

    def store_transaction(self, transaction):
        try:
            transaction_data = {
                'transaction_hash': transaction.transaction_hash,
                "sender": transaction.sender,
                "receiver": transaction.receiver,
                "amount": transaction.amount,
                "fee": transaction.fee,
                "nonce": transaction.nonce,
                "signature": transaction.signature,
                "memo": transaction.memo,
                "confirmed": transaction.confirmed
            }
            self.db_transactions.put(transaction.transaction_hash.encode(), json.dumps(transaction_data).encode('utf-8'))
            logging.info("Stored transaction: %s", transaction.transaction_hash)
        except Exception as err:
            logging.error("Failed to store transaction: %s", err)

    def store_state(self, state_root, state):
        try:
            self.db_states.put(state_root.encode(), json.dumps(state).encode())
            logging.info("State saved: %s", state_root)
        except Exception as err:
            logging.error("Failed to store state: %s", err)

    def fetch_balance(self, account_address):
        accounts_state = self.fetch_contract_state("6163636f756e7473")
        if accounts_state is not None:
            account_data = accounts_state.get(account_address, None)
            if account_data is not None:
                return account_data.get("balance", 0), account_data.get("nonce", 0)
        return None, None

    def fetch_block(self, block_hash):
        block_data = self.db_blocks.get(block_hash.encode())
        return json.loads(block_data.decode()) if block_data is not None else None

    def fetch_last_block_header(self):
        last_block_header = None
        max_height = -1

        if self.db_headers is not None:
            for header_key, header_data in self.db_headers.iterator(reverse=True):
                block_header = BlockHeader.from_dict(json.loads(header_data.decode()))
                if block_header.height > max_height:
                    max_height = block_header.height
                    last_block_header = block_header
        return last_block_header

    def fetch_transaction(self, transaction_hash):
        transaction_data = self.db_transactions.get(transaction_hash.encode())
        return json.loads(transaction_data.decode()) if transaction_data is not None else None

    def get_nonce_for_account(self, account_address):
        accounts_state = self.fetch_contract_state("6163636f756e7473")
        if accounts_state is not None:
            account_data = accounts_state.get(account_address, None)
            if account_data is not None:
                if isinstance(account_data, dict):
                    balance = account_data.get("balance", 0)
                    nonce = account_data.get("nonce", 0)
                    return balance, nonce
                else:
                    return account_data, 0
        return 0, 0
    
    def set_nonce_for_account(self, account_address, nonce):
        contract_address = "6163636f756e7473"
        accounts_state = self.fetch_contract_state(contract_address)
        if accounts_state is not None:
            if account_address in accounts_state:
                accounts_state[account_address]["nonce"] = nonce
            else:
                accounts_state[account_address] = {"balance": 0, "nonce": nonce}
            self.store_contract_state(contract_address, accounts_state)

    def store_contract_state(self, contract_address, state_data):
        try:
            self.db_states.put(contract_address.encode(), json.dumps(state_data).encode())
            logging.info("Stored contract state for address: %s", contract_address)
        except Exception as err:
            logging.error("Failed to store contract state: %s", err)

    def fetch_state(self, state_root):
        state_data = self.db_states.get(state_root.encode())
        if state_data is not None:
            state = json.loads(state_data.decode())
            return state
        return None

    def fetch_contract_state(self, contract_address):
        if self.fetch_last_block_header() is not None:
            state_root = self.fetch_last_block_header().state_root
        else:
            state_root = "0"
        contract_state_data = self.db_states.get(state_root.encode())
        return json.loads(contract_state_data.decode()).get(contract_address) if contract_state_data is not None else None

    def close(self):
        self.close_databases()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create instances of components
wallet = Wallet()
if not wallet.is_initialized():
    logging.info("Wallet is not initialized. Please run wallet_generator.py to generate a wallet.")
    exit()
transactionpool = TransactionPool(max_size=MAX_TX_POOL)
storage_engine = StorageEngine(transactionpool)
validation_engine = ValidationEngine(storage_engine)
forger = Forger(transactionpool, storage_engine, validation_engine, wallet)


async def send_transaction(request):
    data = await request.json()
    if 'transaction' in data:
        transaction_data = data['transaction']
        try:
            validate(instance=transaction_data, schema=transaction_schema)
            transaction = Transaction(**transaction_data)
            if validation_engine.validate_transaction(transaction):
                if transaction.transaction_hash not in transactionpool.transactions:
                    transactionpool.add_transaction(transaction)
                    sender_uri = request.remote
                    await broadcast_transaction(transaction, sender_uri)
                    return web.json_response({'message': 'Transaction added to the transaction pool', 'transaction_hash': transaction.transaction_hash})
        except ValidationError:
            pass
    return web.json_response({'error': 'Invalid transaction data'}, status=400)

async def get_transaction_by_hash(request):
    transaction_hash = request.match_info['transaction_hash']
    transaction_data = storage_engine.fetch_transaction(transaction_hash)
    if transaction_data is not None:
        return web.json_response(transaction_data)
    return web.json_response({'error': 'Block not found'}, status=404)

async def get_block_by_hash(request):
    block_hash = request.match_info['block_hash']
    block_data = storage_engine.fetch_block(block_hash)
    if block_data is not None:
        return web.json_response(block_data)
    return web.json_response({'error': 'Block not found'}, status=404)

async def get_nonce(request):
    account_address = request.match_info['account_address']
    nonce = storage_engine.get_nonce_for_account(account_address)
    return web.json_response({'nonce': nonce})

def find_proposer_signature(block_header):
    for signature in block_header.signatures:
        if signature.validator_address == block_header.proposer:
            return signature
    return None

app.router.add_post('/send_transaction', send_transaction)
app.router.add_get('/get_block/{block_hash}', get_block_by_hash)
app.router.add_get('/transactions/{transaction_hash}', get_transaction_by_hash)
app.router.add_get('/get_nonce/{account_address}', get_nonce)
app.router.add_post('/receive_block', receive_block_header)

async def cleanup(app):
    await asyncio.gather(*[t for t in asyncio.all_tasks() if t is not asyncio.current_task()])
    storage_engine.close()

app.on_cleanup.append(cleanup)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    app_runner = web.AppRunner(app)
    loop.run_until_complete(app_runner.setup())

    site = web.TCPSite(app_runner, host='0.0.0.0', port=HTTP_PORT)
    loop.run_until_complete(site.start())

    storage_engine.open_databases()

    loop.create_task(forger.check_round_robin_result())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(site.stop())
        loop.run_until_complete(app_runner.cleanup())

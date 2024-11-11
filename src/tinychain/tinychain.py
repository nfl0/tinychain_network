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
from parameters import HTTP_PORT, MAX_TX_POOL, ROUND_TIMEOUT
from peer_communication import broadcast_block_header, broadcast_transaction
from forger import Forger

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

async def receive_block_header(request):
    logging.info("Received block header")
    data = await request.json()
    block_header_data = data.get('block_header')
    integrity_check = data.get('integrity_check')
    if not block_header_data or not integrity_check:
        logging.error("Invalid block header data received")
        return web.json_response({'error': 'Invalid block header data'}, status=400)

    block_header = BlockHeader.from_dict(block_header_data)

    # Verify the integrity check
    if integrity_check != forger.generate_integrity_check(block_header):
        logging.error("Integrity check failed for received block header")
        return web.json_response({'error': 'Integrity check failed'}, status=400)

    # Verify the validity of the block header
    if not validation_engine.validate_block_header(block_header, storage_engine.fetch_last_block_header()):
        logging.error("Invalid block header received")
        return web.json_response({'error': 'Invalid block header'}, status=400)

    # Verify the identity of the proposer through the included signature
    proposer_signature = find_proposer_signature(block_header)
    if proposer_signature is None or not Wallet.verify_signature(block_header.block_hash, proposer_signature.signature_data, proposer_signature.validator_address):
        logging.error("Invalid proposer signature received")
        return web.json_response({'error': 'Invalid proposer signature'}, status=400)

    # Check if a block header with the same hash already exists in memory
    async with forger.lock:
        if block_header.block_hash in forger.in_memory_block_headers:
            existing_block_header = forger.in_memory_block_headers[block_header.block_hash]
            existing_block_header.append_signatures(block_header.signatures)
            logging.info(f"Appended signatures to existing block header with hash: {block_header.block_hash}")
        else:
            # Submit the received block header to the forger for replay
            await forger.replay_block(block_header)
            logging.info(f"Submitted block header with hash: {block_header.block_hash} for replay")

    return web.json_response({'message': 'Block header received and processed'}, status=200)

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

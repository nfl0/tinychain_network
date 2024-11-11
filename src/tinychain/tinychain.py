import asyncio
import logging
import json
from jsonschema import validate
from jsonschema.exceptions import ValidationError
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
from storage_engine import StorageEngine
from transaction_pool import TransactionPool

TINYCOIN = 1000000000000000000
TINYCHAIN_UNIT = 'tatoshi'

app = web.Application()

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

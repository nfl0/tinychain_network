import plyvel
import json
import logging

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

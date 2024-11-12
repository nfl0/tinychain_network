from transaction import Transaction

block_header_schema = {
    'type': 'object',
    'properties': {
        'block_hash': {'type': 'string'},
        'height': {'type': 'integer'},
        'timestamp': {'type': 'integer'},
        'previous_block_hash': {'type': 'string'},
        'merkle_root': {'type': 'string'},
        'state_root': {'type': 'string'},
        'proposer': {'type': 'string'},
        'chain_id': {'type': 'string'},
        'signatures': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'validator_address': {'type': 'string'},
                    'timestamp': {'type': 'integer'},
                    'signature_data': {'type': 'string'},
                    'validator_index': {'type': 'integer'}
                },
                'required': ['validator_address', 'timestamp', 'signature_data', 'validator_index']
            }
        },
        'transaction_hashes': {'type': 'array', 'items': {'type': 'string'}}
    },
    'required': ['block_hash', 'height', 'timestamp', 'previous_block_hash', 'state_root', 'proposer', 'chain_id', 'signatures', 'transaction_hashes']
}

class Signature:
    def __init__(self, validator_address, timestamp, signature_data, validator_index):
        self.validator_address = validator_address
        self.timestamp = timestamp
        self.signature_data = signature_data
        self.validator_index = validator_index

    @classmethod
    def from_dict(cls, signature_data):
        if isinstance(signature_data, Signature):
            return signature_data
        return cls(
            signature_data['validator_address'],
            signature_data['timestamp'],
            signature_data['signature_data'],
            signature_data['validator_index']
        )

    def to_dict(self):
        return {
            'validator_address': self.validator_address,
            'timestamp': self.timestamp,
            'signature_data': self.signature_data,
            'validator_index': self.validator_index
        }

class BlockHeader:
    def __init__(self, block_hash, height, timestamp, previous_block_hash, merkle_root, state_root, proposer, chain_id, signatures, transaction_hashes):
        self.block_hash = block_hash
        self.height = int(height)
        self.timestamp = int(timestamp)
        self.previous_block_hash = previous_block_hash
        self.merkle_root = merkle_root
        self.state_root = state_root
        self.proposer = proposer
        self.chain_id = chain_id
        self.signatures = [Signature.from_dict(sig) for sig in signatures]
        self.transaction_hashes = transaction_hashes

        if not hasattr(self, 'transactions'):
            self.transactions = []

    @classmethod
    def from_dict(cls, header_data):

        if 'transactions' not in header_data:
            header_data['transactions'] = []

        block_header = cls(
            header_data['block_hash'],
            header_data['height'],
            header_data['timestamp'],
            header_data['previous_block_hash'],
            header_data['merkle_root'],
            header_data['state_root'],
            header_data['proposer'],
            header_data['chain_id'],
            header_data['signatures'],
            header_data['transaction_hashes']
        )
        return block_header

    def to_dict(self):
        return {
            'block_hash': self.block_hash,
            'height': self.height,
            'timestamp': self.timestamp,
            'previous_block_hash': self.previous_block_hash,
            'merkle_root': self.merkle_root,
            'state_root': self.state_root,
            'proposer': self.proposer,
            'chain_id': self.chain_id,
            'signatures': [sig.to_dict() for sig in self.signatures],
            'transaction_hashes': self.transaction_hashes
        }
    
    def append_signature(self, validator_address, signature_data, validator_index):
        timestamp = int(time.time())
        signature = Signature(validator_address, timestamp, signature_data, validator_index)
        self.signatures.append(signature)

    def find_signature_by_validator(self, validator_address):
        for signature in self.signatures:
            if signature.validator_address == validator_address:
                return signature
        return None

    def append_signatures(self, new_signatures):
        for new_signature in new_signatures:
            existing_signature = self.find_signature_by_validator(new_signature.validator_address)
            if existing_signature is None:
                self.signatures.append(new_signature)
            else:
                if new_signature.timestamp > existing_signature.timestamp:
                    self.signatures.remove(existing_signature)
                    self.signatures.append(new_signature)

    def count_signatures(self):
        return len(self.signatures)

    def has_enough_signatures(self, required_signatures):
        return len(self.signatures) >= required_signatures

class Block:
    def __init__(self, header, transactions):
        self.header = header
        self.transactions = transactions

    @classmethod
    def from_dict(cls, block_data):
        header = BlockHeader.from_dict(block_data['header'])

        transactions = [Transaction(**t) for t in block_data.get('transactions', [])]

        return cls(header, transactions)

    def store(self, storage_engine, new_state):
        if self.header.has_enough_signatures(required_signatures=2/3 * len(storage_engine.fetch_current_validator_set())):
            storage_engine.store_block(self)
            storage_engine.store_block_header(self.header)
            storage_engine.store_state(self.header.state_root, new_state)
            return True
        return False

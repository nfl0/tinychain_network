import ecdsa
from ecdsa import VerifyingKey
import time
from blake3 import blake3
import re

from wallet import Wallet
from block import Block, Signature

class ValidationEngine:
    def __init__(self, storage_engine):
        self.storage_engine = storage_engine

    def is_valid_address(self, address):
        return bool(re.match(r'^[0-9a-fA-F]+$', address))

    def is_valid_block_hash(self, block_hash):
        return bool(re.match(r'^[0-9a-fA-F]+$', block_hash))

    def validate_transaction(self, transaction):

        if transaction.fee <= 0:
            return False

        balance, expected_nonce = self.storage_engine.get_nonce_for_account(transaction.sender)
        if transaction.nonce != expected_nonce:
            return False

        if not self.is_valid_address(transaction.sender):
            return False

        if not self.is_valid_address(transaction.receiver):
            return False

        if transaction.amount <= 0:
            return False
        
        if len(transaction.memo) > 256:
            return False

        sender_balance = self.storage_engine.fetch_balance(transaction.sender)
        if sender_balance is None or sender_balance < transaction.amount:
            return False

        if not self.verify_transaction_signature(transaction):
            return False

        return True

    def verify_transaction_signature(self, transaction):
        public_key = transaction.sender
        signature = transaction.signature
        vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
        message = f"{transaction.sender}-{transaction.receiver}-{transaction.amount}-{transaction.memo}-{transaction.fee}-{transaction.nonce}"
        try:
            if not re.fullmatch(r'[0-9a-fA-F]+', signature):
                raise ValueError("Invalid hexadecimal string for signature")
            vk.verify(bytes.fromhex(signature), message.encode())
            return True
        except ecdsa.BadSignatureError:
            return False
        except ValueError as e:
            print(f"Error: {e}")
            return False

    def validate_block_header(self, block, previous_block_header):
        if not isinstance(block, Block):
            print("Block is not an instance of Block class.")
            return False
        
        if not self.is_valid_block_hash(previous_block_header.block_hash):
            print(f"Invalid previous block hash: {previous_block_header.block_hash}")
            return False

        if not self.is_valid_block_hash(block.header.block_hash):
            print(f"Invalid block hash: {block.header.block_hash}")
            return False

        if block.header.previous_block_hash != previous_block_header.block_hash:
            print(f"Previous block hash mismatch: {block.header.previous_block_hash} != {previous_block_header.block_hash}")
            return False

        if block.header.height != previous_block_header.height + 1:
            print(f"Block height mismatch: {block.header.height} != {previous_block_header.height + 1}")
            return False

        time_tolerance = 2
        current_time = int(time.time())
        if not (previous_block_header.timestamp < block.header.timestamp < current_time + time_tolerance):
            print(f"Timestamp mismatch: {previous_block_header.timestamp} < {block.header.timestamp} < {current_time + time_tolerance}")
            return False

        values = [block.header.merkle_root, str(block.header.timestamp), str(block.header.state_root), previous_block_header.block_hash, block.header.chain_id]
        concatenated_string = ''.join(values).encode()
        computed_hash = blake3(concatenated_string).hexdigest()
        if block.header.block_hash != computed_hash:
            print(f"Block hash mismatch: {block.header.block_hash} != {computed_hash}")
            return False

        # Merkle root computation debugging
        transaction_hashes = [t.to_dict()['transaction_hash'] for t in block.transactions]
        print(f"Transaction hashes: {transaction_hashes}")

        if len(transaction_hashes) == 0:
            computed_merkle_root = blake3(b'').hexdigest()
        else:
            while len(transaction_hashes) > 1:
                if len(transaction_hashes) % 2 != 0:
                    transaction_hashes.append(transaction_hashes[-1])
                transaction_hashes = [blake3(transaction_hashes[i].encode() + transaction_hashes[i + 1].encode()).digest() for i in range(0, len(transaction_hashes), 2)]
            
            if isinstance(transaction_hashes[0], str):
                transaction_hashes[0] = transaction_hashes[0].encode('utf-8')
            computed_merkle_root = blake3(transaction_hashes[0]).hexdigest()

        if block.header.merkle_root != computed_merkle_root:
            print(f"Merkle root mismatch: {block.header.merkle_root} != {computed_merkle_root}")
            return False

        for signature in block.header.signatures:
            if not Wallet.verify_signature(block.header.block_hash, signature.signature_data, signature.validator_address):
                print(f"Invalid signature for block hash: {block.header.block_hash}")
                return False

        for transaction in block.header.transactions:
            if not self.validate_transaction(transaction):
                print(f"Invalid transaction in block: {transaction}")
                return False

        if not self.validate_round_robin_proposer(block.header.proposer, previous_block_header.proposer):
            print(f"Invalid proposer: {block.header.proposer} != {previous_block_header.proposer}")
            return False

        return True


    def validate_block_header_signatures(self, block_header):
        for signature in block_header.signatures:
            if not Wallet.verify_signature(block_header.block_hash, signature.signature_data, signature.validator_address):
                return False
            if signature.validator_index is None:
                return False
        return True

    def validate_enough_signatures(self, block_header, required_signatures):
        return len(block_header.signatures) >= required_signatures

    def validate_round_robin_proposer(self, current_proposer, previous_proposer):
        validator_set = self.storage_engine.fetch_contract_state("7374616b696e67")
        if validator_set:
            sorted_validators = sorted(validator_set.keys(), key=lambda k: validator_set[k]['index'])
            previous_index = sorted_validators.index(previous_proposer)
            expected_proposer = sorted_validators[(previous_index + 1) % len(sorted_validators)]
            logging.info(f"Expected proposer: {expected_proposer}, Current proposer: {current_proposer}")
            return current_proposer == expected_proposer
        logging.error("No validators found in the current validator set")
        return False

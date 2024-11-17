use ecdsa::{VerifyingKey, Signature};
use blake3::Hasher;
use regex::Regex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::wallet::Wallet;
use crate::block::{Block, BlockHeader};
use crate::transaction::Transaction;
use crate::storage_engine::StorageEngine;

pub struct ValidationEngine {
    storage_engine: StorageEngine,
}

impl ValidationEngine {
    pub fn new(storage_engine: StorageEngine) -> Self {
        ValidationEngine { storage_engine }
    }

    pub fn is_valid_address(&self, address: &str) -> bool {
        let re = Regex::new(r"^[0-9a-fA-F]+$").unwrap();
        re.is_match(address)
    }

    pub fn is_valid_block_hash(&self, block_hash: &str) -> bool {
        let re = Regex::new(r"^[0-9a-fA-F]+$").unwrap();
        re.is_match(block_hash)
    }

    pub fn validate_transaction(&self, transaction: &Transaction) -> bool {
        if transaction.fee <= 0 {
            return false;
        }

        let (balance, expected_nonce) = self.storage_engine.get_nonce_for_account(&transaction.sender);
        if transaction.nonce != expected_nonce {
            return false;
        }

        if !self.is_valid_address(&transaction.sender) {
            return false;
        }

        if !self.is_valid_address(&transaction.receiver) {
            return false;
        }

        if transaction.amount <= 0 {
            return false;
        }

        if transaction.memo.len() > 256 {
            return false;
        }

        let sender_balance = self.storage_engine.fetch_balance(&transaction.sender);
        if sender_balance.is_none() || sender_balance.unwrap() < transaction.amount {
            return false;
        }

        if !self.verify_transaction_signature(transaction) {
            return false;
        }

        true
    }

    pub fn verify_transaction_signature(&self, transaction: &Transaction) -> bool {
        let public_key = &transaction.sender;
        let signature = &transaction.signature;
        let vk = VerifyingKey::from_string(public_key).unwrap();
        let message = format!("{}-{}-{}-{}-{}-{}", transaction.sender, transaction.receiver, transaction.amount, transaction.memo, transaction.fee, transaction.nonce);
        vk.verify(signature, message.as_bytes()).is_ok()
    }

    pub fn validate_block_header(&self, block: &Block, previous_block_header: &BlockHeader) -> bool {
        if !self.is_valid_block_hash(&previous_block_header.block_hash) {
            return false;
        }

        if !self.is_valid_block_hash(&block.header.block_hash) {
            return false;
        }

        if block.header.previous_block_hash != previous_block_header.block_hash {
            return false;
        }

        if block.header.height != previous_block_header.height + 1 {
            return false;
        }

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if !(previous_block_header.timestamp < block.header.timestamp && block.header.timestamp < current_time + 2) {
            return false;
        }

        let values = format!("{}{}{}{}{}", block.header.merkle_root, block.header.timestamp, block.header.state_root, previous_block_header.block_hash, block.header.chain_id);
        let mut hasher = Hasher::new();
        hasher.update(values.as_bytes());
        let computed_hash = hasher.finalize().to_hex().to_string();
        if block.header.block_hash != computed_hash {
            return false;
        }

        let transaction_hashes: Vec<String> = block.transactions.iter().map(|t| t.transaction_hash.clone()).collect();
        let computed_merkle_root = self.compute_merkle_root(&transaction_hashes);
        if block.header.merkle_root != computed_merkle_root {
            return false;
        }

        for signature in &block.header.signatures {
            if !Wallet::verify_signature(&block.header.block_hash, &signature.signature_data, &signature.validator_address) {
                return false;
            }
        }

        for transaction in &block.transactions {
            if !self.validate_transaction(transaction) {
                return false;
            }
        }

        if !self.validate_round_robin_proposer(&block.header.proposer, &previous_block_header.proposer) {
            return false;
        }

        true
    }

    pub fn validate_block_header_signatures(&self, block_header: &BlockHeader) -> bool {
        for signature in &block_header.signatures {
            if !Wallet::verify_signature(&block_header.block_hash, &signature.signature_data, &signature.validator_address) {
                return false;
            }
            if signature.validator_index.is_none() {
                return false;
            }
        }
        true
    }

    pub fn validate_enough_signatures(&self, block_header: &BlockHeader, required_signatures: usize) -> bool {
        block_header.signatures.len() >= required_signatures
    }

    pub fn validate_round_robin_proposer(&self, current_proposer: &str, previous_proposer: &str) -> bool {
        let validator_set = self.storage_engine.fetch_contract_state("7374616b696e67");
        if let Some(validator_set) = validator_set {
            let mut sorted_validators: Vec<&str> = validator_set.keys().collect();
            sorted_validators.sort_by_key(|k| validator_set[k].index);
            let previous_index = sorted_validators.iter().position(|&v| v == previous_proposer).unwrap();
            let expected_proposer = sorted_validators[(previous_index + 1) % sorted_validators.len()];
            return current_proposer == expected_proposer;
        }
        false
    }

    fn compute_merkle_root(&self, transaction_hashes: &[String]) -> String {
        if transaction_hashes.is_empty() {
            return Hasher::new().finalize().to_hex().to_string();
        }

        let mut hashes: Vec<[u8; 32]> = transaction_hashes.iter().map(|h| Hasher::new().update(h.as_bytes()).finalize().as_bytes().clone()).collect();
        while hashes.len() > 1 {
            let mut new_hashes = Vec::new();
            for i in (0..hashes.len()).step_by(2) {
                let left_hash = hashes[i];
                let right_hash = if i + 1 < hashes.len() { hashes[i + 1] } else { hashes[i] };
                let mut hasher = Hasher::new();
                hasher.update(&left_hash);
                hasher.update(&right_hash);
                new_hashes.push(hasher.finalize().as_bytes().clone());
            }
            hashes = new_hashes;
        }

        Hasher::new().update(&hashes[0]).finalize().to_hex().to_string()
    }
}

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Signature {
    pub validator_address: String,
    pub timestamp: u64,
    pub signature_data: String,
    pub validator_index: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockHeader {
    pub block_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub previous_block_hash: String,
    pub merkle_root: String,
    pub state_root: String,
    pub proposer: String,
    pub chain_id: String,
    pub signatures: Vec<Signature>,
    pub transaction_hashes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl BlockHeader {
    pub fn append_signature(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }

    pub fn find_signature_by_validator(&self, validator_address: &str) -> Option<&Signature> {
        self.signatures.iter().find(|&sig| sig.validator_address == validator_address)
    }

    pub fn append_signatures(&mut self, new_signatures: Vec<Signature>) {
        for new_signature in new_signatures {
            if let Some(existing_signature) = self.find_signature_by_validator(&new_signature.validator_address) {
                if new_signature.timestamp > existing_signature.timestamp {
                    self.signatures.retain(|sig| sig.validator_address != new_signature.validator_address);
                    self.signatures.push(new_signature);
                }
            } else {
                self.signatures.push(new_signature);
            }
        }
    }

    pub fn count_signatures(&self) -> usize {
        self.signatures.len()
    }

    pub fn has_enough_signatures(&self, required_signatures: usize) -> bool {
        self.signatures.len() >= required_signatures
    }
}

impl Block {
    pub fn store(&self, storage_engine: &StorageEngine, new_state: &State) -> bool {
        if self.header.has_enough_signatures((2.0 / 3.0 * storage_engine.fetch_current_validator_set().len() as f64) as usize) {
            storage_engine.store_block(self);
            storage_engine.store_block_header(&self.header);
            storage_engine.store_state(&self.header.state_root, new_state);
            true
        } else {
            false
        }
    }
}

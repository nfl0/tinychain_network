use crate::merkle_tree::MerkleTree;
use crate::transaction::Transaction;
use crate::parameters::BLOCK_REWARD;
use std::collections::HashMap;

const TINYCOIN: u64 = 1_000_000_000_000_000_000; // 1 tinycoin = 1,000,000,000,000,000,000 tatoshi
const BLOCK_REWARD_AMOUNT: u64 = BLOCK_REWARD * TINYCOIN;

pub struct TinyVMEngine {
    merkle_tree: MerkleTree,
    current_state: HashMap<String, HashMap<String, u64>>,
    accounts_contract_address: String,
    staking_contract_address: String,
    storage_contract_address: String,
}

impl TinyVMEngine {
    pub fn new(current_state: HashMap<String, HashMap<String, u64>>) -> Self {
        TinyVMEngine {
            merkle_tree: MerkleTree::new(),
            current_state,
            accounts_contract_address: "6163636f756e7473".to_string(),
            staking_contract_address: "7374616b696e67".to_string(),
            storage_contract_address: "73746f72616765".to_string(),
        }
    }

    pub fn exec(&mut self, transactions: Vec<Transaction>, proposer: String) -> (String, HashMap<String, HashMap<String, u64>>) {
        let mut accounts_contract_state = self.current_state.get(&self.accounts_contract_address).cloned().unwrap_or_else(|| {
            let mut genesis_state = HashMap::new();
            genesis_state.insert("genesis".to_string(), 60_000 * TINYCOIN);
            genesis_state
        });

        let mut staking_contract_state = self.current_state.get(&self.staking_contract_address).cloned().unwrap_or_default();

        let mut summary = HashMap::new();
        summary.insert("success", 0);
        summary.insert("failed", 0);

        if proposer != "genesis" {
            accounts_contract_state = self.execute_accounts_contract(accounts_contract_state, proposer.clone(), None, BLOCK_REWARD_AMOUNT, "credit");
        }

        for transaction in transactions {
            let success = self.process_transaction(&mut accounts_contract_state, &mut staking_contract_state, &transaction);
            if success {
                *summary.get_mut("success").unwrap() += 1;
            } else {
                *summary.get_mut("failed").unwrap() += 1;
            }
        }

        let mut state = HashMap::new();
        state.insert(self.accounts_contract_address.clone(), accounts_contract_state);
        state.insert(self.staking_contract_address.clone(), staking_contract_state);

        let state_root = self.merkle_tree.root_hash().to_hex().to_string();

        (state_root, state)
    }

    fn process_transaction(&mut self, accounts_state: &mut HashMap<String, u64>, staking_state: &mut HashMap<String, u64>, transaction: &Transaction) -> bool {
        if transaction.receiver == self.staking_contract_address && (transaction.memo == "stake" || transaction.memo == "unstake") {
            let is_stake = transaction.memo == "stake";
            self.execute_staking_contract(staking_state, &transaction.sender, transaction.amount, is_stake, accounts_state);
            true
        } else if transaction.memo != "stake" && transaction.memo != "unstake" && transaction.receiver == self.staking_contract_address {
            false
        } else {
            self.execute_accounts_contract(accounts_state.clone(), transaction.sender.clone(), Some(transaction.receiver.clone()), transaction.amount, "transfer").is_some()
        }
    }

    fn execute_accounts_contract(&mut self, mut contract_state: HashMap<String, u64>, sender: String, receiver: Option<String>, amount: u64, operation: &str) -> Option<HashMap<String, u64>> {
        match operation {
            "credit" => {
                *contract_state.entry(sender).or_insert(0) += amount;
            }
            "transfer" => {
                let sender_balance = contract_state.get(&sender).cloned().unwrap_or(0);
                if sender_balance >= amount {
                    *contract_state.entry(sender.clone()).or_insert(0) -= amount;
                    if let Some(receiver) = receiver {
                        *contract_state.entry(receiver).or_insert(0) += amount;
                    }
                } else {
                    return None;
                }
            }
            _ => return None,
        }

        self.merkle_tree.append(&serde_json::to_vec(&contract_state).unwrap());
        Some(contract_state)
    }

    fn execute_staking_contract(&mut self, contract_state: &mut HashMap<String, u64>, sender: &str, amount: u64, is_stake: bool, accounts_state: &mut HashMap<String, u64>) {
        let staked_balance = contract_state.entry(sender.to_string()).or_insert(0);

        if is_stake {
            let sender_balance = accounts_state.get(sender).cloned().unwrap_or(0);
            if sender_balance >= amount {
                *staked_balance += amount;
                *accounts_state.entry(sender.to_string()).or_insert(0) -= amount;
            }
        } else {
            if *staked_balance > 0 {
                let released_balance = *staked_balance;
                *staked_balance = 0;
                self.execute_accounts_contract(accounts_state.clone(), self.staking_contract_address.clone(), Some(sender.to_string()), released_balance, "transfer");
            }
        }

        self.merkle_tree.append(&serde_json::to_vec(&contract_state).unwrap());
    }
}

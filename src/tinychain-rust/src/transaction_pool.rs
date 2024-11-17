pub struct TransactionPool {
    transactions: Vec<Transaction>,
    max_size: usize,
}

impl TransactionPool {
    pub fn new(max_size: usize) -> Self {
        TransactionPool {
            transactions: Vec::new(),
            max_size,
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<(), &'static str> {
        if self.transactions.len() >= self.max_size {
            return Err("Transaction pool is full");
        }
        self.transactions.push(transaction);
        Ok(())
    }

    pub fn remove_transaction(&mut self, transaction_hash: &str) {
        self.transactions.retain(|tx| tx.transaction_hash != transaction_hash);
    }

    pub fn get_transactions(&self) -> Vec<&Transaction> {
        let mut sorted_transactions: Vec<&Transaction> = self.transactions.iter().collect();
        sorted_transactions.sort_by(|a, b| b.fee.cmp(&a.fee));
        sorted_transactions
    }

    pub fn get_transaction_by_hash(&self, hash: &str) -> Option<&Transaction> {
        self.transactions.iter().find(|tx| tx.transaction_hash == hash)
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

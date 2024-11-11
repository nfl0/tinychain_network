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

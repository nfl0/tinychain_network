from blake3 import blake3

transaction_schema = {
    "type": "object",
    "properties": {
        "sender": {"type": "string"},
        "receiver": {"type": "string"},
        "amount": {"type": "number"},
        "fee": {"type": "number"},
        "nonce": {"type": "number"},
        "signature": {"type": "string"},
        "memo": {"type": "string"}
    },
    "required": ["sender", "receiver", "amount", "fee", "nonce", "signature"]
}

class Transaction:
    def __init__(self, sender, receiver, amount, fee, nonce, signature, memo=''):
        self.sender = sender
        self.receiver = receiver
        self.amount = int(amount)
        self.fee = int(fee)
        self.nonce = int(nonce)
        self.signature = signature
        self.memo = memo

        self.message = f"{self.sender}-{self.receiver}-{self.amount}-{self.memo}"
        self.transaction_hash = self.generate_transaction_hash()
        self.confirmed = None

    def generate_transaction_hash(self):
        values = [str(self.sender), str(self.receiver), str(self.amount), str(self.fee), str(self.nonce), str(self.signature)]
        hasher = blake3()
        for value in values:
            hasher.update(value.encode())
        return hasher.hexdigest()

    def to_dict(self):
        return {
            'transaction_hash': self.transaction_hash,
            'sender': self.sender,
            'receiver': self.receiver,
            'amount': self.amount,
            'signature': self.signature,
            'fee': self.fee,
            'nonce': self.nonce,
            'memo': self.memo,
            'confirmed': self.confirmed
        }

use blake3::Hasher;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub signature: String,
    pub memo: String,
    pub transaction_hash: String,
    pub confirmed: Option<u64>,
}

impl Transaction {
    pub fn new(sender: String, receiver: String, amount: u64, fee: u64, nonce: u64, signature: String, memo: String) -> Self {
        let message = format!("{}-{}-{}-{}", sender, receiver, amount, memo);
        let transaction_hash = Self::generate_transaction_hash(&sender, &receiver, amount, fee, nonce, &signature);
        Transaction {
            sender,
            receiver,
            amount,
            fee,
            nonce,
            signature,
            memo,
            transaction_hash,
            confirmed: None,
        }
    }

    fn generate_transaction_hash(sender: &str, receiver: &str, amount: u64, fee: u64, nonce: u64, signature: &str) -> String {
        let mut hasher = Hasher::new();
        hasher.update(sender.as_bytes());
        hasher.update(receiver.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(&fee.to_le_bytes());
        hasher.update(&nonce.to_le_bytes());
        hasher.update(signature.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "transaction_hash": self.transaction_hash,
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "signature": self.signature,
            "fee": self.fee,
            "nonce": self.nonce,
            "memo": self.memo,
            "confirmed": self.confirmed,
        })
    }
}

use ecdsa::{SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use rand::rngs::OsRng;
use std::fs::{self, File};
use std::io::{self, Write, Read};
use std::path::Path;

const WALLET_PATH: &str = "./wallet/";
const WALLET_FILE: &str = "wallet.dat";

pub struct Wallet {
    private_key: SigningKey,
    public_key: VerifyingKey,
}

impl Wallet {
    pub fn new() -> Self {
        let mut rng = OsRng;
        let private_key = SigningKey::random(&mut rng);
        let public_key = private_key.verifying_key();
        Wallet { private_key, public_key }
    }

    pub fn sign_message(&self, message: &str) -> String {
        let signature = self.private_key.sign(message.as_bytes());
        hex::encode(signature.to_bytes())
    }

    pub fn get_address(&self) -> String {
        hex::encode(self.public_key.to_bytes())
    }

    pub fn save_wallet(&self) -> io::Result<()> {
        fs::create_dir_all(WALLET_PATH)?;
        let mut file = File::create(Path::new(WALLET_PATH).join(WALLET_FILE))?;
        file.write_all(&self.private_key.to_bytes())?;
        Ok(())
    }

    pub fn load_wallet() -> io::Result<Self> {
        let mut file = File::open(Path::new(WALLET_PATH).join(WALLET_FILE))?;
        let mut private_key_bytes = [0u8; 32];
        file.read_exact(&mut private_key_bytes)?;
        let private_key = SigningKey::from_bytes(&private_key_bytes).unwrap();
        let public_key = private_key.verifying_key();
        Ok(Wallet { private_key, public_key })
    }

    pub fn wallet_exists() -> bool {
        Path::new(WALLET_PATH).join(WALLET_FILE).exists()
    }

    pub fn verify_signature(message: &str, signature: &str, public_key_hex: &str) -> bool {
        let public_key_bytes = hex::decode(public_key_hex).unwrap();
        let public_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
        let signature_bytes = hex::decode(signature).unwrap();
        public_key.verify(message.as_bytes(), &signature_bytes).is_ok()
    }
}

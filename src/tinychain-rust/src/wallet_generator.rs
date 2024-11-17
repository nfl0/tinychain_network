use ecdsa::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs::{self, File};
use std::io::{self, Write, Read};
use std::path::Path;
use std::error::Error;

const WALLET_PATH: &str = "./wallet/";
const WALLET_FILE: &str = "wallet.dat";

pub fn generate_wallet() -> Result<(), Box<dyn Error>> {
    let mut rng = OsRng;
    let private_key = SigningKey::random(&mut rng);
    let public_key = private_key.verifying_key();

    fs::create_dir_all(WALLET_PATH)?;
    let mut file = File::create(Path::new(WALLET_PATH).join(WALLET_FILE))?;
    file.write_all(&private_key.to_bytes())?;

    println!("Wallet generated successfully!");
    println!("Public Key: {}", hex::encode(public_key.to_bytes()));

    Ok(())
}

pub fn load_wallet() -> Result<(SigningKey, VerifyingKey), Box<dyn Error>> {
    let mut file = File::open(Path::new(WALLET_PATH).join(WALLET_FILE))?;
    let mut private_key_bytes = [0u8; 32];
    file.read_exact(&mut private_key_bytes)?;
    let private_key = SigningKey::from_bytes(&private_key_bytes)?;
    let public_key = private_key.verifying_key();
    Ok((private_key, public_key))
}

pub fn wallet_exists() -> bool {
    Path::new(WALLET_PATH).join(WALLET_FILE).exists()
}

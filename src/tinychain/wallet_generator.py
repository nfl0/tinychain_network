import os
import ecdsa
import pickle
from mnemonic import Mnemonic
import logging

WALLET_PATH = './wallet/'
WALLET_FILE = 'wallet.dat'

def generate_mnemonic():
    try:
        mnemo = Mnemonic("english")
        return mnemo.generate(strength=256)
    except Exception as e:
        logging.error(f"Failed to generate mnemonic: {e}")
        return None

def generate_keypair_from_mnemonic(mnemonic):
    try:
        seed = Mnemonic.to_seed(mnemonic)
        private_key = ecdsa.SigningKey.from_string(seed[:32], curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        return private_key, public_key
    except Exception as e:
        logging.error(f"Failed to generate keypair from mnemonic: {e}")
        return None, None

def save_wallet(private_key, filename):
    try:
        with open(os.path.join(WALLET_PATH, filename), "wb") as file:
            pickle.dump(private_key, file)
    except Exception as e:
        logging.error(f"Failed to save wallet: {e}")

def wallet_exists(filename):
    return os.path.exists(os.path.join(WALLET_PATH, filename))

def main():
    os.makedirs(WALLET_PATH, exist_ok=True)

    if wallet_exists(WALLET_FILE):
        print(f"Wallet already exists at {WALLET_PATH + WALLET_FILE}.")
        print("Aborting to prevent overwrite.")
        return

    mnemonic = generate_mnemonic()
    if mnemonic is None:
        print("Failed to generate mnemonic. Aborting.")
        return

    private_key, public_key = generate_keypair_from_mnemonic(mnemonic)
    if private_key is None or public_key is None:
        print("Failed to generate keypair. Aborting.")
        return

    save_wallet(private_key, WALLET_FILE)

    print("Mnemonic:", mnemonic)
    print("Private Key:", private_key.to_string().hex())
    print("Public Key:", public_key.to_string().hex())

if __name__ == "__main__":
    main()

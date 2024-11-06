import ecdsa
import pickle
import os
import logging

WALLET_PATH = './wallet/'

class Wallet:
    def sign_message(self, message):
        try:
            with open(os.path.join(WALLET_PATH, "wallet.dat"), "rb") as file:
                private_key = pickle.load(file)
                signature = private_key.sign(message.encode()).hex()
                return signature
        except Exception as e:
            logging.error(f"Failed to sign message: {e}")
            return None
    
    def get_address(self):
        try:
            with open(os.path.join(WALLET_PATH, "wallet.dat"), "rb") as file:
                private_key = pickle.load(file)
                public_key = private_key.get_verifying_key()
                return public_key.to_string().hex()
        except Exception as e:
            logging.error(f"Failed to get address: {e}")
            return None

    @staticmethod
    def verify_signature(message, signature, public_key_hex):
        try:
            public_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=ecdsa.SECP256k1)
            message = message.encode()
            return public_key.verify(bytes.fromhex(signature), message)
        except ecdsa.BadSignatureError:
            return False
        except Exception as e:
            logging.error(f"Failed to verify signature: {e}")
            return False

    def is_initialized(self):
        return os.path.exists(os.path.join(WALLET_PATH, "wallet.dat"))

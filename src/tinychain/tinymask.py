import argparse
import json
import os
import requests
from wallet import Wallet
from transaction import Transaction
from parameters import HTTP_PORT

class TinyMask:
    def __init__(self):
        self.wallet = Wallet()

    def create_wallet(self):
        if not self.wallet.is_initialized():
            print("Wallet is not initialized. Please run wallet_generator.py to generate a wallet.")
            return
        print("Wallet already exists.")

    def check_balance(self):
        address = self.wallet.get_address()
        response = requests.get(f'http://localhost:{HTTP_PORT}/get_balance/{address}')
        if response.status_code == 200:
            balance = response.json().get('balance', 0)
            print(f"Balance for address {address}: {balance}")
        else:
            print("Failed to fetch balance.")

    def send_transaction(self, receiver, amount, memo):
        sender = self.wallet.get_address()
        nonce_response = requests.get(f'http://localhost:{HTTP_PORT}/get_nonce/{sender}')
        if nonce_response.status_code == 200:
            nonce = nonce_response.json().get('nonce', 0)
        else:
            print("Failed to fetch nonce.")
            return

        transaction = Transaction(sender, receiver, amount, 0, nonce, self.wallet.sign_message(f"{sender}-{receiver}-{amount}-{memo}"), memo)
        transaction_data = transaction.to_dict()
        response = requests.post(f'http://localhost:{HTTP_PORT}/send_transaction', json={'transaction': transaction_data})
        if response.status_code == 200:
            print(f"Transaction sent successfully. Transaction hash: {response.json().get('transaction_hash')}")
        else:
            print("Failed to send transaction.")

def main():
    parser = argparse.ArgumentParser(description="TinyMask - Wallet Software for TinyChain")
    parser.add_argument('--action', choices=['create', 'balance', 'send'], required=True, help="Action to perform")
    parser.add_argument('--receiver', help="Receiver address for sending transaction")
    parser.add_argument('--amount', type=int, help="Amount to send")
    parser.add_argument('--memo', help="Memo for the transaction")

    args = parser.parse_args()
    tinymask = TinyMask()

    if args.action == 'create':
        tinymask.create_wallet()
    elif args.action == 'balance':
        tinymask.check_balance()
    elif args.action == 'send':
        if not args.receiver or not args.amount:
            print("Receiver and amount are required for sending transaction.")
            return
        tinymask.send_transaction(args.receiver, args.amount, args.memo)

if __name__ == "__main__":
    main()

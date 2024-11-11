this is tinychain
tinychain is this

## Setting up a Python Virtual Environment

0. Create a virtual environment in root dir of project:
   ```bash
   python -m venv .venv
   ```

1. Activate the virtual environment:
   - On Windows:
     ```bash
     .venv\Scripts\activate
     ```
   - On macOS and Linux:
     ```bash
     source .venv/bin/activate
     ```

2. Install the required dependencies using `pip`:
   ```bash
   pip install -r requirements.txt
   ```

## Peer Discovery Method

TinyChain now supports multiple methods for peer discovery. You can specify the method of peer discovery using the `PEER_DISCOVERY_METHOD` parameter in the `src/parameters.py` file. The available options are:

- `file`: Discover peers from a file.
- `api`: Discover peers from an API endpoint.

### File-based Peer Discovery

To use file-based peer discovery, set the `PEER_DISCOVERY_METHOD` parameter to `file` and specify the file path using the `PEER_DISCOVERY_FILE` parameter. The file should contain a list of peer URIs, one per line.

Example:
```python
PEER_DISCOVERY_METHOD = 'file'
PEER_DISCOVERY_FILE = 'peers.txt'
```

### API-based Peer Discovery

To use API-based peer discovery, set the `PEER_DISCOVERY_METHOD` parameter to `api` and specify the API endpoint using the `PEER_DISCOVERY_API` parameter. The API should return a JSON object with a `peers` field containing a list of peer URIs.

Example:
```python
PEER_DISCOVERY_METHOD = 'api'
PEER_DISCOVERY_API = 'http://example.com/api/peers'
```

## TinyMask - Wallet Software for TinyChain

TinyMask is a wallet software for TinyChain that allows you to create a wallet, check your balance, and send transactions.

### How to Use TinyMask

1. **Create a Wallet:**
   Run the wallet generator script to create a new wallet.
   ```bash
   python src/tinychain/wallet_generator.py
   ```

2. **Check Balance:**
   Use the TinyMask script to check the balance of your wallet.
   ```bash
   python src/tinychain/tinymask.py --action balance
   ```

3. **Send Transaction:**
   Use the TinyMask script to send a transaction.
   ```bash
   python src/tinychain/tinymask.py --action send --receiver <receiver_address> --amount <amount> --memo <memo>
   ```

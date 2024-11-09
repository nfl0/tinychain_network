import requests
import logging
import socket
import psutil  # Import psutil to get all network interfaces and their IPs
import time  # Import time module for timeout handling
from parameters import PEER_DISCOVERY_METHOD, PEER_DISCOVERY_FILE, PEER_DISCOVERY_API, ROUND_TIMEOUT

# Dictionary to store the last broadcast time for each block header
last_broadcast_time = {}

def get_local_ips():
    local_ips = set()  # Use a set to avoid duplicate IPs

    try:
        # Get all IP addresses associated with network interfaces on the machine
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:  # Filter for IPv4 addresses only
                    local_ips.add(addr.address)

        # Attempt to get the public IP address
        try:
            public_ip_response = requests.get('https://api.ipify.org?format=json', timeout=0.5)
            if public_ip_response.status_code == 200:
                public_ip = public_ip_response.json().get('ip')
                if public_ip:
                    local_ips.add(public_ip)
        except requests.RequestException as e:
            logging.error(f"Could not retrieve public IP address: {e}")

    except Exception as e:
        logging.error(f"Error getting local IP addresses: {e}")

    return list(local_ips)  # Return as a list for consistency

def get_peers():
    if PEER_DISCOVERY_METHOD == 'file':
        try:
            with open(PEER_DISCOVERY_FILE, 'r') as file:
                peers = file.read().splitlines()
                return peers
        except Exception as e:
            logging.error(f"Error reading peers from file: {e}")
            return []
    elif PEER_DISCOVERY_METHOD == 'api':
        try:
            response = requests.get(PEER_DISCOVERY_API, timeout=0.3)
            if response.status_code == 200:
                peers = response.json().get('peers', [])
                return peers
            else:
                logging.error(f"Failed to fetch peers from API: {response.status_code}")
                return []
        except Exception as e:
            logging.error(f"Error fetching peers from API: {e}")
            return []
    else:
        logging.error(f"Unknown peer discovery method: {PEER_DISCOVERY_METHOD}")
        return []

def broadcast_block_header(block_header, integrity_check):
    logging.info(f"Broadcasting block header with hash: {block_header.block_hash}")
    peers = get_peers()
    local_ips = get_local_ips()
    current_time = time.time()

    # Check if the block header has been broadcasted within the timeout window
    if block_header.block_hash in last_broadcast_time:
        last_broadcast = last_broadcast_time[block_header.block_hash]
        if current_time - last_broadcast < ROUND_TIMEOUT:
            logging.info(f"Skipping broadcast for block header {block_header.block_hash} due to timeout window")
            return

    for peer_uri in peers:
        peer_ip, peer_port = peer_uri.split(':')
        if peer_ip in local_ips:
            continue  # Skip broadcasting to self
        for attempt in range(2):  # Retry mechanism
            try:
                response = requests.post(f'http://{peer_uri}/receive_block', json={'block_header': block_header.to_dict(), 'integrity_check': integrity_check}, timeout=1)
                if response.status_code == 200:
                    logging.info(f"Block header broadcasted to peer {peer_uri}")
                    break  # Exit the retry loop if successful
                else:
                    logging.error(f"Failed to broadcast block header to peer {peer_uri}")
            except Exception as e:
                logging.error(f"Error broadcasting block header to peer {peer_uri}: {e}")
                if attempt < 1:
                    logging.info(f"Retrying broadcast to peer {peer_uri} (attempt {attempt + 1}/2)")

    # Update the last broadcast time for the block header
    last_broadcast_time[block_header.block_hash] = current_time

def broadcast_transaction(transaction, sender_uri):
    peers = get_peers()
    local_ips = get_local_ips()
    for peer_uri in peers:
        peer_ip, peer_port = peer_uri.split(':')
        if peer_uri == sender_uri or peer_ip in local_ips:
            continue  # Skip broadcasting to self or sender
        try:
            response = requests.post(f'http://{peer_uri}/send_transaction', json={'transaction': transaction.to_dict()}, timeout=2)
            if response.status_code == 200:
                logging.info(f"Transaction broadcasted to peer {peer_uri}")
            else:
                logging.error(f"Failed to broadcast transaction to peer {peer_uri}")
        except Exception as e:
            logging.error(f"Error broadcasting transaction to peer {peer_uri}: {e}")

def reset_broadcast_flags():
    global last_broadcast_time
    last_broadcast_time = {}
    logging.info("Broadcast flags reset for new round")

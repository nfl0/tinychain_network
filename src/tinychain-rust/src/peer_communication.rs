use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::timeout;
use tokio::sync::RwLock;
use std::sync::Arc;
use log::{info, error};

use crate::parameters::{PEER_DISCOVERY_METHOD, PEER_DISCOVERY_FILE, PEER_DISCOVERY_API, ROUND_TIMEOUT};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockHeader {
    pub block_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub previous_block_hash: String,
    pub merkle_root: String,
    pub state_root: String,
    pub proposer: String,
    pub chain_id: String,
    pub signatures: Vec<Signature>,
    pub transaction_hashes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Signature {
    pub validator_address: String,
    pub timestamp: u64,
    pub signature_data: String,
    pub validator_index: u32,
}

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

pub struct PeerCommunication {
    client: Client,
    last_broadcast_time: Arc<RwLock<HashMap<String, u64>>>,
}

impl PeerCommunication {
    pub fn new() -> Self {
        PeerCommunication {
            client: Client::new(),
            last_broadcast_time: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_local_ips(&self) -> Vec<IpAddr> {
        let mut local_ips = Vec::new();
        match local_ip_address::list_afinet_netifas() {
            Ok(ips) => {
                for (_, ip) in ips {
                    local_ips.push(ip);
                }
            }
            Err(e) => {
                error!("Error getting local IP addresses: {}", e);
            }
        }
        local_ips
    }

    pub async fn get_peers(&self) -> Vec<String> {
        match PEER_DISCOVERY_METHOD.as_str() {
            "file" => {
                match std::fs::read_to_string(PEER_DISCOVERY_FILE) {
                    Ok(content) => content.lines().map(|s| s.to_string()).collect(),
                    Err(e) => {
                        error!("Error reading peers from file: {}", e);
                        Vec::new()
                    }
                }
            }
            "api" => {
                match self.client.get(PEER_DISCOVERY_API).timeout(Duration::from_millis(300)).send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            match response.json::<HashMap<String, Vec<String>>>().await {
                                Ok(json) => json.get("peers").cloned().unwrap_or_default(),
                                Err(e) => {
                                    error!("Failed to parse peers from API response: {}", e);
                                    Vec::new()
                                }
                            }
                        } else {
                            error!("Failed to fetch peers from API: {}", response.status());
                            Vec::new()
                        }
                    }
                    Err(e) => {
                        error!("Error fetching peers from API: {}", e);
                        Vec::new()
                    }
                }
            }
            _ => {
                error!("Unknown peer discovery method: {}", PEER_DISCOVERY_METHOD);
                Vec::new()
            }
        }
    }

    pub async fn broadcast_block_header(&self, block_header: BlockHeader, integrity_check: &str) {
        info!("Broadcasting block header with hash: {}", block_header.block_hash);
        let peers = self.get_peers().await;
        let local_ips = self.get_local_ips().await;
        let current_time = tokio::time::Instant::now().elapsed().as_secs();

        let mut last_broadcast_time = self.last_broadcast_time.write().await;
        if let Some(&last_broadcast) = last_broadcast_time.get(&block_header.block_hash) {
            if current_time - last_broadcast < ROUND_TIMEOUT {
                info!("Skipping broadcast for block header {} due to timeout window", block_header.block_hash);
                return;
            }
        }

        for peer_uri in peers {
            let peer_ip: IpAddr = match peer_uri.split(':').next().unwrap().parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            if local_ips.contains(&peer_ip) {
                continue;
            }
            for attempt in 0..2 {
                match timeout(Duration::from_secs(1), self.client.post(&format!("http://{}/receive_block", peer_uri))
                    .json(&serde_json::json!({ "block_header": block_header, "integrity_check": integrity_check }))
                    .send()).await {
                    Ok(Ok(response)) => {
                        if response.status().is_success() {
                            info!("Block header broadcasted to peer {}", peer_uri);
                            break;
                        } else {
                            error!("Failed to broadcast block header to peer {}", peer_uri);
                        }
                    }
                    Ok(Err(e)) => {
                        error!("Error broadcasting block header to peer {}: {}", peer_uri, e);
                    }
                    Err(_) => {
                        error!("Timeout broadcasting block header to peer {}", peer_uri);
                    }
                }
                if attempt < 1 {
                    info!("Retrying broadcast to peer {} (attempt {}/{})", peer_uri, attempt + 1, 2);
                }
            }
        }

        last_broadcast_time.insert(block_header.block_hash.clone(), current_time);
    }

    pub async fn broadcast_transaction(&self, transaction: Transaction, sender_uri: &str) {
        let peers = self.get_peers().await;
        let local_ips = self.get_local_ips().await;
        for peer_uri in peers {
            let peer_ip: IpAddr = match peer_uri.split(':').next().unwrap().parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            if peer_uri == sender_uri || local_ips.contains(&peer_ip) {
                continue;
            }
            match timeout(Duration::from_secs(2), self.client.post(&format!("http://{}/send_transaction", peer_uri))
                .json(&serde_json::json!({ "transaction": transaction }))
                .send()).await {
                Ok(Ok(response)) => {
                    if response.status().is_success() {
                        info!("Transaction broadcasted to peer {}", peer_uri);
                    } else {
                        error!("Failed to broadcast transaction to peer {}", peer_uri);
                    }
                }
                Ok(Err(e)) => {
                    error!("Error broadcasting transaction to peer {}: {}", peer_uri, e);
                }
                Err(_) => {
                    error!("Timeout broadcasting transaction to peer {}", peer_uri);
                }
            }
        }
    }

    pub async fn reset_broadcast_flags(&self) {
        let mut last_broadcast_time = self.last_broadcast_time.write().await;
        last_broadcast_time.clear();
        info!("Broadcast flags reset for new round");
    }
}

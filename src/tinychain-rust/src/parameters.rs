pub const ROUND_TIMEOUT: u64 = 10;
pub const BLOCK_REWARD: u64 = 10;
pub const MAX_TX_BLOCK: usize = 15;
pub const POOL_MAX_TX: usize = 50;
pub const HTTP_PORT: u16 = 5000;
pub const MAX_TX_POOL: usize = 50;
pub const PEER_DISCOVERY_METHOD: &str = "file";  // Options: "file", "api"
pub const PEER_DISCOVERY_FILE: &str = "peers.txt";
pub const PEER_DISCOVERY_API: &str = "http://example.com/api/peers";
pub const MIN_VALIDATORS: usize = 4;
pub const MAX_VALIDATORS: usize = 6;

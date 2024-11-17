use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use warp::Filter;

mod block;
mod transaction;
mod merkle_tree;
mod peer_communication;
mod parameters;
mod validation_engine;
mod vm;
mod wallet;
mod wallet_generator;
mod transaction_pool;

use block::{Block, BlockHeader, Signature};
use transaction::Transaction;
use validation_engine::ValidationEngine;
use vm::TinyVMEngine;
use wallet::Wallet;
use parameters::{HTTP_PORT, MAX_TX_POOL, ROUND_TIMEOUT};
use peer_communication::{broadcast_block_header, broadcast_transaction};
use transaction_pool::TransactionPool;

#[derive(Clone)]
struct AppState {
    transaction_pool: Arc<RwLock<TransactionPool>>,
    storage_engine: Arc<RwLock<StorageEngine>>,
    validation_engine: Arc<RwLock<ValidationEngine>>,
    wallet: Arc<RwLock<Wallet>>,
    in_memory_blocks: Arc<Mutex<HashMap<String, Block>>>,
    in_memory_block_headers: Arc<Mutex<HashMap<String, BlockHeader>>>,
    current_proposer_index: Arc<Mutex<usize>>,
}

#[tokio::main]
async fn main() {
    let wallet = Arc::new(RwLock::new(Wallet::new()));
    if !wallet.read().await.is_initialized() {
        eprintln!("Wallet is not initialized. Please run wallet_generator.rs to generate a wallet.");
        return;
    }

    let transaction_pool = Arc::new(RwLock::new(TransactionPool::new(MAX_TX_POOL)));
    let storage_engine = Arc::new(RwLock::new(StorageEngine::new(transaction_pool.clone())));
    let validation_engine = Arc::new(RwLock::new(ValidationEngine::new(storage_engine.clone())));

    let app_state = AppState {
        transaction_pool: transaction_pool.clone(),
        storage_engine: storage_engine.clone(),
        validation_engine: validation_engine.clone(),
        wallet: wallet.clone(),
        in_memory_blocks: Arc::new(Mutex::new(HashMap::new())),
        in_memory_block_headers: Arc::new(Mutex::new(HashMap::new())),
        current_proposer_index: Arc::new(Mutex::new(0)),
    };

    let send_transaction_route = warp::path("send_transaction")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_state(app_state.clone()))
        .and_then(send_transaction);

    let receive_block_header_route = warp::path("receive_block")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_state(app_state.clone()))
        .and_then(receive_block_header);

    let get_transaction_by_hash_route = warp::path!("transactions" / String)
        .and(warp::get())
        .and(with_state(app_state.clone()))
        .and_then(get_transaction_by_hash);

    let get_block_by_hash_route = warp::path!("get_block" / String)
        .and(warp::get())
        .and(with_state(app_state.clone()))
        .and_then(get_block_by_hash);

    let get_nonce_route = warp::path!("get_nonce" / String)
        .and(warp::get())
        .and(with_state(app_state.clone()))
        .and_then(get_nonce);

    let routes = send_transaction_route
        .or(receive_block_header_route)
        .or(get_transaction_by_hash_route)
        .or(get_block_by_hash_route)
        .or(get_nonce_route);

    warp::serve(routes).run(([0, 0, 0, 0], HTTP_PORT)).await;
}

fn with_state(
    state: AppState,
) -> impl Filter<Extract = (AppState,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}

async fn send_transaction(
    transaction_data: Transaction,
    state: AppState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let transaction = Transaction::from(transaction_data);
    let validation_engine = state.validation_engine.read().await;
    if validation_engine.validate_transaction(&transaction) {
        let mut transaction_pool = state.transaction_pool.write().await;
        if !transaction_pool.contains(&transaction) {
            transaction_pool.add_transaction(transaction.clone());
            drop(transaction_pool);
            let sender_uri = "sender_uri_placeholder"; // Replace with actual sender URI
            broadcast_transaction(transaction, sender_uri).await;
            return Ok(warp::reply::json(&json!({
                "message": "Transaction added to the transaction pool",
                "transaction_hash": transaction.transaction_hash
            })));
        }
    }
    Err(warp::reject::custom(CustomError::InvalidTransaction))
}

async fn receive_block_header(
    block_header_data: BlockHeader,
    state: AppState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let block_header = BlockHeader::from(block_header_data);
    let integrity_check = "integrity_check_placeholder"; // Replace with actual integrity check

    if integrity_check != generate_integrity_check(&block_header) {
        return Err(warp::reject::custom(CustomError::IntegrityCheckFailed));
    }

    let validation_engine = state.validation_engine.read().await;
    if !validation_engine.validate_block_header(&block_header) {
        return Err(warp::reject::custom(CustomError::InvalidBlockHeader));
    }

    let proposer_signature = find_proposer_signature(&block_header);
    if proposer_signature.is_none()
        || !Wallet::verify_signature(
            &block_header.block_hash,
            &proposer_signature.unwrap().signature_data,
            &proposer_signature.unwrap().validator_address,
        )
    {
        return Err(warp::reject::custom(CustomError::InvalidProposerSignature));
    }

    let mut in_memory_block_headers = state.in_memory_block_headers.lock().unwrap();
    if let Some(existing_block_header) = in_memory_block_headers.get_mut(&block_header.block_hash) {
        existing_block_header.append_signatures(block_header.signatures);
    } else {
        drop(in_memory_block_headers);
        replay_block(block_header, state.clone()).await;
    }

    Ok(warp::reply::json(&json!({
        "message": "Block header received and processed"
    })))
}

async fn get_transaction_by_hash(
    transaction_hash: String,
    state: AppState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let storage_engine = state.storage_engine.read().await;
    if let Some(transaction_data) = storage_engine.fetch_transaction(&transaction_hash) {
        return Ok(warp::reply::json(&transaction_data));
    }
    Err(warp::reject::custom(CustomError::TransactionNotFound))
}

async fn get_block_by_hash(
    block_hash: String,
    state: AppState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let storage_engine = state.storage_engine.read().await;
    if let Some(block_data) = storage_engine.fetch_block(&block_hash) {
        return Ok(warp::reply::json(&block_data));
    }
    Err(warp::reject::custom(CustomError::BlockNotFound))
}

async fn get_nonce(
    account_address: String,
    state: AppState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let storage_engine = state.storage_engine.read().await;
    let nonce = storage_engine.get_nonce_for_account(&account_address);
    Ok(warp::reply::json(&json!({ "nonce": nonce })))
}

async fn replay_block(block_header: BlockHeader, state: AppState) {
    let transactions_to_forge = get_transactions_to_forge(&block_header, state.clone()).await;
    let valid_transactions_to_forge: Vec<Transaction> = transactions_to_forge
        .into_iter()
        .filter(|t| state.validation_engine.read().await.validate_transaction(t))
        .collect();

    let previous_block_header = state.storage_engine.read().await.fetch_last_block_header();
    let current_state = state
        .storage_engine
        .read()
        .await
        .fetch_state(&previous_block_header.state_root);

    let tvm_engine = TinyVMEngine::new(current_state);

    let state_root = tvm_engine.exec(&valid_transactions_to_forge, &block_header.proposer);
    if state_root == block_header.state_root {
        let transaction_hashes: Vec<String> = block_header
            .transactions
            .iter()
            .map(|t| t.transaction_hash.clone())
            .collect();
        let computed_merkle_root = compute_merkle_root(&transaction_hashes);
        if computed_merkle_root == block_header.merkle_root {
            let signature = state.wallet.read().await.sign_message(&block_header.block_hash);
            let validator_index = get_validator_index(&block_header.proposer, state.clone()).await;
            let mut signatures = block_header.signatures.clone();
            signatures.push(Signature {
                validator_address: state.wallet.read().await.get_address(),
                timestamp: get_current_timestamp(),
                signature_data: signature,
                validator_index,
            });

            let new_block_header = BlockHeader {
                block_hash: block_header.block_hash.clone(),
                height: block_header.height,
                timestamp: block_header.timestamp,
                previous_block_hash: block_header.previous_block_hash.clone(),
                merkle_root: block_header.merkle_root.clone(),
                state_root: block_header.state_root.clone(),
                proposer: block_header.proposer.clone(),
                chain_id: block_header.chain_id.clone(),
                signatures,
                transaction_hashes: block_header.transaction_hashes.clone(),
            };

            let block = Block {
                header: new_block_header.clone(),
                transactions: valid_transactions_to_forge.clone(),
            };

            let mut in_memory_blocks = state.in_memory_blocks.lock().unwrap();
            in_memory_blocks.insert(block.header.block_hash.clone(), block.clone());
            drop(in_memory_blocks);

            let mut in_memory_block_headers = state.in_memory_block_headers.lock().unwrap();
            in_memory_block_headers.insert(block.header.block_hash.clone(), new_block_header);
            drop(in_memory_block_headers);

            let integrity_check = generate_integrity_check(&block.header);
            broadcast_block_header(block.header.clone(), &integrity_check).await;

            if has_enough_signatures(&block.header, state.clone()).await {
                store_block_procedure(block, state_root, state.clone()).await;
            } else {
                let mut in_memory_blocks = state.in_memory_blocks.lock().unwrap();
                in_memory_blocks.remove(&block.header.block_hash);
                drop(in_memory_blocks);

                let mut in_memory_block_headers = state.in_memory_block_headers.lock().unwrap();
                in_memory_block_headers.remove(&block.header.block_hash);
                drop(in_memory_block_headers);
            }
        }
    }
}

async fn get_transactions_to_forge(
    block_header: &BlockHeader,
    state: AppState,
) -> Vec<Transaction> {
    let mut transactions_to_forge = Vec::new();
    for transaction_hash in &block_header.transaction_hashes {
        if let Some(transaction) = state
            .transaction_pool
            .read()
            .await
            .get_transaction_by_hash(transaction_hash)
        {
            transactions_to_forge.push(transaction.clone());
        }
    }
    transactions_to_forge
}

fn generate_integrity_check(block_header: &BlockHeader) -> String {
    let values = [
        &block_header.block_hash,
        &block_header.height.to_string(),
        &block_header.timestamp.to_string(),
        &block_header.previous_block_hash,
        &block_header.merkle_root,
        &block_header.state_root,
        &block_header.proposer,
        &block_header.chain_id,
        &block_header.transaction_hashes.join(""),
    ];
    let concatenated_string = values.concat();
    blake3::hash(concatenated_string.as_bytes()).to_hex().to_string()
}

fn find_proposer_signature(block_header: &BlockHeader) -> Option<&Signature> {
    block_header
        .signatures
        .iter()
        .find(|sig| sig.validator_address == block_header.proposer)
}

async fn get_validator_index(validator_address: &str, state: AppState) -> i32 {
    let staking_contract_state = state
        .storage_engine
        .read()
        .await
        .fetch_contract_state("7374616b696e67");
    if let Some(staking_contract_state) = staking_contract_state {
        if let Some(validator) = staking_contract_state.get(validator_address) {
            return validator.index;
        }
    }
    -1
}

fn get_current_timestamp() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    since_the_epoch.as_secs() as i64
}

async fn has_enough_signatures(block_header: &BlockHeader, state: AppState) -> bool {
    let required_signatures = (2.0 / 3.0 * state
        .storage_engine
        .read()
        .await
        .fetch_current_validator_set()
        .len() as f64)
        .ceil() as usize;
    block_header.signatures.len() >= required_signatures
}

async fn store_block_procedure(block: Block, state_root: String, state: AppState) {
    let mut storage_engine = state.storage_engine.write().await;
    storage_engine.store_block(&block).await;
    storage_engine.store_block_header(&block.header).await;
    storage_engine.store_state(&block.header.state_root, &state_root).await;
}

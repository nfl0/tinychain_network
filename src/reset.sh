#!/bin/bash

# List of directories and files to be removed
directories=("transactions.db" "headers.db" "blocks.db" "states.db")
files=("block.py" "merkle_tree.py" "peer_communication.py" "requirements.txt" "transaction.py" "vm.py" "wallet.py" "genesis.json" "parameters.py" "peers.txt" "README.md" "tinychain.py" "validation_engine.py" "wallet_generator.py")

# Iterate through node* directories
for node_dir in node*/; do
    echo "Processing $node_dir"
    # Iterate through the list and remove each directory and its contents
    for dir in "${directories[@]}"; do
        if [ -d "$node_dir$dir" ]; then
            rm -r "$node_dir$dir"
            echo "Removed $dir in $node_dir"
        else
            echo "$dir does not exist in $node_dir"
        fi
    done

    # Reset the genesis_timestamp in genesis.json to 0
    if [ -f "$node_dir/genesis.json" ]; then
        jq '.genesis_timestamp = 0' "$node_dir/genesis.json" > tmp.$$.json && mv tmp.$$.json "$node_dir/genesis.json"
        echo "Reset genesis_timestamp to 0 in $node_dir/genesis.json"
    else
        echo "genesis.json not found in $node_dir"
    fi
done

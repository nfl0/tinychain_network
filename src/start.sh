#!/bin/bash

# Set genesis_timestamp to current time + 60 seconds in all node*/genesis.json files
current_time=$(date +%s)
genesis_timestamp=$((current_time + 60))

for node in node*/genesis.json; do
    jq --argjson timestamp "$genesis_timestamp" '.genesis_timestamp = $timestamp' "$node" > tmp.$$.json && mv tmp.$$.json "$node"
done

# Run the containers for each node directory
for node_dir in node*; do
    docker run --rm -v "$PWD/$node_dir:/app" -w /app python:3.9 sh -c "pip install -r requirements.txt && python tinychain.py" &
done

# Wait for all background processes to finish
wait

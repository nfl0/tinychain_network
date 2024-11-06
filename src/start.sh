#!/bin/bash

# Set genesis_timestamp to current time + 60 seconds in all node*/genesis.json files
current_time=$(date +%s)
genesis_timestamp=$((current_time + 60))

for node in node*/genesis.json; do
    jq --argjson timestamp "$genesis_timestamp" '.genesis_timestamp = $timestamp' "$node" > tmp.$$.json && mv tmp.$$.json "$node"
done

# Check if the custom network already exists, create it if it doesn't
network_name="tinychain_network"
subnet="172.18.0.0/24"  # Updated subnet to avoid conflict
if ! docker network inspect "$network_name" >/dev/null 2>&1; then
    echo "Creating Docker network $network_name..."
    docker network create --subnet="$subnet" "$network_name"
fi

# Verify the network was created successfully
if ! docker network inspect "$network_name" >/dev/null 2>&1; then
    echo "Error: Failed to create Docker network $network_name"
    exit 1
fi

# Define IPs for each node within the new subnet
declare -a ips=("172.18.0.2" "172.18.0.3" "172.18.0.4" "172.18.0.5" "172.18.0.6" "172.18.0.7")

# Run the containers for each node directory, assigning a specific IP
index=0
for node_dir in node*; do
    konsole --new-tab -e bash -c "docker run --rm --network $network_name --ip ${ips[$index]} \
        -v \"$PWD/$node_dir:/app\" -w /app python:3.9 \
        sh -c 'pip install -r requirements.txt && python tinychain.py'; exec bash" &
    index=$((index + 1))
done

# Wait for all background processes to finish
wait

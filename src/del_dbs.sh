#!/bin/bash

# List of directories to be removed
directories=("transactions.db" "headers.db" "blocks.db" "states.db")

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
done

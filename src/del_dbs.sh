#!/bin/bash

# List of directories to be removed
directories=("transactions.db" "headers.db" "blocks.db" "states.db")

# Iterate through the list and remove each directory and its contents
for dir in "${directories[@]}"; do
    if [ -d "$dir" ]; then
        rm -r "$dir"
        echo "Removed $dir"
    else
        echo "$dir does not exist"
    fi
done

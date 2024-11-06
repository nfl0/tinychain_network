#!/bin/bash

# Define the source directory and target directories
SOURCE_DIR="node1"
TARGET_DIRS=("node2" "node3" "node4" "node5" "node6")

# List of files to copy
FILES=("genesis.json" "validation_engine.py" "peer_communication.py" "tinychain.py")

# Loop over each target directory
for TARGET in "${TARGET_DIRS[@]}"; do
  # Loop over each file and overwrite in the target directory
  for FILE in "${FILES[@]}"; do
    cp "$SOURCE_DIR/$FILE" "$TARGET/$FILE"
    echo "Overwritten $TARGET/$FILE"
  done
done

echo "Finished overwriting files in all nodes."

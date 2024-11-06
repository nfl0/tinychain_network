#!/bin/bash

# Define the source directory and target directory
SOURCE_DIR="node2"
TARGET_DIRS=("node1")

# List of files to copy
FILES=("genesis.json" "validation_engine.py" "peer_communication.py" "tinychain.py", "parameters.py")

# Loop over each target directory
for TARGET in "${TARGET_DIRS[@]}"; do
  # Loop over each file and overwrite in the target directory
  for FILE in "${FILES[@]}"; do
    cp "$SOURCE_DIR/$FILE" "$TARGET/$FILE"
    echo "Overwritten $TARGET/$FILE"
  done
done

echo "Finished overwriting files in all nodes."

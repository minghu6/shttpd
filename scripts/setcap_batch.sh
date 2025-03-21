#!/bin/bash

# Check if at least two arguments are provided (directory and at least one setcap argument)
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <directory_path> <setcap_arguments...>"
    exit 1
fi

# Assign the first argument to the directory variable
DIRECTORY="$1"

# Check if the provided directory exists
if [ ! -d "$DIRECTORY" ]; then
    echo "Error: Directory '$DIRECTORY' does not exist."
    exit 1
fi

# Shift the first argument so that $@ contains only the setcap arguments
shift

# Loop through each executable file in the directory
for file in "$DIRECTORY"/*; do
    if [ -x "$file" ]; then  # Check if the file is executable
        # Set capabilities using all provided arguments
        sudo setcap "$@" "$file"
        echo "Set capability '$*' on $file"
    fi
done

echo "Finished setting capabilities."

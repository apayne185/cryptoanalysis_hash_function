#!/bin/bash

BRUTE_FORCER="functions/brute.py"
OUTPUT_FILE="solutions/exercise03.txt"

# COLLISION_RESULT=$(python3 "$BRUTE_FORCER")
# echo "$COLLISION_RESULT" > "$OUTPUT_FILE"

python3 "$BRUTE_FORCER" > "$OUTPUT_FILE"

if [ -s "$OUTPUT_FILE" ]; then
    echo "Success- collision saved to $OUTPUT_FILE"
    cat "$OUTPUT_FILE"
else
    echo "Error: output file is empty"
fi
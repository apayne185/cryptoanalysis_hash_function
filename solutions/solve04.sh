#!/bin/bash

#find strs starting with "bitcoin whose SHA256 hash starts w the hex prefixes  -  cafe faded decade
#brute force by appending incremeting ints to "bitcoin"  then hashing until match is found for each  


# i realize this was only staged along with pow.py- never commited to the repo - sorry
POW_FILE="implementation/pow.py"
OUTPUT_FILE="submissions/exercise06.txt" 

python3 "$POW_FILE"

if [ -s "$OUTPUT_FILE" ]; then
    echo ""
    echo "Solution saved to $OUTPUT_FILE"
    cat "$OUTPUT_FILE"
else
    echo "Error: no solution found"
fi

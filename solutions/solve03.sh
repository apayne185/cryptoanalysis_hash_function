#!/bin/bash

#simple_hash uses h = (h << 5) - h + ord(c)  - same as   h = h * 31 + ord(c) 
#use brute force


#32 bit hash w 2^32 possible outputs - birthday paradox collision by sqrt(2^32)=2^16 =65,000 random input
#generate random 8char ASCII str, hash each and store in dict - eventually find a duplicate hash/collision 


BRUTE_FORCER="implementation/brute.py"
OUTPUT_FILE="submissions/exercise03.txt"

python3 $BRUTE_FORCER        # i found out i never commited brute.py to the repo

if [ -s $OUTPUT_FILE ]; then
    echo "Success -collision saved to $OUTPUT_FILE"
    cat $OUTPUT_FILE
else
    echo "Error: no collision found"
fi

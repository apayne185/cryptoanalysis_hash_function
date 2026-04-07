#!/bin/bash


#shift amount = (i % 4)*8
#pos 0,4  shift  0 bits  (byte0)
#pos 1,5  shift 8 bits  (byte1)
#pos 2,6  shift 16 bits (byte2)
#pos 3,7  shift 24 bits  (byte3)

STR1="baaaaaaa"
STR2="aaaabaaa"

HASH1=$(python3 functions/hash0.py "$STR1")
HASH2=$(python3 functions/hash0.py "$STR2")

echo "  '$STR1' -> $HASH1"
echo "  '$STR2' -> $HASH2"

if [ "$HASH1" == "$HASH2" ]; then
    echo ""
    echo "Collision found, writing to submissions/exercise01.txt"
    echo "$STR1,$STR2" > submissions/exercise01.txt
else
    echo "Error - Hashes don't match"
fi

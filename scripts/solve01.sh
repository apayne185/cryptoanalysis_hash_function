#!/bin/bash

STR1="baaaaaaa"
STR2="aaaabaaa"
HASH1=$(python3 functions/hash0.py "$STR1")   
HASH2=$(python3 functions/hash0.py "$STR2")  

  
echo "Hash of $STR1: $HASH1"
echo "Hash of $STR2: $HASH2"    

if [ "$HASH1" == "$HASH2" ]; then
    echo "Collision found, writing to solutions/exercise01.txt"
    echo "$STR1,$STR2" > solutions/exercise01.txt  
else
    echo "Error - Hashes don't match"
fi
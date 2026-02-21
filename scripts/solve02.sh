#!/bin/bash

STR="adg+0000"
RESULT=$(python3 functions/hash0.py "$STR")
echo "$RESULT" 


if [ "$RESULT" == "1b575451" ]; then   
    echo "$STR" > solutions/exercise02.txt
    echo "Preimage found and saved"
else
    echo "Hash mismatch: $RESULT"
fi
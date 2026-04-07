#!/bin/bash

STR="adg+0000"
TARGET="1b575451"

#reversing each byte lane - positons 4-7 fixed as 0=0x30 
#byte0: 0x51 ^ 0x30= 0x61=a  -pos 0
#byte1: 0x54 ^ 0x30= 0x64=d   -pos 1
#byte2: 0x57 ^ 0x30= 0x67=g  -pos 2
#byte3: 0x1b ^ 0x30= 0x2b=+  -pos 3


RESULT=$(python3 functions/hash0.py "$STR")
echo "'$STR' -> $RESULT"

if [ "$RESULT" == "$TARGET" ]; then
    echo ""
    echo "Pre-image confirmed, writing to submissions/exercise02.txt"
    echo "$STR" > submissions/exercise02.txt
else
    echo "Hash mismatch: expected $TARGET got $RESULT"
fi

#!/bin/bash

for i in {1..5}; do
    USERNAME="User_$i"
    PRICE=$i
    
    expect <<EOF
        spawn python bidder.py
        expect "Enter your name: " { send "$USERNAME\r" }
        expect "Enter your bid amount: " { send "$PRICE\r" }
        expect eof
EOF
done

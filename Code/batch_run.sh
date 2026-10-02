#!/bin/bash

# Assign command line arguments to variables
ALGO=$1
NETWORK=$2
ISP=$3
START=$4
END=$5

# Loop through the specified batch range
for ((i=START; i<=END; i++))
do
    echo "Starting session: batch$i"
    sudo python3 -E run_client.py "$ALGO" --network "$NETWORK" --isp "$ISP" --session "batch$i" -n 100
    echo "Finished session: batch$i"
    echo "----------------------------"
done


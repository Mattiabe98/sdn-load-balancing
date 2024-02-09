#!/bin/bash

rate=$1
packet_size=$2
timeout=$3
streams=$4


for ((sender=5,receiver=6, i=0; i<$streams; i++, sender+=2, receiver+=2))
do
    bash /home/ubuntu/tools/mininet/util/m "${!sender}" ITGSend -a 10.0.0."${!receiver}" -T TCP -C $rate -c $packet_size -t $timeout &
done

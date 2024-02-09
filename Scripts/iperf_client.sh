#!/bin/bash

timeout=$1
streams=$2

for ((client=3,server=4, i=0; i<$streams; i++, client+=2, server+=2))
do
    bash /home/ubuntu/tools/mininet/util/m "${!client}" iperf3 -c 10.0.0."${!server}" -i 60 -t $timeout &
done

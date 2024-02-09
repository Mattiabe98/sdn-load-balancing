#!/bin/bash
exit_script() {
    echo "Killing iperf on hosts.."
    trap - SIGINT SIGTERM # clear the trap
    for host in "$@"
    do
        bash /home/ubuntu/tools/mininet/util/m "$host" killall iperf3 &
    done
}

trap exit_script SIGINT

for host in "$@"
do
    bash /home/ubuntu/tools/mininet/util/m "$host" iperf3 -s -i 60 &
done

sleep 3600
exit_script "$@"

wait

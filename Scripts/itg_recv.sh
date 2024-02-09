#!/bin/bash
exit_script() {
    echo "Killing iperf on hosts.."
    trap - SIGINT SIGTERM # clear the trap
    for host in "$@"
    do
        bash /home/ubuntu/tools/mininet/util/m "$host" killall ITGRecv &
    done
}

trap exit_script SIGINT

for host in "$@"
do
    bash /home/ubuntu/tools/mininet/util/m "$host" ITGRecv &
done

sleep 65
exit_script "$@"

wait
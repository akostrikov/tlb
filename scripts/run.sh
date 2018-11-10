#!/bin/bash
modprobe dns-resolver
insmod tlb.ko
echo '127.0.0.1 7777' > /sys/fs/tlb/start_server
echo '127.0.0.1 8080' > /sys/fs/tlb/add_target
echo '127.0.0.1 8081' > /sys/fs/tlb/add_target

go run test/server.go -address 127.0.0.1:8080 2>1 1>/dev/null &
BACK1=$!
go run test/server.go -address 127.0.0.1:8081 2>1 1>/dev/null &
BACK2=$!

shutdown() {
	kill $BACK1
	kill $BACK2
	rmmod tlb
	exit 0
}

trap shutdown SIGINT
trap shutdown SIGTERM

while true; do
	sleep 1
done

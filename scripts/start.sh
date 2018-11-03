#!/bin/bash -xv
echo '127.0.0.1 7777' > /sys/fs/tlb/start_server
echo '127.0.0.1 8080' > /sys/fs/tlb/add_target
echo '127.0.0.1 8081' > /sys/fs/tlb/add_target

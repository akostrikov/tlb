# tlb - tcp connection based load balancer

#### Prerequisites:
```CONFIG_DEBUG_STACKOVERFLOW=n``` to allow coroutines in linux kernel mode :-)

#### Usage:
```modprobe dns-resolver
insmod tlb.ko
echo 'EDGE_IP EDGE_PORT' > /sys/fs/tlb/start_server
echo 'TARGET1_IP TARGET1_PORT' > /sys/fs/tlb/add_target
echo 'TARGET2_IP TARGET2_PORT' > /sys/fs/tlb/add_target
echo 'TARGET3_IP TARGET3_PORT' > /sys/fs/tlb/add_target```

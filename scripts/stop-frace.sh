#!/bin/bash -xv

WDIR=./ftrace

echo 0 > /sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/trace > $WDIR/trace
echo '' > /sys/kernel/debug/tracing/trace
echo 0 > /sys/kernel/debug/tracing/events/tlbtrace/enable

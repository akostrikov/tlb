#!/bin/bash -xv

WDIR=./ftrace

rm -rf $WDIR
mkdir -p $WDIR

echo 0 > /sys/kernel/debug/tracing/tracing_on
echo 'nop' > /sys/kernel/debug/tracing/current_tracer
echo 100000 > /sys/kernel/debug/tracing/buffer_size_kb
echo '' > /sys/kernel/debug/tracing/trace
echo 1 > /sys/kernel/debug/tracing/events/tlbtrace/enable
echo 1 > /sys/kernel/debug/tracing/tracing_on

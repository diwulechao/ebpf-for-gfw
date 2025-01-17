#!/bin/bash
rm -rf xdp_prog.o

# Compile the eBPF program
clang -O2 -target bpf -c xdp_prog.c -o xdp_prog.o -I/usr/include/bpf -g

# Detach any existing XDP program enp175s0np0.201
sudo ip link set dev eth0 xdp off

start_time=$(date +%s.%N)

# Attach the new XDP program
sudo ip link set dev eth0 xdp obj xdp_prog.o sec xdp

end_time=$(date +%s.%N)
elapsed_time=$(echo "$end_time - $start_time" | bc)

echo "Elapsed time: $elapsed_time seconds"

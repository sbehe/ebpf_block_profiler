#!/bin/bash

set -e

clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c src/io_profiler_kern.c -o src/io_profiler_kern.o
bpftool gen skeleton src/io_profiler_kern.o > src/io_profiler.skel.h
gcc -O2 -g -Wall -I$(pwd)/src -o io_profiler src/io_profiler_user.c -lbpf -lelf -lz

sudo ./io_profiler
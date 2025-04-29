How To Build and Run

# First time
sudo apt install clang llvm libbpf-dev libelf-dev gcc make bpftool

# Then:
make all


# eBPF-Based Block I/O Profiler

## Overview
This project implements a real-time, low-overhead block I/O profiler using **eBPF** technology.  
The profiler monitors disk I/O operations at the block layer to capture detailed statistics about storage system behavior.

**Current version** tracks:
- Per-process I/O activity
- Read/write request size
- I/O latency
- Real-time monitoring without heavy system overhead

The profiler is intended for optimizing storage performance and understanding I/O patterns under different workloads.

## How It Works
- **Submission Tracking**:  
  The program hooks into the `block_bio_queue` tracepoint to record when an I/O request is queued (BIO submission).
  
- **Completion Tracking**:  
  The program hooks into the `bio_endio()` kernel function using a **kprobe** to reliably capture the completion of the I/O request.  
  This ensures all completed I/O events are captured — even for high-speed NVMe devices and optimized fast paths.

- **Data Transfer**:  
  Latency, request size, process ID, and process name are collected in the kernel and passed to userspace through a **BPF ring buffer**.

- **Userspace Display**:  
  A userspace application reads the events from the ring buffer and displays:
  - PID
  - Process name
  - Latency (microseconds)
  - I/O size (bytes)

- **Debugging**:  
  - `bpf_printk()` is used internally for kernel-side debugging.
  - Kernel messages can be viewed live via `sudo cat /sys/kernel/debug/tracing/trace_pipe`.

## Project Structure

```bash
ebpf_block_profiler/
├── src/
│   ├── io_profiler_kern.c    # eBPF kernel-side code
│   ├── io_profiler_user.c    # Userspace code to read and display events
│   └── io_event.h            # Shared struct definition (my_io_event)
├── scripts/
│   └── fio_test.sh           # Script to generate sample disk workload
├── Makefile                  # Builds everything automatically
└── README.md                 # Project documentation
```

## Building and Running

**Prerequisites**
	•	Linux Kernel ≥ 5.8 (Tested on 6.8.0)
	•	clang, llvm
	•	bpftool
	•	libbpf-dev, libelf-dev
	•	gcc, make

## Build

```bash
  make
```

This automatically:
	•	Generates vmlinux.h
	•	Compiles eBPF kernel object
	•	Generates skeleton headers
	•	Builds userspace binary

**Run**

```bash
  make run
```

**In a separate terminal, monitor kernel debug messages:**

```bash
  sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**Generate Workload**

```bash
  ./scripts/fio_test.sh
```

This will create random disk I/O to simulate activity.

**What You Should See**

In one terminal (profiler output):

```bash
PID: 12345  COMM: fio              Latency(us): 205   Size(bytes): 4096
PID: 12346  COMM: postgres          Latency(us): 312   Size(bytes): 8192
...
```

In another terminal (trace_pipe output):

```bash
submit event
complete event
submit event
complete event
...
```

## Current Limitations

	•	Only basic latency and size tracking per I/O.
	•	No histograms or per-process aggregation yet.
	•	No filtering by device or PID.
	•	No CSV export or plotting yet.

## Future Improvements (Planned)

	•	Build latency histograms (log-scale buckets).
	•	Aggregate average/min/max latency per process.
	•	Export profiling data to CSV files.
	•	Build a lightweight CLI dashboard or web dashboard.
	•	Support filtering by disk device or PID.

## Summary

This savepoint marks a working, basic real-time Block I/O Profiler built with eBPF, with kernel hooks at block_bio_queue and bio_endio() (kprobe), and live userspace event display.
	•	Kernel hooks operational ✅
	•	Ring buffer operational ✅
	•	Userspace event reader operational ✅
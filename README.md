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
  The program hooks into the `submit_bio_noacct` kernel function via a kprobe to record when a BIO is submitted.  
  At this point, the original I/O size is captured and stored in an eBPF hash map along with the submission timestamp.

- **Completion Tracking**:  
  The program hooks into `bio_endio` via a kprobe to capture when a BIO is completed.  
  Using the previously stored information, it calculates I/O latency and retrieves the original I/O size.
  Both metrics are passed to userspace via a BPF ring buffer.

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
	•	No histograms or per-process aggregation yet.
	•	No filtering by device or PID.
	•	No CSV export or plotting yet.

## What is actually working
	•	attachment of BPF Type Format (BTF) Tracepoints for I/O submission
	•	attachment of kprobe into bio_endio () for I/O completion
	•	diplaying I/O submission and I/O completion messages on real time in trace_pipe
	•	user program run (make run) displays I/O Latency and Size for the I/O requests of all the programs.

## Future Improvements (Planned)

	•	Build latency histograms (log-scale buckets).
	•	Aggregate average/min/max latency per process.
	•	Export profiling data to CSV files.
	•	Build a lightweight CLI dashboard or web dashboard.
	•	Support filtering by disk device or PID.

## Summary

## Summary

This version improves the profiler by:
- Replacing fragile block tracepoints with stable kprobes:
  - I/O submission: Hooked at `submit_bio_noacct`
  - I/O completion: Hooked at `bio_endio`
- Capturing and preserving original I/O size at submission time to avoid size=0 errors at completion.
- Passing both latency and size information correctly to userspace.
- Verified working with live fio workloads and accurate size reporting.

This completes the base functional version of the real-time I/O profiler.
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

- **Latency Measurement and Aggregation**
  - Each I/O operation's completion latency is calculated.
  - Latencies are bucketed using log2 scale into a histogram for efficient aggregation.
  - Histogram is displayed live, refreshing every 5 second for real-time visibility.
  - Upon program exit, the histogram is exported to a CSV file (`histogram.csv`) for offline analysis.

- **Per-Process Aggregation**:
  - The profiler tracks I/O count and cumulative latency per PID.
  - The process name (COMM) is captured at first I/O event for each process.
  - At program exit, a per-process summary is printed showing:
    - PID
    - Process Name
    - Number of I/Os
    - Average I/O Latency (in microseconds)

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
	•	No filtering by device.

## What is actually working
	•	attachment of BPF Type Format (BTF) Tracepoints for I/O submission
	•	attachment of kprobe into bio_endio () for I/O completion
	•	diplaying I/O submission and I/O completion messages on real time in trace_pipe
	•	a histogram is displayed with data about the bulk of I/O in a particular latency range every 5 seconds and when the user program is stopped
	•	Histogram data is stored in a CSV export.
	•	Per-process data aggregation.

## Future Improvements (Planned)

	•	Aggregate average/min/max latency per process.
	•	Export profiling data to CSV files.
	•	Build a lightweight CLI dashboard or web dashboard.
	•	Support filtering by disk device or PID.

## Summary

This savepoint adds per-process I/O aggregation to the profiler:
- Extended kernel maps to track per-PID I/O count, total latency, and process name (COMM).
- On each I/O completion, updated per-PID statistics in eBPF maps.
- Modified userspace program to fetch per-process statistics and display:
  - PID
  - Process Name
  - Total I/O Count
  - Average Latency
- Now provides clear insights into which processes are generating I/O and their performance impact.
- Maintains real-time histogram live refresh and CSV export alongside.

With Savepoint6, the profiler achieves complete process-level visibility into storage performance.
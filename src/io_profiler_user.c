#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "io_profiler_kern.skel.h"
#include "io_event.h"
static volatile bool exiting = false;

// Fix struct to match BPF program
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct my_io_event *e = data; // <-- Correct struct
    printf("PID: %-5d COMM: %-16s Latency(us): %-6llu Size(bytes): %-6u\n",
           e->pid, e->comm, e->latency_ns / 1000, e->bytes);
    return 0;
}

static void sig_handler(int sig) {
    exiting = true;
}

int main(int argc, char **argv) {
    struct io_profiler_kern *skel; // <-- Correct skeleton
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = io_profiler_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = io_profiler_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    err = io_profiler_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Started I/O Profiler. Hit Ctrl-C to exit.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms timeout */);
        if (err == -EINTR) break;
        if (err < 0) {
            printf("Polling error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    io_profiler_kern__destroy(skel);
    return err < 0 ? -err : 0;
}
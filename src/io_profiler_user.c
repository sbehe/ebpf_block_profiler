#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "io_profiler_kern.skel.h"
#include "io_event.h"
#include <bpf/bpf.h>
#include <time.h>

#define PRINT_ALL_IO_REQUESTS false

static volatile bool exiting = false;

// Fix struct to match BPF program
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct my_io_event *e = data;
    
    if (PRINT_ALL_IO_REQUESTS == true) {
        printf("PID: %-5d COMM: %-16s Latency(us): %-6llu Size(bytes): %-6u\n",
            e->pid, e->comm, e->latency_ns / 1000, e->bytes);
    }
    return 0;
}

static void sig_handler(int sig) {
    exiting = true;
}

void print_latency_histogram(int map_fd) {
    printf("\nLatency Histogram (microseconds):\n");
    printf("%-20s %-10s\n", "Latency Range", "Count");

    for (__u32 i = 0; i < 64; i++) {
        __u64 value = 0;
        if (bpf_map_lookup_elem(map_fd, &i, &value) == 0 && value > 0) {
            printf("[%6u, %6u) us   %10llu\n",
                   (1U << i) / 1000, (1U << (i+1)) / 1000, value);
        }
    }
}

void write_latency_histogram_csv(int map_fd, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("fopen");
        return;
    }

    fprintf(f, "latency_us_low,latency_us_high,count\n");

    for (__u32 i = 0; i < 64; i++) {
        __u64 value = 0;
        if (bpf_map_lookup_elem(map_fd, &i, &value) == 0 && value > 0) {
            fprintf(f, "%u,%u,%llu\n",
                    (1U << i) / 1000,
                    (1U << (i + 1)) / 1000,
                    value);
        }
    }

    fclose(f);
    printf("Histogram written to %s\n", filename);
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

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    err = io_profiler_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    printf("Started I/O Profiler. Hit Ctrl-C to exit.\n");

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms timeout */);
        if (err == -EINTR) break;
        if (err < 0) {
            printf("Polling error: %d\n", err);
            break;
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - start.tv_sec) >= 5) {  // 5 second passed
            printf("\033[H\033[J"); // Clear terminal (ANSI escape code)
            print_latency_histogram(bpf_map__fd(skel->maps.latency_histogram));
            start = now;
        }
    }

    print_latency_histogram(bpf_map__fd(skel->maps.latency_histogram));
    write_latency_histogram_csv(bpf_map__fd(skel->maps.latency_histogram), "output/histogram.csv");
cleanup:
    ring_buffer__free(rb);
    io_profiler_kern__destroy(skel);
    return err < 0 ? -err : 0;
}
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "io_event.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct request *);
    __type(value, __u64);
    __uint(max_entries, 10240);
} start_ts SEC(".maps");

// Submission hook
SEC("tp_btf/block_rq_issue")
int trace_io_submit(struct request *rq) {
    if (!rq)
        return 0;

    bpf_printk("submit event\n");

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ts, &rq, &ts, BPF_ANY);
    return 0;
}

// Completion hook
SEC("tp_btf/block_rq_complete")
int trace_io_complete(struct request *rq) {
    if (!rq)
        return 0;

    __u64 *tsp = bpf_map_lookup_elem(&start_ts, &rq);
    if (!tsp)
        return 0;

    __u64 latency = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ts, &rq);

    struct my_io_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->ts = bpf_ktime_get_ns();

    struct bio *bio = BPF_CORE_READ(rq, bio);
    if (bio) {
        event->bytes = BPF_CORE_READ(bio, bi_iter.bi_size);
    } else {
        event->bytes = 0;
    }

    event->latency_ns = latency;

    bpf_printk("complete event\n");

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
// SPDX-License-Identifier: GPL-2.0
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "io_event.h"

static __always_inline __u32 bpf_log2l(__u64 v) {
    __u32 r = 0;
    while (v >>= 1)
        r++;
    return r;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);   // Enough to cover latency buckets
    __type(key, __u32);
    __type(value, __u64);
} latency_histogram SEC(".maps");

struct bio_info {
    __u64 ts;
    __u32 size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bio *);
    __type(value, struct bio_info);
    __uint(max_entries, 10240);
} start_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Submission hook
SEC("kprobe/submit_bio_noacct")
int trace_io_submit(struct pt_regs *ctx) {
    struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);
    if (!bio)
        return 0;

    bpf_printk("submit event\n");

    struct bio_info info = {
        .ts = bpf_ktime_get_ns(),
        .size = BPF_CORE_READ(bio, bi_iter.bi_size),
    };

    bpf_map_update_elem(&start_ts, &bio, &info, BPF_ANY);
    return 0;
}

// Completion hook
SEC("kprobe/bio_endio")
int trace_io_complete(struct pt_regs *ctx) {
    struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);
    if (!bio)
        return 0;

    bpf_printk("complete event\n");

    struct bio_info *info = bpf_map_lookup_elem(&start_ts, &bio);
    if (!info) {
        bpf_printk("lookup failed for bio=%p\n", bio);
        return 0;
    }

    __u64 latency = bpf_ktime_get_ns() - info->ts;
    bpf_map_delete_elem(&start_ts, &bio);

    struct my_io_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

    if (!event) {
        bpf_printk("ringbuf reserve failed\n");
        return 0;
    }
    bpf_printk("reserving event succeeded\n");

    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->ts = bpf_ktime_get_ns();
    event->bytes = info->size; //BPF_CORE_READ(bio, bi_iter.bi_size);
    event->latency_ns = latency;

    __u32 slot = bpf_log2l(latency);
    if (slot < 64) {
        __u64 *count = bpf_map_lookup_elem(&latency_histogram, &slot);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
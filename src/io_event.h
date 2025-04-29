#ifndef __IO_EVENT_H
#define __IO_EVENT_H

#define TASK_COMM_LEN 16

// Must match between kernel and user
struct my_io_event {
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u64 ts;
    __u32 bytes;
    __u64 latency_ns;
};

#endif // __IO_EVENT_H
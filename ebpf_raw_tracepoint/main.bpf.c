#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    u32 pid;
    char filename[128];
    char command[64]
};

/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");


// include/trace/events/sched.h
SEC("raw_tracepoint/sched_process_exec")
int raw_tracepoint_demo(struct bpf_raw_tracepoint_args *ctx) {

    struct event *e;
    e=bpf_ringbuf_reserve(&events,sizeof(*e),0);
    if (!e) {
        return 0;
    }
    bpf_core_read(&e->filename,sizeof(e->filename),ctx->args[0]);
    e->pid=bpf_get_current_pid_tgid() >>32;
    bpf_get_current_comm(&e->command,sizeof(e->command));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
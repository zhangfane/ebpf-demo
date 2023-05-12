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

/* taken from /sys/kernel/debug/tracing/events/sched/sched_switch/format */
struct sched_switch_args {
    unsigned long long pad;
    char prev_comm[TASK_COMM_LEN];
    int prev_pid;
    int prev_prio;
    long long prev_state;
    char next_comm[TASK_COMM_LEN];
    int next_pid;
    int next_prio;
};

struct sched_process_exec_args{

    int __data_loc;
    pid_t pid;
    pid_t old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int tracepoint_demo(struct trace_event_raw_sched_process_exec *ctx) {
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    unsigned short filename_offset=ctx->__data_loc_filename;
    char *filename=(char *)ctx +filename_offset;

    bpf_core_read(&e->filename,sizeof(e->filename),filename);
    e->filename= (char *)(ctx+filename_offset);
    e->pid=bpf_get_current_pid_tgid() >>32;
    bpf_get_current_comm(&e->command,sizeof(e->command));
    bpf_ringbuf_submit(e, 0);

    return 0;
}

//
//SEC("tracepoint/sched/sched_process_exec")
//int tracepoint_demo(struct pt_regs *ctx) {
//    struct event *e;
//    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//    if (!e) {
//        return 0;
//    }
//    struct pt_regs *regs= ctx;
//
//    unsigned short filename_offset=ctx->si &0XFFFF;
////    unsigned short filename_offset=ctx->__data_loc & 0xFFFF;
//    char *filename=(char *)ctx +filename_offset;
//    bpf_core_read(&e->filename,sizeof(e->filename),regs->si);
//
//    e->pid=bpf_get_current_pid_tgid() >>32;
//    bpf_get_current_comm(&e->command,sizeof(e->command));
//    bpf_ringbuf_submit(e, 0);
//
//    return 0;
//}

char _license[] SEC("license") = "GPL";
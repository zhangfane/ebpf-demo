#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "main.skel.h"
#include "time.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}


struct event {
    int pid;
    char filename[128];
    char command[64]
};

int handle_event(void *ctx,void *data,size_t data_sz){
    struct event *e=data;
    time_t t;
    time(&t);
    struct tm *tt=localtime(&t);
    char ts[32];
    strftime(ts,sizeof(ts),"%H:%M:%S",tt);
    printf("%-8s %-5s %-7d %-16s %s\n", ts, "EXEC", e->pid, e->command, e->filename);
    return 0;
}

int main(int argc, char **argv)
{
    struct main_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = main_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = main_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = main_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    struct ring_buffer *rb=ring_buffer__new(bpf_map__fd(skel->maps.events),handle_event,NULL,NULL);
    if (!rb){

        fprintf(stderr, "Failed to create BPF ringbuffer\n");
        err=-1;
        goto cleanup;
    }
    while (true) {
        /* trigger our BPF program */
        err= ring_buffer__poll(rb,100);
        if (err==-EINTR){
            err=0;
            break;
        }
        if (err<0){
            fprintf(stderr, "error polling ring buffer\n");
            break;
        }
    }

    cleanup:
    ring_buffer__free(rb);
    main_bpf__destroy(skel);
    return -err;
}
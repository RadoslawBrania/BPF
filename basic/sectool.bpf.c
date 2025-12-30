#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license")="GPL";

SEC("tracepoint/syscalls/sys_enter_bpf")
int handle_prog_load(struct trace_event_raw_sys_enter *ctx){
if (ctx->args[0]==BPF_PROG_LOAD) bpf_printk("sys_bpf called cmd =%d\n",ctx->args[0]);
return 0;
}

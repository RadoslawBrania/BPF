#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf.h>

char LICENSE[] SEC("license")="GPL";

SEC("fexit/bpf_prog_load")
int BPF_PROG(trace_bpf_prog, struct bpf_prog *prog){
struct bpf_prog_info info ={};
uint32_t len = sizeof(info);
bpf_prog_get_info_by_fd(prog->fd,&info,&len);
bpf_printk("BPF program, id = %s",name);
return 0;
}

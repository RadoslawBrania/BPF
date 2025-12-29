#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
//#include "vmlinux.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx){
	bpf_printk("execve()))\n\n");
return 0;
}

char LICENSE[] SEC("license") = "GPL";

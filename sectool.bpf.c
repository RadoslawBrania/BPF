#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

//#include <bpf/bpf.h>

/*int bpf_obj_get_info_by_fd(int bpf_fd, void* info, __u32 *info_len)
{
const size_t attr_sz =offsetofend(union bpf_attr,info);
union bpf_attr attr;
int err;

memset(&attr,0,attr_sz);
attr.info.bpf_fd = bpf_fd;
attr.info.info_len = *info_len;
attr.info.info = ptr_to_u64(info);

err= sys_bpf(BPF_OBJ_GET_INFO_BY_FD,&attr,attr_sz);
if(!err)
	*info_len = attr.info.info_len;
return libbpf_err_errno(err);
}
*/
char LICENSE[] SEC("license")="GPL";

SEC("tp/syscalls/sys_exit_bpf")
int handle_exit(void){
union bpf_attr *uattr_ptr = 0;
union bpf_attr attr = {};
bpf_probe_read(&attr,sizeof(attr),uattr_ptr);
bpf_printk("BPF program, id = %lu",(unsigned long)attr.next_id);
return 0;
}

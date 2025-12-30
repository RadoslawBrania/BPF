#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>


int main(){

	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;


obj = bpf_object__open_file("target.o",NULL);
if(!obj){
	perror("bpf_object__open_file");
	return 1;
}
if(bpf_object__load(obj)){
fprintf(stderr,"failed to load");
return 1;
}

bpf_object__for_each_program(prog,obj){
const char *sec = bpf_program__section_name(prog);
if (strcmp(sec,"tracepoint/syscalls/sys_enter_bpf") == 0) {
	link = bpf_program__attach_tracepoint(prog,"syscalls","sys_enter_bpf");
	if(!link){
	     fprintf(stderr,"failed att");
		return 1;
	}
	printf("att prog");
	break;
	}
}

//link = bpf_program__attach_tracepoint(prog,"syscalls","sys_enter_execve");
if(!link){
perror("no link");
return 1;
}
printf("att\n");
while (1){
true;
}
bpf_link__destroy(link);
bpf_object__close(obj);
return 0;
}


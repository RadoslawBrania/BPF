loadbpfFentry: target.o
	cc bpfloader.c -lbpf -lelf -o loadbpfFentry

target.o:
	clang -O2 -I/lib/modules/$(uname -r)/build/arch/x86/include  -target bpf -g -c sectool.bpf.c -o target.o


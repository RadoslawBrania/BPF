loadbpf2: target.o
	cc bpfloader.c -lbpf -lelf -o loadbpf2

target.o:
	clang -O2 -target bpf -c -g sectool.bpf.c -o target.o


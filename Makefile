loadbpfFentry: target.o
	cc bpfloader.c -lbpf -lelf -o loadbpfFentry

target.o:
	clang -O2 -target bpf -c -g sectool.bpf.c -o target.o


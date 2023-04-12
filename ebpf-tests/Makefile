all: simple

simple: vmlinux.h simple.bpf.o

%.bpf.o: %.bpf.c
	clang -target bpf -c $< -o $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -rf *.bpf.o vmlinux.h

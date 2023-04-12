#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("main.test")
int main__test(void *ctx)
{
	bpf_printk("Hello world!\n");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

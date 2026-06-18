// custom ebpf user plane function (UPF) forwarder  
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// Define the license (required by the kernel)
SEC("license") const char LICENSE[] = "GPL";

// Attach this function to the sys_enter_execve tracepoint
SEC("tracepoint/syscalls/sys_enter_execve")
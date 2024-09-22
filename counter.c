//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Define the BPF map that will hold the syscall counts.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 20000);
}  syscall_count_map SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_read")
int count_read_calls(void *ctx) {
    __u32 key = 0;
    __u64 *value, zero = 0;

    // Look up the current count in the map.
    value = bpf_map_lookup_elem(&syscall_count_map, &key);
    if (!value) {
        // Initialize the counter if it doesn't exist.
        bpf_map_update_elem(&syscall_count_map, &key, &zero, BPF_ANY);
        value = &zero;
    }
    
    // Increment the syscall count atomically.
    __sync_fetch_and_add(value, 1);
}

char _license[] SEC("license") = "GPL";

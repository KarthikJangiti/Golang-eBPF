#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

// BPF map to store the allowed process ID
struct bpf_map_def SEC("maps") allowed_pid_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,
};

// Define the allowed port (default 4040)
#define ALLOWED_PORT 4040

SEC("xdp_prog")
int xdp_filter(struct xdp_md *ctx) {
    // Get the Ethernet header
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (eth + 1 > data_end) {
        return XDP_DROP;
    }

    // Check if it's an IP packet
    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Get the IP header
    struct iphdr *ip = data + sizeof(*eth);
    if (ip + 1 > data_end) {
        return XDP_DROP;
    }

    // Check if it's a TCP packet
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // Get the TCP header
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if (tcp + 1 > data_end) {
        return XDP_DROP;
    }

    // Get the current process ID
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if the current process ID is allowed
    u32 *allowed_pid = bpf_map_lookup_elem(&allowed_pid_map, &pid);
    if (!allowed_pid) {
        // If the process is not in the allowed list, drop the packet
        return XDP_DROP;
    }

    // Check if the destination port is the allowed port
    if (tcp->dest == htons(ALLOWED_PORT)) {
        return XDP_PASS;
    }

    // Drop all other traffic for the allowed process
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

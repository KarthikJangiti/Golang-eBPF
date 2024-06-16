#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <linux/bpf.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <bpf/bpf_helpers.h>

// BPF map to store the port number
struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// XDP program to drop TCP packets on the specified port
SEC("xdp")
int drop_tcp_port(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Check if it's an IP packet
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    // Check if it's a TCP packet
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // Get the port number from the BPF map
    __u32 key = 0;
    __u32 *port = bpf_map_lookup_elem(&port_map, &key);
    if (port && tcp->dest == htons(*port)) {
        // Drop the packet if the destination port matches
        return XDP_DROP;
    }

    return XDP_PASS;
}

// License for the eBPF program
char _license[] SEC("license") = "GPL";

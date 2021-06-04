char _license[] SEC("license") = "GPL";

#include <linux/bpf.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

SEC("xdp_sock")
int udp_filter(struct xdp_md *ctx)
{
    bpf_trace_printk("got a packet\n");      
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end) {
            if (ip->protocol == IPPROTO_UDP) {
                bpf_trace_printk("udp packet\n");
                return XDP_PASS;
            }
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
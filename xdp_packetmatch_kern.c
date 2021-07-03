#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

int xdp_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    char match_pattern[] = "test";
    unsigned int payload_size, i;
    struct ethhdr *eth = data;
    unsigned char *payload;
    struct udphdr *udp;
    struct iphdr *ip;

    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    udp = (void *)ip + sizeof(*ip);
    if ((void *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;

    if (udp->dest != ntohs(5005))
        return XDP_PASS;

    payload_size = ntohs(udp->len) - sizeof(*udp);
    // Here we use "size - 1" to account for the final '\0' in "test".
    // This '\0' may or may not be in your payload, adjust if necessary.
    if (payload_size != sizeof(match_pattern) - 1) 
        return XDP_PASS;

    // Point to start of payload.
    payload = (unsigned char *)udp + sizeof(*udp);
    if ((void *)payload + payload_size > data_end)
        return XDP_PASS;

    // Compare each byte, exit if a difference is found.
    for (i = 0; i < payload_size; i++)
        if (payload[i] != match_pattern[i])
            return XDP_PASS;

    // Same payload, drop.
    return XDP_DROP;
}
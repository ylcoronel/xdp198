#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// map for the af_xdp socket
struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    int index = ctx->rx_queue_index;

    if (( void *) eth + sizeof (* eth) <= data_end ){
        struct iphdr *ip = data + sizeof (* eth);
        if (( void *) ip + sizeof (* ip) <= data_end ){
            if (ip -> protocol == IPPROTO_UDP ){ // if protocol is UDP, parse payload
                if (bpf_map_lookup_elem(&xsks_map, &index)){
                    return bpf_redirect_map(&xsks_map, index, 0);
                }
                /*udp++;
                struct udphdr *udp = (void *)ip + sizeof(*ip);
                if ((void *)udp + sizeof(*udp) <= data_end){
                    payload_size = ntohs(udp->len) - sizeof(*udp);
                    payload = (unsigned char *)udp + sizeof(*udp); // start of payload
                    if ((void *)payload + payload_size <= data_end){
                        check_pattern(payload, payload_size);
                        if (flag != 0){ rec->matched_packets++; }
                        return XDP_PASS;
                    
                    }
                } */        
            }
        }
    }   
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
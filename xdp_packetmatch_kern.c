/* SPDX-License-Identifier: GPL-2.0 */

//KMP IMPLEMENTATION

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "common_kern_user.h" /* defines: struct datarec; */

/* Lesson#1: See how a map is defined.
 * - Here an array with XDP_ACTION_MAX (max_)entries are created.
 * - The idea is to keep stats per (enum) xdp_action
 */
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp_stats1")
int  xdp_stats1_func(struct xdp_md *ctx)
{

	struct datarec *rec;
	
	__u32 key = XDP_PASS; /* XDP_PASS = 2 */

	/* Lookup in kernel BPF-side return pointer to actual data record */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec){
		return XDP_ABORTED;
	}

	void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    char *match_pattern[8] = {"FJDMFOEOLTUUWU","HJGFUJKFMYLDCBOXVJTRTEGF", "CCFHT", "EGENLZRNEYILONYHKUOPGRGU", "XYGKLGPTNEGMVV",
     "UGCBCDYALKNRBGEFMSDJN", "FYHLXQHFUIHXIHI", "ZPIOKVVIDGHTONNYWMJGWE"};
	int pattern_sizes[8] = {14, 24, 5, 24, 14, 21, 15, 22};
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

	// change this
    if (udp->dest != ntohs(5201))
        return XDP_PASS;
	else
		lock_xadd(&rec->rx_packets, 1);

    payload_size = ntohs(udp->len) - sizeof(*udp);

    // Point to start of payload.
    payload = (unsigned char *)udp + sizeof(*udp);
    if ((void *)payload + payload_size > data_end){
        return XDP_PASS;
	}

	int j = 0, ctr = 0;
	
    for (i = 0; i < payload_size; i++){
        if (payload[i] == match_pattern[0][j]){
			j++;
		}else if(payload[i] != match_pattern[0][j]){
			j = 0;
		}

		if(j == pattern_sizes[0]-1){
			ctr++;
			return XDP_PASS;
		}
	}

	// 2nd pattern
	j = 0, ctr = 0;
	
    for (i = 0; i < payload_size; i++){
        if (payload[i] == match_pattern[1][j]){
			j++;
		}else if(payload[i] != match_pattern[1][j]){
			j = 0;
		}

		if(j == pattern_sizes[1]-1){
			ctr++;
			return XDP_PASS;
		}
	}

	// 3rd pattern
	j = 0, ctr = 0;
	
    for (i = 0; i < payload_size; i++){
        if (payload[i] == match_pattern[2][j]){
			j++;
		}else if(payload[i] != match_pattern[2][j]){
			j = 0;
		}

		if(j == pattern_sizes[2]-1){
			ctr++;
			return XDP_PASS;
		}
	}

	// 4th pattern
	j = 0, ctr = 0;
	
    for (i = 0; i < payload_size; i++){
        if (payload[i] == match_pattern[3][j]){
			j++;
		}else if(payload[i] != match_pattern[3][j]){
			j = 0;
		}

		if(j == pattern_sizes[3]-1){
			ctr++;
			return XDP_PASS;
		}
	}

	// 5th pattern
	j = 0, ctr = 0;
	
    for (i = 0; i < payload_size; i++){
        if (payload[i] == match_pattern[4][j]){
			j++;
		}else if(payload[i] != match_pattern[4][j]){
			j = 0;
		}

		if(j == pattern_sizes[4]-1){
			ctr++;
			return XDP_PASS;
		}
	}

	// 6th pattern
	j = 0, ctr = 0;
	
    for (i = 0; i < payload_size; i++){
        if (payload[i] == match_pattern[5][j]){
			j++;
		}else if(payload[i] != match_pattern[5][j]){
			j = 0;
		}

		if(j == pattern_sizes[5]-1){
			ctr++;
			return XDP_PASS;
		}
	}

	// 7th pattern
	j = 0, ctr = 0;
	
    for (i = 0; i < payload_size; i++){
        if (payload[i] == match_pattern[6][j]){
			j++;
		}else if(payload[i] != match_pattern[6][j]){
			j = 0;
		}

		if(j == pattern_sizes[6]-1){
			ctr++;
			return XDP_PASS;
		}
	}

	// 8th pattern
	j = 0, ctr = 0;
	
    for (i = 0; i < payload_size; i++){
        if (payload[i] == match_pattern[7][j]){
			j++;
		}else if(payload[i] != match_pattern[7][j]){
			j = 0;
		}

		if(j == pattern_sizes[7]-1){
			ctr++;
			return XDP_PASS;
		}
	}

	if(ctr>=0){
		lock_xadd(&rec->match, 1);
	}


	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


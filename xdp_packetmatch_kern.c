/* SPDX-License-Identifier: GPL-2.0 */
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
	//void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	unsigned int payload_size;
	struct ethhdr *eth = data;
    //unsigned char *payload;
    struct udphdr *udp;
    struct iphdr *ip;

	struct datarec *rec;
	
	__u32 key = XDP_PASS; /* XDP_PASS = 2 */

	/* Lookup in kernel BPF-side return pointer to actual data record */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	/* BPF kernel-side verifier will reject program if the NULL pointer
	 * check isn't performed here. Even-though this is a static array where
	 * we know key lookup XDP_PASS always will succeed.
	 */
	if (!rec)
		return XDP_ABORTED;

	/* Multiple CPUs can access data record. Thus, the accounting needs to
	 * use an atomic operation.
	 */
	lock_xadd(&rec->rx_packets, 1);
	int *rcvdpackets = (int*)&rec->rx_packets;
	int k = *rcvdpackets;
	if(k > 200)
		lock_xadd(&rec->match, 1);
    
	ip = data + sizeof(*eth);
	udp = (void *)ip + sizeof(*ip);
	payload_size = ntohs(udp->len) - sizeof(*udp);

	lock_xadd(&rec->payload_size, payload_size);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


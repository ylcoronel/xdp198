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
    char match_pattern[] = "FJDMFOEOLTUUWU"; 
	char match_pattern1[]= "HJGFUJKFMYLDCBOXVJTRTEGF";
	char match_pattern2[]= "CCFHT";
	char match_pattern3[]= "EGENLZRNEYILONYHKUOPGRGU"; 
	char match_pattern4[]= "XYGKLGPTNEGMV";
	char match_pattern5[]= "UGCBCDYALKNRBGEFMSDJN";
	char match_pattern6[]= "FYHLXQHFUIHXIHI";
	char match_pattern7[]= "ZPIOKVVIDGHTONNYWMJGWE";
	char match_pattern8[]= "FFEVILXXVNHRIRUR";	
	char match_pattern9[]= "SOUVLXARDXZPWYM";
	char match_pattern10[]= "SUZFMQZAM";
  	char match_pattern11[]= "OXJQOBJKC";
  	char match_pattern12[]= "JKFXID";
  	char match_pattern13[]= "YBBFSCOEHNMKDWYLTNCDH";
  	char match_pattern14[]= "ZSSDJNDMOIHRYLYOALRWJEPX";
  	char match_pattern15[]= "VGRJBYKVSN";
  	char match_pattern16[]= "JGLBFRYLI";
  	char match_pattern17[]= "CZQPVXBD";
  	char match_pattern18[]= "SFPHVRJWHATGBXQ";
  	char match_pattern19[]= "BSPLVFDDUMAMVYVW";

    unsigned int payload_size;
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

    payload_size = ntohs(udp->len) - sizeof(*udp);

    // Point to start of payload.
    payload = (unsigned char *)udp + sizeof(*udp);
    if ((void *)payload + payload_size > data_end){
        return XDP_PASS;
	}

	int ctr = 0;

	// pattern 1
	if(payload[0] == match_pattern[0]){
		ctr++;
	}
	if(payload[1] == match_pattern[1]){
		ctr++;
	}
	if(payload[2] == match_pattern[2]){
		ctr++;
	}
	if(payload[3] == match_pattern[3]){
		ctr++;
	}
	if(payload[4] == match_pattern[4]){
		ctr++;
	}
	if(payload[5] == match_pattern[5]){
		ctr++;
	}
	if(payload[6] == match_pattern[6]){
		ctr++;
	}
	if(payload[7] == match_pattern[7]){
		ctr++;
	}
	if(payload[8] == match_pattern[8]){
		ctr++;
	}
	if(payload[9] == match_pattern[9]){
		ctr++;
	}
	if(payload[10] == match_pattern[10]){
		ctr++;
	}
	if(payload[11]] == match_pattern[11]){
		ctr++;
	}
	if(payload[12] == match_pattern[12]){
		ctr++;
	}

	if(ctr == 13){
		lock_xadd(&rec->match, 1);
	}else{
		ctr = 0;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


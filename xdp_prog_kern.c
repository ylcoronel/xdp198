#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_kern_user.h" /* defines: struct datarec; */

#define MAXNUMPATS 10
#define MAXPATLEN 27
int match;

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};


#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

static __always_inline
void check_pattern(unsigned char *text, int N, unsigned char *pattern, int M, int pps[]) {
    if (N < M) // if text_len < pat_len
        return;

    int i = 0;
    int j = 0;
    while (i < N) {
        if (pattern[j] == text[i]) {
            j++;
            i++;
        }
        if (j == M) {
            match++;
            j = pps[j - 1];
        }
        else if (i < N && pattern[j] != text[i]) {
            if (j != 0)
                j = pps[j - 1];
            else
              i = i + 1;
        }
    }
    return;
}

static __always_inline
void prefixSuffixArray(unsigned char* pat, int M, int* pps) {
    int length = 0;
    pps[0] = 0;
    int i = 1;
    while (i < M) {
        if (pat[i] == pat[length]) {
            length++;
            pps[i] = length;
            i++;
        } else {
            if (length != 0)
                length = pps[length - 1];
            else {
                pps[i] = 0;
                i++;
            }
        }
    }
}               

SEC("xdp_prog")
int  xdp_prog_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct datarec *rec;
	__u32 key = XDP_PASS; /* XDP_PASS = 2 */
    int index = ctx->rx_queue_index;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec)
		return XDP_ABORTED;

    char *pat_ = NULL;
    size_t len_ = 0;
    ssize_t read;
    int i, j;
    unsigned char *pat[MAXNUMPATS];
    int pat_len[MAXNUMPATS];
    int* pps[MAXNUMPATS];
    unsigned int payload_size;
    struct ethhdr *eth = data;
    unsigned char *payload;
    struct udphdr *udp;
    char pat[10][27] = {"FJDMFOEOLTUUWU", "CCFHT", "EGENLZRNEYILONYHKUOPGRGU", "XYGKLGPTNEGMVV",
                        "UGCBCDYALKNRBGEFMSDJN", "FYHLXQHFUIHXIHI", "ZPIOKVVIDGHTONNYWMJGWE",
                        "FFEVILXXVNHRIRUR", "SOUVLXARDXZPWYM"};

    for (i = 0; i < MAXNUMPATS; i++) {
        pat_len[i] = strlen(pattern[i]);
        pps[i] = (int *)malloc(MAXPATLEN * sizeof(int));
        prefixSuffixArray(pat[i], pat_len[i], pps[i]);
    }

    struct iphdr *ip = data + sizeof(*eth);
    udp = (void *)ip + sizeof(*ip);
    payload_size = ntohs(udp->len) - sizeof(*udp);
    payload = (unsigned char *)udp + sizeof(*udp);
    
    if ((void*)eth + sizeof(*eth) <= data_end) {
        if ((void*)ip + sizeof(*ip) <= data_end) {
            if (ip->protocol == IPPROTO_UDP) {
                for (i = 0; i < MAXNUMPATS; i++) {
                    if(match == 0)
                        lock_xadd(&rec->rx_packets, 1);
                }
            }
        }
    }

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";